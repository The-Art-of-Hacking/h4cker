#!/usr/bin/env node
// Local dry-run harness for the automerge-baseline workflow logic
// Usage: node automerge_dry_run.js --pr=123 --branch=auto/update-secrets-baseline-1 --approved=true --perm=write --status=success --draft=false

function parseArgs() {
  const argv = require('minimist')(process.argv.slice(2));
  return {
    prNumber: argv.pr || argv.prNumber || 123,
    branch: argv.branch || 'auto/update-secrets-baseline-1',
    approved: (argv.approved === 'true' || argv.approved === true),
    perm: argv.perm || 'write',
    status: argv.status || 'success',
    draft: (argv.draft === 'true' || argv.draft === true)
  };
}

async function runDryRun(opts) {
  console.log('--- Dry-run starting with options:', opts);

  // Mocked PR object
  const pr = {
    number: opts.prNumber,
    head: { ref: opts.branch, sha: 'deadbeef1234567890' },
    draft: opts.draft
  };

  // Mocked GitHub API
  const github = {
    rest: {
      pulls: {
        get: async ({ owner, repo, pull_number }) => ({ data: pr }),
        listReviews: async ({ owner, repo, pull_number }) => {
          const reviews = [];
          if (opts.approved) reviews.push({ state: 'APPROVED', user: { login: 'approver-user' } });
          return { data: reviews };
        },
        update: async ({ owner, repo, pull_number, draft }) => {
          console.log(`Simulate: updating PR ${pull_number} draft=${draft}`);
          pr.draft = draft;
          return { data: pr };
        },
        merge: async ({ owner, repo, pull_number, merge_method, commit_title }) => {
          console.log(`Simulate: merging PR ${pull_number} with method=${merge_method}`);
          return { data: { sha: 'mergedsha9876543210' } };
        }
      },
      repos: {
        getCollaboratorPermissionLevel: async ({ owner, repo, username }) => ({ data: { permission: opts.perm } }),
        getCombinedStatusForRef: async ({ owner, repo, ref }) => ({ data: { state: opts.status } })
      },
      issues: {
        addLabels: async ({ owner, repo, issue_number, labels }) => {
          console.log(`Simulate: adding labels ${labels} to issue ${issue_number}`);
          if (opts.failAddLabel) {
            const err = new Error('Simulated addLabels failure');
            err.status = 404;
            throw err;
          }
          return { data: {} };
        },
        createLabel: async ({ owner, repo, name, color, description }) => {
          console.log(`Simulate: creating label ${name}`);
          return { data: { name } };
        },
        createComment: async ({ owner, repo, issue_number, body }) => {
          console.log(`Simulate: createComment on ${issue_number}:\n${body}`);
          return { data: {} };
        }
      }
    }
  };

  // Begin logic (mirrors workflow's merge step)
  // Only operate on branches created by our baseline action
  if (!pr.head.ref.startsWith('auto/update-secrets-baseline-')) {
    console.log('Skipping: PR branch does not match auto baseline pattern');
    return { merged: false, reason: 'branch-mismatch' };
  }

  // If PR is draft, convert to ready for review first
  if (pr.draft) {
    console.log('PR is draft; converting to ready for review');
    await github.rest.pulls.update({ owner: 'org', repo: 'repo', pull_number: pr.number, draft: false });
  }

  // Re-check for a recent approved review and approver permission
  const reviews = (await github.rest.pulls.listReviews({ owner: 'org', repo: 'repo', pull_number: pr.number })).data;
  let approver = null;
  for (let i = reviews.length - 1; i >= 0; i--) {
    if (reviews[i].state === 'APPROVED') {
      approver = reviews[i].user.login;
      break;
    }
  }

  if (!approver) {
    console.log('No approved review found at merge time');
    return { merged: false, reason: 'no-approver' };
  }

  const permResponse = (await github.rest.repos.getCollaboratorPermissionLevel({ owner: 'org', repo: 'repo', username: approver }));
  const perm = permResponse.data.permission;
  if (!['admin', 'write', 'maintain'].includes(perm)) {
    console.log(`Approver ${approver} does not have sufficient permission (${perm}).`);
    return { merged: false, reason: 'insufficient-permission' };
  }

  // Add an audit label to the PR (attempting to create it if missing, then add)
  const auditLabel = 'automerge-baseline';
  try {
    await github.rest.issues.addLabels({ owner: 'org', repo: 'repo', issue_number: pr.number, labels: [auditLabel] });
  } catch (err) {
    console.log('Adding label failed (will try to create it):', err.message);
    try {
      await github.rest.issues.createLabel({ owner: 'org', repo: 'repo', name: auditLabel, color: '0e8a16', description: 'Automerged baseline PRs' });
      await github.rest.issues.addLabels({ owner: 'org', repo: 'repo', issue_number: pr.number, labels: [auditLabel] });
    } catch (err2) {
      console.log('Failed to create/add label; continuing without label:', err2.message);
    }
  }

  // Merge the PR (squash)
  const mergeResult = await github.rest.pulls.merge({ owner: 'org', repo: 'repo', pull_number: pr.number, merge_method: 'squash', commit_title: 'chore: update detect-secrets baseline' });
  const mergedSha = mergeResult.data && mergeResult.data.sha ? mergeResult.data.sha : pr.head.sha;

  // Post a detailed audit comment for traceability (approver + merged SHA)
  const commentBody = `Automerged baseline update after approval by @${approver}.\n\nMerged commit SHA: ${mergedSha}`;
  await github.rest.issues.createComment({ owner: 'org', repo: 'repo', issue_number: pr.number, body: commentBody });

  console.log('Merge completed successfully. mergedSha=', mergedSha);
  return { merged: true, mergedSha, approver };
}

async function main() {
  const opts = parseArgs();
  const res = await runDryRun(opts);
  console.log('Result:', res);
}

if (require.main === module) main();
