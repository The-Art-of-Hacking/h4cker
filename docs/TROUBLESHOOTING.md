# Troubleshooting Guide

This document describes common edge-cases and workarounds for checking links to various sites. \
Please add your own findings and send us a pull request if you can.

## GitHub Rate Limiting

GitHub has a quite aggressive rate limiter. \
If you're seeing errors like:

```
GitHub token not specified. To check GitHub links reliably, use `--github-token` flag / `GITHUB_TOKEN` env var.
```

That means you're getting rate-limited. As per the message, you can make lychee \
use a GitHub personal access token to circumvent this.

For more details, see ["GitHub token" section in README.md](https://github.com/lycheeverse/lychee#github-token).

## Too Many Open Files

The number of concurrent network requests (`MAX_CONCURRENCY`) is set to 128 by default.
Every network request maps to an open socket, which is represented as a file on UNIX systems.
If you see error messages like "error trying to connect: tcp open error: Too
many open files (os error 24)" then you ran out of file handles.

You have two options:

1. Lower the concurrency by setting `--max-concurrency` to something more
   conservative like 32. This works, but it also comes with a performance
   penalty.
2. Increase the number of maximum file handles. See instructions
   [here](https://web.archive.org/web/20241127024709/https://wilsonmar.github.io/maximum-limits/) or
   [here](https://synthomat.de/blog/2020/01/increasing-the-file-descriptor-limit-on-macos/).

## Unexpected Status Codes

Some websites don't respond with a `200` (OK) status code. \
Instead they might send `204` (No Content), `206` (Partial Content), or
[something else entirely](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/418).

If you run into such issues you can work around that by providing a custom \
list of accepted status codes, such as `--accept 200,204,206`.

## Website Expects Custom Headers

Some sites expect one or more custom headers to return a valid response. \
For example, crates.io expects a `Accept: text/html` header or else it \
will [return a 404](https://github.com/rust-lang/crates.io/issues/788).

To fix that you can pass additional headers like so: `--header "Accept: text/html"`. \
You can use that argument multiple times to add more headers. \
Or, you can accept all content/MIME types: `--header "Accept: */*"`.

See more info about the Accept header
[over at MDN](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept).

## Unreachable Mail Address

You can check email addresses by providing the `--include-mail` flag.
We use https://github.com/reacherhq/check-if-email-exists for email checking.
You can test your mail address with curl:

```bash
 curl -X POST \
  'https://api.reacher.email/v0/check_email' \
  -H 'content-type: application/json' \
  -H 'authorization: test_api_token' \
  -d '{"to_email": "box@domain.test"}'
```

Some settings on your mail server (such as `SPF` Policy, `DNSBL`) may prevent
your email from being verified. If you have an error with checking a working
email, you can exclude specific addresses with the `--exclude` flag or skip
all email addresses by removing the `--include-mail` flag.
