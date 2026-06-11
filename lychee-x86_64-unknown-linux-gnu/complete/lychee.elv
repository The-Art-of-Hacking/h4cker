
use builtin;
use str;

set edit:completion:arg-completer[lychee] = {|@words|
    fn spaces {|n|
        builtin:repeat $n ' ' | str:join ''
    }
    fn cand {|text desc|
        edit:complex-candidate $text &display=$text' '(spaces (- 14 (wcswidth $text)))$desc
    }
    var command = 'lychee'
    for word $words[1..-1] {
        if (str:has-prefix $word '-') {
            break
        }
        set command = $command';'$word
    }
    var completions = [
        &'lychee'= {
            cand -c 'Configuration file to use. Can be specified multiple times.  If given multiple times, the configs are merged and later occurrences take precedence over previous occurrences.  [default: lychee.toml]'
            cand --config 'Configuration file to use. Can be specified multiple times.  If given multiple times, the configs are merged and later occurrences take precedence over previous occurrences.  [default: lychee.toml]'
            cand --files-from 'Read input filenames from the given file or stdin (if path is ''-'').'
            cand -n 'Do not show progress bar. This is recommended for non-interactive shells (e.g. for continuous integration)'
            cand --no-progress 'Do not show progress bar. This is recommended for non-interactive shells (e.g. for continuous integration)'
            cand --host-stats 'Show per-host statistics at the end of the run'
            cand --extensions 'A list of file extensions. Files not matching the specified extensions are skipped.'
            cand --default-extension 'This is the default file extension that is applied to files without an extension.'
            cand --cache 'Use request cache stored on disk at `.lycheecache`'
            cand --max-cache-age 'Discard all cached requests older than this duration'
            cand --cache-exclude-status 'A list of status codes that will be ignored from the cache'
            cand --dump 'Don''t perform any link checking. Instead, dump all the links extracted from inputs that would be checked'
            cand --dump-inputs 'Don''t perform any link extraction and checking. Instead, dump all input sources from which links would be collected'
            cand --archive 'Web archive to use to provide suggestions for `--suggest`'
            cand --suggest 'Suggest link replacements for broken links, using a web archive. The web archive can be specified with `--archive`'
            cand -m 'Maximum number of allowed redirects'
            cand --max-redirects 'Maximum number of allowed redirects'
            cand --max-retries 'Maximum number of retries per request'
            cand --min-tls 'Minimum accepted TLS Version'
            cand --max-concurrency 'Maximum number of concurrent network requests'
            cand --host-concurrency 'Default maximum concurrent requests per host (default: 10)'
            cand --host-request-interval 'Minimum interval between requests to the same host (default: 50ms)'
            cand -T 'Number of threads to utilize. Defaults to number of cores available to the system'
            cand --threads 'Number of threads to utilize. Defaults to number of cores available to the system'
            cand -u 'User agent'
            cand --user-agent 'User agent'
            cand -i 'Proceed for server connections considered insecure (invalid TLS)'
            cand --insecure 'Proceed for server connections considered insecure (invalid TLS)'
            cand -s 'Only test links with the given schemes (e.g. https). Omit to check links with any other scheme. At the moment, we support http, https, file, and mailto.'
            cand --scheme 'Only test links with the given schemes (e.g. https). Omit to check links with any other scheme. At the moment, we support http, https, file, and mailto.'
            cand --offline 'Only check local files and block network requests'
            cand --include 'URLs to check (supports regex). Has preference over all excludes'
            cand --exclude 'Exclude URLs and mail addresses from checking. The values are treated as regular expressions'
            cand --exclude-file 'Deprecated; use `--exclude-path` instead'
            cand --exclude-path 'Exclude paths from getting checked. The values are treated as regular expressions'
            cand -E 'Exclude all private IPs from checking. Equivalent to `--exclude-private --exclude-link-local --exclude-loopback`'
            cand --exclude-all-private 'Exclude all private IPs from checking. Equivalent to `--exclude-private --exclude-link-local --exclude-loopback`'
            cand --exclude-private 'Exclude private IP address ranges from checking'
            cand --exclude-link-local 'Exclude link-local IP address range from checking'
            cand --exclude-loopback 'Exclude loopback IP address range and localhost from checking'
            cand --include-mail 'Also check email addresses'
            cand --remap 'Remap URI matching pattern to different URI'
            cand --fallback-extensions 'When checking locally, attempts to locate missing files by trying the given fallback extensions. Multiple extensions can be separated by commas. Extensions will be checked in order of appearance.'
            cand --index-files 'When checking locally, resolves directory links to a separate index file. The argument is a comma-separated list of index file names to search for. Index names are relative to the link''s directory and attempted in the order given.'
            cand -H 'Set custom header for requests.'
            cand --header 'Set custom header for requests.'
            cand -a 'A List of accepted status codes for valid links'
            cand --accept 'A List of accepted status codes for valid links'
            cand --accept-timeouts 'Accept timed out requests and return exit code 0 when encountering timeouts but not any other errors'
            cand --include-fragments 'Enable the checking of fragments in links.'
            cand -t 'Website timeout in seconds from connect to response finished'
            cand --timeout 'Website timeout in seconds from connect to response finished'
            cand -r 'Minimum wait time in seconds between retries of failed requests'
            cand --retry-wait-time 'Minimum wait time in seconds between retries of failed requests'
            cand -X 'Request method'
            cand --method 'Request method'
            cand --base 'Deprecated; use `--base-url` instead'
            cand -b 'Base URL to use when resolving relative URLs in local files. If specified, relative links in local files are interpreted as being relative to the given base URL.'
            cand --base-url 'Base URL to use when resolving relative URLs in local files. If specified, relative links in local files are interpreted as being relative to the given base URL.'
            cand --root-dir 'Root directory to use when checking absolute links in local files. This option is required if absolute links appear in local files, otherwise those links will be flagged as errors. This must be an absolute path (i.e., one beginning with `/`).'
            cand --basic-auth 'Basic authentication support. E.g. `http://example.com username:password`'
            cand --github-token 'GitHub API token to use when checking github.com links, to avoid rate limiting'
            cand --skip-missing 'Skip missing input files (default is to error if they don''t exist)'
            cand --no-ignore 'Do not skip files that would otherwise be ignored by ''.gitignore'', ''.ignore'', or the global ignore file'
            cand --hidden 'Do not skip hidden directories and files'
            cand --include-verbatim 'Find links in verbatim sections like `pre`- and `code` blocks'
            cand --glob-ignore-case 'Ignore case when expanding filesystem path glob inputs'
            cand -o 'Output file of status report'
            cand --output 'Output file of status report'
            cand --mode 'Set the output display mode. Determines how results are presented in the terminal'
            cand -f 'Output format of final status report'
            cand --format 'Output format of final status report'
            cand --generate 'Generate special output (e.g. the man page) instead of performing link checking'
            cand --require-https 'When HTTPS is available, treat HTTP links as errors'
            cand --cookie-jar 'Read and write cookies using the given file. Cookies will be stored in the cookie jar and sent with requests. New cookies will be stored in the cookie jar and existing cookies will be updated.'
            cand --include-wikilinks 'Check WikiLinks in Markdown files, this requires specifying --base-url'
            cand -p 'Preprocess input files with the given command.'
            cand --preprocess 'Preprocess input files with the given command.'
            cand -v 'Set verbosity level; more output per occurrence (e.g. `-v` or `-vv`)'
            cand --verbose 'Set verbosity level; more output per occurrence (e.g. `-v` or `-vv`)'
            cand -q 'Less output per occurrence (e.g. `-q` or `-qq`)'
            cand --quiet 'Less output per occurrence (e.g. `-q` or `-qq`)'
            cand -h 'Print help (see more with ''--help'')'
            cand --help 'Print help (see more with ''--help'')'
            cand -V 'Print version'
            cand --version 'Print version'
        }
    ]
    $completions[$command]
}
