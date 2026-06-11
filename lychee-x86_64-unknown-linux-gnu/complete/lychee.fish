complete -c lychee -s c -l config -d 'Configuration file to use. Can be specified multiple times.  If given multiple times, the configs are merged and later occurrences take precedence over previous occurrences.  [default: lychee.toml]' -r -F
complete -c lychee -l files-from -d 'Read input filenames from the given file or stdin (if path is \'-\').' -r -F
complete -c lychee -s n -l no-progress -d 'Do not show progress bar. This is recommended for non-interactive shells (e.g. for continuous integration)' -r -f -a "true\t''
false\t''"
complete -c lychee -l host-stats -d 'Show per-host statistics at the end of the run' -r -f -a "true\t''
false\t''"
complete -c lychee -l extensions -d 'A list of file extensions. Files not matching the specified extensions are skipped.' -r
complete -c lychee -l default-extension -d 'This is the default file extension that is applied to files without an extension.' -r
complete -c lychee -l cache -d 'Use request cache stored on disk at `.lycheecache`' -r -f -a "true\t''
false\t''"
complete -c lychee -l max-cache-age -d 'Discard all cached requests older than this duration' -r
complete -c lychee -l cache-exclude-status -d 'A list of status codes that will be ignored from the cache' -r
complete -c lychee -l dump -d 'Don\'t perform any link checking. Instead, dump all the links extracted from inputs that would be checked' -r -f -a "true\t''
false\t''"
complete -c lychee -l dump-inputs -d 'Don\'t perform any link extraction and checking. Instead, dump all input sources from which links would be collected' -r -f -a "true\t''
false\t''"
complete -c lychee -l archive -d 'Web archive to use to provide suggestions for `--suggest`' -r -f -a "wayback\t''"
complete -c lychee -l suggest -d 'Suggest link replacements for broken links, using a web archive. The web archive can be specified with `--archive`' -r -f -a "true\t''
false\t''"
complete -c lychee -s m -l max-redirects -d 'Maximum number of allowed redirects' -r
complete -c lychee -l max-retries -d 'Maximum number of retries per request' -r
complete -c lychee -l min-tls -d 'Minimum accepted TLS Version' -r -f -a "TLSv1_0\t''
TLSv1_1\t''
TLSv1_2\t''
TLSv1_3\t''"
complete -c lychee -l max-concurrency -d 'Maximum number of concurrent network requests' -r
complete -c lychee -l host-concurrency -d 'Default maximum concurrent requests per host (default: 10)' -r
complete -c lychee -l host-request-interval -d 'Minimum interval between requests to the same host (default: 50ms)' -r
complete -c lychee -s T -l threads -d 'Number of threads to utilize. Defaults to number of cores available to the system' -r
complete -c lychee -s u -l user-agent -d 'User agent' -r
complete -c lychee -s i -l insecure -d 'Proceed for server connections considered insecure (invalid TLS)' -r -f -a "true\t''
false\t''"
complete -c lychee -s s -l scheme -d 'Only test links with the given schemes (e.g. https). Omit to check links with any other scheme. At the moment, we support http, https, file, and mailto.' -r
complete -c lychee -l offline -d 'Only check local files and block network requests' -r -f -a "true\t''
false\t''"
complete -c lychee -l include -d 'URLs to check (supports regex). Has preference over all excludes' -r
complete -c lychee -l exclude -d 'Exclude URLs and mail addresses from checking. The values are treated as regular expressions' -r
complete -c lychee -l exclude-file -d 'Deprecated; use `--exclude-path` instead' -r
complete -c lychee -l exclude-path -d 'Exclude paths from getting checked. The values are treated as regular expressions' -r
complete -c lychee -s E -l exclude-all-private -d 'Exclude all private IPs from checking. Equivalent to `--exclude-private --exclude-link-local --exclude-loopback`' -r -f -a "true\t''
false\t''"
complete -c lychee -l exclude-private -d 'Exclude private IP address ranges from checking' -r -f -a "true\t''
false\t''"
complete -c lychee -l exclude-link-local -d 'Exclude link-local IP address range from checking' -r -f -a "true\t''
false\t''"
complete -c lychee -l exclude-loopback -d 'Exclude loopback IP address range and localhost from checking' -r -f -a "true\t''
false\t''"
complete -c lychee -l include-mail -d 'Also check email addresses' -r -f -a "true\t''
false\t''"
complete -c lychee -l remap -d 'Remap URI matching pattern to different URI' -r
complete -c lychee -l fallback-extensions -d 'When checking locally, attempts to locate missing files by trying the given fallback extensions. Multiple extensions can be separated by commas. Extensions will be checked in order of appearance.' -r
complete -c lychee -l index-files -d 'When checking locally, resolves directory links to a separate index file. The argument is a comma-separated list of index file names to search for. Index names are relative to the link\'s directory and attempted in the order given.' -r
complete -c lychee -s H -l header -d 'Set custom header for requests.' -r
complete -c lychee -s a -l accept -d 'A List of accepted status codes for valid links' -r
complete -c lychee -l accept-timeouts -d 'Accept timed out requests and return exit code 0 when encountering timeouts but not any other errors' -r -f -a "true\t''
false\t''"
complete -c lychee -l include-fragments -d 'Enable the checking of fragments in links.' -r
complete -c lychee -s t -l timeout -d 'Website timeout in seconds from connect to response finished' -r
complete -c lychee -s r -l retry-wait-time -d 'Minimum wait time in seconds between retries of failed requests' -r
complete -c lychee -s X -l method -d 'Request method' -r
complete -c lychee -l base -d 'Deprecated; use `--base-url` instead' -r
complete -c lychee -s b -l base-url -d 'Base URL to use when resolving relative URLs in local files. If specified, relative links in local files are interpreted as being relative to the given base URL.' -r
complete -c lychee -l root-dir -d 'Root directory to use when checking absolute links in local files. This option is required if absolute links appear in local files, otherwise those links will be flagged as errors. This must be an absolute path (i.e., one beginning with `/`).' -r -F
complete -c lychee -l basic-auth -d 'Basic authentication support. E.g. `http://example.com username:password`' -r
complete -c lychee -l github-token -d 'GitHub API token to use when checking github.com links, to avoid rate limiting' -r
complete -c lychee -l skip-missing -d 'Skip missing input files (default is to error if they don\'t exist)' -r -f -a "true\t''
false\t''"
complete -c lychee -l no-ignore -d 'Do not skip files that would otherwise be ignored by \'.gitignore\', \'.ignore\', or the global ignore file' -r -f -a "true\t''
false\t''"
complete -c lychee -l hidden -d 'Do not skip hidden directories and files' -r -f -a "true\t''
false\t''"
complete -c lychee -l include-verbatim -d 'Find links in verbatim sections like `pre`- and `code` blocks' -r -f -a "true\t''
false\t''"
complete -c lychee -l glob-ignore-case -d 'Ignore case when expanding filesystem path glob inputs' -r -f -a "true\t''
false\t''"
complete -c lychee -s o -l output -d 'Output file of status report' -r -F
complete -c lychee -l mode -d 'Set the output display mode. Determines how results are presented in the terminal' -r -f -a "plain\t''
color\t''
emoji\t''
task\t''"
complete -c lychee -s f -l format -d 'Output format of final status report' -r -f -a "compact\t''
detailed\t''
json\t''
junit\t''
markdown\t''"
complete -c lychee -l generate -d 'Generate special output (e.g. the man page) instead of performing link checking' -r -f -a "man\t''
complete-bash\t''
complete-elvish\t''
complete-fish\t''
complete-powershell\t''
complete-zsh\t''"
complete -c lychee -l require-https -d 'When HTTPS is available, treat HTTP links as errors' -r -f -a "true\t''
false\t''"
complete -c lychee -l cookie-jar -d 'Read and write cookies using the given file. Cookies will be stored in the cookie jar and sent with requests. New cookies will be stored in the cookie jar and existing cookies will be updated.' -r -F
complete -c lychee -l include-wikilinks -d 'Check WikiLinks in Markdown files, this requires specifying --base-url' -r -f -a "true\t''
false\t''"
complete -c lychee -s p -l preprocess -d 'Preprocess input files with the given command.' -r
complete -c lychee -s v -l verbose -d 'Set verbosity level; more output per occurrence (e.g. `-v` or `-vv`)'
complete -c lychee -s q -l quiet -d 'Less output per occurrence (e.g. `-q` or `-qq`)'
complete -c lychee -s h -l help -d 'Print help (see more with \'--help\')'
complete -c lychee -s V -l version -d 'Print version'
