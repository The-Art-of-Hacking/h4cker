_lychee() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="lychee"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        lychee)
            opts="-c -v -q -n -m -T -u -i -s -E -H -a -t -r -X -b -o -f -p -h -V --config --files-from --verbose --quiet --no-progress --host-stats --extensions --default-extension --cache --max-cache-age --cache-exclude-status --dump --dump-inputs --archive --suggest --max-redirects --max-retries --min-tls --max-concurrency --host-concurrency --host-request-interval --threads --user-agent --insecure --scheme --offline --include --exclude --exclude-file --exclude-path --exclude-all-private --exclude-private --exclude-link-local --exclude-loopback --include-mail --remap --fallback-extensions --index-files --header --accept --accept-timeouts --include-fragments --timeout --retry-wait-time --method --base --base-url --root-dir --basic-auth --github-token --skip-missing --no-ignore --hidden --include-verbatim --glob-ignore-case --output --mode --format --generate --require-https --cookie-jar --include-wikilinks --preprocess --help --version [inputs]..."
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --files-from)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --no-progress)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                -n)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --host-stats)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --extensions)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --default-extension)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --max-cache-age)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --cache-exclude-status)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dump)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --dump-inputs)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --archive)
                    COMPREPLY=($(compgen -W "wayback" -- "${cur}"))
                    return 0
                    ;;
                --suggest)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --max-redirects)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -m)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --max-retries)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --min-tls)
                    COMPREPLY=($(compgen -W "TLSv1_0 TLSv1_1 TLSv1_2 TLSv1_3" -- "${cur}"))
                    return 0
                    ;;
                --max-concurrency)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-concurrency)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --host-request-interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --threads)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -T)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --user-agent)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -u)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --insecure)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                -i)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --scheme)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -s)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --offline)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --include)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-path)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --exclude-all-private)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                -E)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --exclude-private)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --exclude-link-local)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --exclude-loopback)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --include-mail)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --remap)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --fallback-extensions)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --index-files)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --header)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -H)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --accept)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -a)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --accept-timeouts)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --include-fragments)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --timeout)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -t)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --retry-wait-time)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -r)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --method)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -X)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --base)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --base-url)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -b)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --root-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --basic-auth)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --github-token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --skip-missing)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --no-ignore)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --hidden)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --include-verbatim)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --glob-ignore-case)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --mode)
                    COMPREPLY=($(compgen -W "plain color emoji task" -- "${cur}"))
                    return 0
                    ;;
                --format)
                    COMPREPLY=($(compgen -W "compact detailed json junit markdown" -- "${cur}"))
                    return 0
                    ;;
                -f)
                    COMPREPLY=($(compgen -W "compact detailed json junit markdown" -- "${cur}"))
                    return 0
                    ;;
                --generate)
                    COMPREPLY=($(compgen -W "man complete-bash complete-elvish complete-fish complete-powershell complete-zsh" -- "${cur}"))
                    return 0
                    ;;
                --require-https)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --cookie-jar)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --include-wikilinks)
                    COMPREPLY=($(compgen -W "true false" -- "${cur}"))
                    return 0
                    ;;
                --preprocess)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -p)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _lychee -o nosort -o bashdefault -o default lychee
else
    complete -F _lychee -o bashdefault -o default lychee
fi
