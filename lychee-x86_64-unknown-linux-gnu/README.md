<div align="center">

<a name="back-to-top"></a>
![lychee](assets/logo.svg)

[![Homepage](https://img.shields.io/badge/Homepage-Online-EA3A97)](https://lychee.cli.rs/)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-lychee-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAM6wAADOsB5dZE0gAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAERSURBVCiRhZG/SsMxFEZPfsVJ61jbxaF0cRQRcRJ9hlYn30IHN/+9iquDCOIsblIrOjqKgy5aKoJQj4O3EEtbPwhJbr6Te28CmdSKeqzeqr0YbfVIrTBKakvtOl5dtTkK+v4HfA9PEyBFCY9AGVgCBLaBp1jPAyfAJ/AAdIEG0dNAiyP7+K1qIfMdonZic6+WJoBJvQlvuwDqcXadUuqPA1NKAlexbRTAIMvMOCjTbMwl1LtI/6KWJ5Q6rT6Ht1MA58AX8Apcqqt5r2qhrgAXQC3CZ6i1+KMd9TRu3MvA3aH/fFPnBodb6oe6HM8+lYHrGdRXW8M9bMZtPXUji69lmf5Cmamq7quNLFZXD9Rq7v0Bpc1o/tp0fisAAAAASUVORK5CYII=)](https://github.com/marketplace/actions/lychee-broken-link-checker)
[![Rust](https://github.com/lycheeverse/lychee/workflows/CI/badge.svg)](https://github.com/lycheeverse/lychee/actions/workflows/ci.yml)
[![docs.rs](https://img.shields.io/docsrs/lychee-lib/latest)](https://docs.rs/lychee-lib/latest/lychee_lib/)
[![Check Links](https://github.com/lycheeverse/lychee/actions/workflows/links.yml/badge.svg)](https://github.com/lycheeverse/lychee/actions/workflows/links.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/lycheeverse/lychee?color=%23099cec&logo=Docker)](https://hub.docker.com/r/lycheeverse/lychee)

⚡ A fast, async, stream-based link checker written in Rust ⚡\
Finds broken hyperlinks and mail addresses in websites
and Markdown, HTML, and other file formats!\
Available as command-line utility,
[library](https://docs.rs/lychee-lib/latest/lychee_lib/) and
[GitHub Action](https://github.com/lycheeverse/lychee-action).

</div>

![Lychee demo](./assets/screencast.svg)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of Contents

- [Development](#development)
- [Installation](#installation)
- [Features](#features)
- [Commandline usage](#commandline-usage)
- [Supported file formats](#supported-file-formats)
- [Library usage](#library-usage)
- [GitHub Action Usage](#github-action-usage)
- [Pre-commit Usage](#pre-commit-usage)
- [Contributing to lychee](#contributing-to-lychee)
- [Troubleshooting and Workarounds](#troubleshooting-and-workarounds)
- [Users](#users)
- [Credits](#credits)
- [License](#license)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Development

After [installing Rust](https://rust-lang.org/tools/install/) use [Cargo](https://doc.rust-lang.org/cargo/) for building and testing.
For Nix we provide a flake so you can use `nix develop` and `nix build`.

## Installation

<details><summary><b>View installation instructions</b></summary>

### Arch Linux

```sh
pacman -S lychee
```

### OpenSUSE Tumbleweed

```sh
zypper in lychee
```

### Ubuntu

```sh
snap install lychee
```

### Alpine Linux

```sh
 # available for Alpine Edge in testing repositories
apk add lychee
```

### macOS

Via [Homebrew](https://brew.sh):

```sh
brew install lychee
```

Via [MacPorts](https://www.macports.org):

```sh
sudo port install lychee
```

### Docker

```sh
docker pull lycheeverse/lychee
```

### Nix

```sh
nix-shell -p lychee
```

Or let Nix even check a packaged site with [`testers.lycheeLinkCheck`](https://nixos.org/manual/nixpkgs/stable/#tester-lycheeLinkCheck) `{ site = …; }`

### FreeBSD

```sh
pkg install lychee
```

### Termux

```sh
pkg install lychee
```

### Conda

```sh
conda install lychee -c conda-forge
```

### Windows

Via [scoop](https://scoop.sh/):

```sh
scoop install lychee
```

Via [WinGet](https://github.com/microsoft/winget-cli):

```sh
winget install --id lycheeverse.lychee
```

Via [Chocolatey](https://chocolatey.org/):

```sh
choco install lychee
```

</details>

### Pre-built binaries

We provide binaries for Linux, macOS, and Windows for every release. \
You can download them from the [releases page](https://github.com/lycheeverse/lychee/releases).

### Cargo

#### Build dependencies

On APT/dpkg-based Linux distros (e.g. Debian, Ubuntu, Linux Mint and Kali Linux)
the following commands will install all required build dependencies, including
the Rust toolchain and `cargo`:

```sh
curl -sSf 'https://sh.rustup.rs' | sh
apt install gcc pkg-config libc6-dev libssl-dev
```

#### Compile and install lychee

```sh
cargo install lychee
```

#### Feature flags

Lychee supports the following feature flags:

- `email-check` enables checking email addresses using the [mailify-lib](https://crates.io/crates/mailify-lib) crate.
- `check_example_domains` allows checking example domains such as `example.com`. This feature is useful for testing.

By default, `email-check` is enabled.
Note that in the past lychee could be configured to use either OpenSSL or Rustls.
[It was decided](https://github.com/lycheeverse/lychee/pull/1928)
to fully switch to Rustls and drop OpenSSL support.
Please tell us if this negatively affects you in any way.

## Features

This comparison is made on a best-effort basis. Please create a PR to fix
outdated information.

|                      | lychee  | [awesome_bot] | [muffet] | [broken-link-checker] | [linkinator] | [linkchecker]        | [markdown-link-check] | [fink] |
| -------------------- | ------- | ------------- | -------- | --------------------- | ------------ | -------------------- | --------------------- | ------ |
| Language             | Rust    | Ruby          | Go       | JS                    | TypeScript   | Python               | JS                    | PHP    |
| Async/Parallel       | ![yes]  | ![yes]        | ![yes]   | ![yes]                | ![yes]       | ![yes]               | ![yes]                | ![yes] |
| JSON output          | ![yes]  | ![no]         | ![yes]   | ![yes]                | ![yes]       | ![maybe]<sup>1</sup> | ![yes]                | ![yes] |
| Static binary        | ![yes]  | ![no]         | ![yes]   | ![no]                 | ![no]        | ️![no]               | ![no]                 | ![no]  |
| Markdown files       | ![yes]  | ![yes]        | ![no]    | ![no]                 | ![no]        | ![yes]               | ![yes]                | ![no]  |
| HTML files           | ![yes]  | ![no]         | ![no]    | ![yes]                | ![yes]       | ![no]                | ![yes]                | ![no]  |
| Text files           | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![no]                | ![no]                 | ![no]  |
| Website support      | ![yes]  | ![no]         | ![yes]   | ![yes]                | ![yes]       | ![yes]               | ![no]                 | ![yes] |
| Chunked encodings    | ![yes]  | ![maybe]      | ![maybe] | ![maybe]              | ![maybe]     | ![no]                | ![yes]                | ![yes] |
| GZIP compression     | ![yes]  | ![maybe]      | ![maybe] | ![yes]                | ![maybe]     | ![yes]               | ![maybe]              | ![no]  |
| Basic Auth           | ![yes]  | ![no]         | ![no]    | ![yes]                | ![no]        | ![yes]               | ![no]                 | ![no]  |
| Custom user agent    | ![yes]  | ![no]         | ![no]    | ![yes]                | ![no]        | ![yes]               | ![no]                 | ![no]  |
| Relative URLs        | ![yes]  | ![yes]        | ![no]    | ![yes]                | ![yes]       | ![yes]               | ![yes]                | ![yes] |
| Anchors/Fragments    | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![yes]               | ![yes]                | ![no]  |
| Include patterns     | ![yes]️  | ![yes]        | ![no]    | ![yes]                | ![no]        | ![no]                | ![no]                 | ![no]  |
| Exclude patterns     | ![yes]  | ![no]         | ![yes]   | ![yes]                | ![yes]       | ![yes]               | ![yes]                | ![yes] |
| Handle redirects     | ![yes]  | ![yes]        | ![yes]   | ![yes]                | ![yes]       | ![yes]               | ![yes]                | ![yes] |
| Ignore insecure SSL  | ![yes]  | ![yes]        | ![yes]   | ![no]                 | ![no]        | ![yes]               | ![no]                 | ![yes] |
| File globbing        | ![yes]  | ![yes]        | ![no]    | ![no]                 | ![yes]       | ![no]                | ![yes]                | ![no]  |
| Limit scheme         | ![yes]  | ![no]         | ![no]    | ![yes]                | ![no]        | ![yes]               | ![no]                 | ![no]  |
| [Custom headers]     | ![yes]  | ![no]         | ![yes]   | ![no]                 | ![no]        | ![no]                | ![yes]                | ![yes] |
| Summary              | ![yes]  | ![yes]        | ![yes]   | ![maybe]              | ![yes]       | ![yes]               | ![no]                 | ![yes] |
| `HEAD` requests      | ![yes]  | ![yes]        | ![no]    | ![yes]                | ![yes]       | ![yes]               | ![no]                 | ![no]  |
| Colored output       | ![yes]  | ![maybe]      | ![yes]   | ![maybe]              | ![yes]       | ![yes]               | ![no]                 | ![yes] |
| [Filter status code] | ![yes]  | ![yes]        | ![no]    | ![no]                 | ![no]        | ![no]                | ![yes]                | ![no]  |
| Custom timeout       | ![yes]  | ![yes]        | ![yes]   | ![no]                 | ![yes]       | ![yes]               | ![no]                 | ![yes] |
| E-mail links         | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![yes]               | ![no]                 | ![no]  |
| Progress bar         | ![yes]  | ![yes]        | ![no]    | ![no]                 | ![no]        | ![yes]               | ![yes]                | ![yes] |
| Retry and backoff    | ![yes]  | ![no]         | ![no]    | ![no]                 | ![yes]       | ![no]                | ![yes]                | ![no]  |
| Per-host throttling  | ![yes]  | ![no]         | ![yes]   | ![yes]                | ![no]        | ![yes]               | ![no]                 | ![no]  |
| Respect rate limits  | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![no]                | ![no]                 | ![no]  |
| Skip private domains | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![no]                | ![no]                 | ![no]  |
| [Use as library]     | ![yes]  | ![yes]        | ![no]    | ![yes]                | ![yes]       | ![no]                | ![yes]                | ![no]  |
| Quiet mode           | ![yes]  | ![no]         | ![no]    | ![no]                 | ![yes]       | ![yes]               | ![yes]                | ![yes] |
| [Config file]        | ![yes]  | ![no]         | ![no]    | ![no]                 | ![yes]       | ![yes]               | ![yes]                | ![no]  |
| Cookies              | ![yes]  | ![no]         | ![yes]   | ![no]                 | ![no]        | ![yes]               | ![no]                 | ![yes] |
| Recursion            | ![no]   | ![no]         | ![yes]   | ![yes]                | ![yes]       | ![yes]               | ![yes]                | ![no]  |
| Amazing lychee logo  | ![yes]  | ![no]         | ![no]    | ![no]                 | ![no]        | ![no]                | ![no]                 | ![no]  |

[awesome_bot]: https://github.com/dkhamsing/awesome_bot
[muffet]: https://github.com/raviqqe/muffet
[broken-link-checker]: https://github.com/stevenvachon/broken-link-checker
[linkinator]: https://github.com/JustinBeckwith/linkinator
[linkchecker]: https://github.com/linkchecker/linkchecker
[markdown-link-check]: https://github.com/tcort/markdown-link-check
[fink]: https://github.com/dantleech/fink
[yes]: ./assets/yes.svg
[no]: ./assets/no.svg
[maybe]: ./assets/maybe.svg
[custom headers]: https://github.com/rust-lang/crates.io/issues/788
[filter status code]: https://github.com/tcort/markdown-link-check/issues/94
[skip private domains]: https://github.com/appscodelabs/liche/blob/a5102b0bf90203b467a4f3b4597d22cd83d94f99/url_checker.go
[use as library]: https://github.com/raviqqe/liche/issues/13
[config file]: https://github.com/lycheeverse/lychee/blob/master/lychee.example.toml

<sup>1</sup> Other machine-readable formats like CSV are supported.

## Commandline usage

```sh
# recursively check all links in supported files inside the current directory
lychee .

# check links in specific local file(s):
lychee README.md test.html info.txt

# check links on a website:
lychee https://endler.dev
```

For more examples check out our
[usage guide](https://lychee.cli.rs/guides/getting-started/#usage).

<details><summary><b>Docker Usage</b></summary>

Here's how to mount a local directory into the container and check some input
with lychee.

- The `--init` parameter is passed so that lychee can be stopped from the terminal.
- We also pass `-it` to start an interactive terminal, which is required to show the progress bar.
- The `--rm` removes not used anymore container from the host after the run (self-cleanup).
- The `-w /input` points to `/input` as the default workspace
- The `-v $(pwd):/input` does local volume mounting to the container for lychee access.

> By default a Debian-based Docker image is used. If you want to run an Alpine-based image, use the `latest-alpine` tag.
> For example, `lycheeverse/lychee:latest-alpine`

#### Linux/macOS shell command

```sh
docker run --init -it --rm -w /input -v $(pwd):/input lycheeverse/lychee README.md
```

#### Windows PowerShell command

```powershell
docker run --init -it --rm -w /input -v ${PWD}:/input lycheeverse/lychee README.md
```

</details>

### GitHub Token

To avoid getting rate-limited while checking GitHub links, you can optionally
set an environment variable with your GitHub token like so `GITHUB_TOKEN=xxxx`,
or use the `--github-token` CLI option. It can also be set in the config file.
[Here is an example config file][config file].

The token can be generated on your [GitHub account settings page](https://github.com/settings/tokens).
A personal access token with no extra permissions is enough to be able to check public repo links.

For more scalable organization-wide scenarios you can consider a [GitHub App][github-app-overview].
It has a higher rate limit than personal access tokens but requires additional configuration steps on your GitHub workflow.
Please follow the [GitHub App Setup][github-app-setup] example.

[github-app-overview]: https://docs.github.com/en/apps/overview
[github-app-setup]: https://github.com/github/combine-prs/blob/main/docs/github-app-setup.md#github-app-setup

### Commandline Parameters

Use `lychee --help` or `man lychee` to see all available command line parameters.

<details><summary><b>View full help message</b></summary>

```help-message
lychee is a fast, asynchronous link checker which detects broken URLs and mail addresses in local files and websites. It supports Markdown and HTML and works with other file formats.

lychee is powered by lychee-lib, the Rust library for link checking.

Usage: lychee [OPTIONS] [inputs]...

Arguments:
  [inputs]...
          Inputs for link checking (where to get links to check from).
          These can be: files (e.g. `README.md`), file globs (e.g. `'~/git/*/README.md'`),
          remote URLs (e.g. `https://example.com/README.md`), or standard input (`-`).
          Alternatively, use `--files-from` to read inputs from a file.

          NOTE: Use `--` to separate inputs from options that allow multiple arguments.

Options:
  -a, --accept <ACCEPT>
          A List of accepted status codes for valid links

          The following accept range syntax is supported: [start]..[[=]end]|code.
          Some valid examples are:

          - 200 (accepts the 200 status code only)
          - ..204 (accepts any status code < 204)
          - ..=204 (accepts any status code <= 204)
          - 200..=204 (accepts any status code from 200 to 204 inclusive)
          - 200..205 (accepts any status code from 200 to 205 excluding 205, same as 200..=204)

          Use "lychee --accept '200..=204, 429, 500' <inputs>..." to provide a comma-
          separated list of accepted status codes. This example will accept 200, 201,
          202, 203, 204, 429, and 500 as valid status codes.

          [default: 100..=103,200..=299]

      --accept-timeouts[=<false|true>]
          Accept timed out requests and return exit code 0 when encountering timeouts but not any other errors

      --archive <ARCHIVE>
          Web archive to use to provide suggestions for `--suggest`.

          [default: wayback]

          [possible values: wayback]

  -b, --base-url <BASE_URL>
          Base URL to use when resolving relative URLs in local files. If specified,
          relative links in local files are interpreted as being relative to the given
          base URL.

          For example, given a base URL of `https://example.com/dir/page`, the link `a`
          would resolve to `https://example.com/dir/a` and the link `/b` would resolve
          to `https://example.com/b`. This behavior is not affected by the filesystem
          path of the file containing these links.

          Note that relative URLs without a leading slash become siblings of the base
          URL. If, instead, the base URL ended in a slash, the link would become a child
          of the base URL. For example, a base URL of `https://example.com/dir/page/` and
          a link of `a` would resolve to `https://example.com/dir/page/a`.

          Basically, the base URL option resolves links as if the local files were hosted
          at the given base URL address.

          The provided base URL value must either be a URL (with scheme) or an absolute path.
          Note that certain URL schemes cannot be used as a base, e.g., `data` and `mailto`.

      --base <BASE>
          Deprecated; use `--base-url` instead

      --basic-auth <BASIC_AUTH>
          Basic authentication support. E.g. `http://example.com username:password`

  -c, --config <FILE_PATH>
          Configuration file to use. Can be specified multiple times.

          If given multiple times, the configs are merged and later
          occurrences take precedence over previous occurrences.

          [default: lychee.toml]

      --cache[=<false|true>]
          Use request cache stored on disk at `.lycheecache`

      --cache-exclude-status <CACHE_EXCLUDE_STATUS>
          A list of status codes that will be ignored from the cache

          The following exclude range syntax is supported: [start]..[[=]end]|code. Some valid
          examples are:

          - 429 (excludes the 429 status code only)
          - 500.. (excludes any status code >= 500)
          - ..100 (excludes any status code < 100)
          - 500..=599 (excludes any status code from 500 to 599 inclusive)
          - 500..600 (excludes any status code from 500 to 600 excluding 600, same as 500..=599)

          Use "lychee --cache-exclude-status '429, 500..502' <inputs>..." to provide a
          comma-separated list of excluded status codes. This example will not cache results
          with a status code of 429, 500 and 501.

      --cookie-jar <COOKIE_JAR>
          Read and write cookies using the given file. Cookies will be stored in the
          cookie jar and sent with requests. New cookies will be stored in the cookie jar
          and existing cookies will be updated.

      --default-extension <EXTENSION>
          This is the default file extension that is applied to files without an extension.

          This is useful for files without extensions or with unknown extensions.
          The extension will be used to determine the file type for processing.

          Examples:
            --default-extension md
            --default-extension html

      --dump[=<false|true>]
          Don't perform any link checking. Instead, dump all the links extracted from inputs that would be checked

      --dump-inputs[=<false|true>]
          Don't perform any link extraction and checking. Instead, dump all input sources from which links would be collected

  -E, --exclude-all-private[=<false|true>]
          Exclude all private IPs from checking.
          Equivalent to `--exclude-private --exclude-link-local --exclude-loopback`

      --exclude <EXCLUDE>
          Exclude URLs and mail addresses from checking. The values are treated as regular expressions

      --exclude-file <EXCLUDE_FILE>
          Deprecated; use `--exclude-path` instead

      --exclude-link-local[=<false|true>]
          Exclude link-local IP address range from checking

      --exclude-loopback[=<false|true>]
          Exclude loopback IP address range and localhost from checking

      --exclude-path <EXCLUDE_PATH>
          Exclude paths from getting checked. The values are treated as regular expressions

      --exclude-private[=<false|true>]
          Exclude private IP address ranges from checking

      --extensions <EXTENSIONS>
          A list of file extensions. Files not matching the specified extensions are skipped.

          Multiple extensions can be separated by commas. Note that if you want to check filetypes,
          which have multiple extensions, e.g. HTML files with both .html and .htm extensions, you need to
          specify both extensions explicitly.
          An example is: `--extensions html,htm,php,asp,aspx,jsp,cgi`.

          This is useful when the default extensions are not enough and you don't
          want to provide a long list of inputs (e.g. file1.html, file2.md, etc.)

          [default: md,mkd,mdx,mdown,mdwn,mkdn,mkdown,markdown,html,htm,css,txt,xml]

  -f, --format <FORMAT>
          Output format of final status report

          [default: compact]

          [possible values: compact, detailed, json, junit, markdown]

      --fallback-extensions <FALLBACK_EXTENSIONS>
          When checking locally, attempts to locate missing files by trying the given
          fallback extensions. Multiple extensions can be separated by commas. Extensions
          will be checked in order of appearance.

          Example: --fallback-extensions html,htm,php,asp,aspx,jsp,cgi

          Note: This option takes effect on `file://` URIs which do not exist and on
                `file://` URIs pointing to directories which resolve to themself (by the
                --index-files logic).

      --files-from <PATH>
          Read input filenames from the given file or stdin (if path is '-').

          This is useful when you have a large number of inputs that would be
          cumbersome to specify on the command line directly.

          Examples:

              lychee --files-from list.txt
              find . -name '*.md' | lychee --files-from -
              echo 'README.md' | lychee --files-from -

          File Format:
          - Each line should contain one input (file path, URL, or glob pattern).
          - Lines starting with '#' are treated as comments and ignored.
          - Empty lines are also ignored.

      --generate <GENERATE>
          Generate special output (e.g. the man page) instead of performing link checking

          [possible values: man, complete-bash, complete-elvish, complete-fish, complete-powershell, complete-zsh]

      --github-token <GITHUB_TOKEN>
          GitHub API token to use when checking github.com links, to avoid rate limiting

          [env: GITHUB_TOKEN]

      --glob-ignore-case[=<false|true>]
          Ignore case when expanding filesystem path glob inputs

  -h, --help
          Print help (see a summary with '-h')

  -H, --header <HEADER:VALUE>
          Set custom header for requests.

          Some websites require custom headers to be passed in order to return valid responses.
          You can specify custom headers in the format 'Name: Value'. For example, 'Accept: text/html'.
          This is the same format that other tools like curl or wget use.
          Multiple headers can be specified by using the flag multiple times.
          The specified headers are used for ALL requests.
          Use the `hosts` option to configure headers on a per-host basis.

      --hidden[=<false|true>]
          Do not skip hidden directories and files

      --host-concurrency <HOST_CONCURRENCY>
          Default maximum concurrent requests per host (default: 10)

          This limits the maximum amount of requests that are sent simultaneously
          to the same host. This helps to prevent overwhelming servers and
          running into rate-limits. Use the `hosts` option to configure this
          on a per-host basis.

          Examples:
            --host-concurrency 2   # Conservative for slow APIs
            --host-concurrency 20  # Aggressive for fast APIs

      --host-request-interval <HOST_REQUEST_INTERVAL>
          Minimum interval between requests to the same host (default: 50ms)

          Sets a baseline delay between consecutive requests to prevent
          overloading servers. The adaptive algorithm may increase this based
          on server responses (rate limits, errors). Use the `hosts` option
          to configure this on a per-host basis.

          Examples:
            --host-request-interval 50ms   # Fast for robust APIs
            --host-request-interval 1s     # Conservative for rate-limited APIs

      --host-stats[=<false|true>]
          Show per-host statistics at the end of the run

  -i, --insecure[=<false|true>]
          Proceed for server connections considered insecure (invalid TLS)

      --include <INCLUDE>
          URLs to check (supports regex). Has preference over all excludes

      --include-fragments[=<none|anchor-only|text-only|full>]
          Enable the checking of fragments in links.

          Use `none` to disable fragment checks, `anchor-only` for anchor fragments
          like `#section`, `text-only` for text fragments like `#:~:text=example`,
          or `full` to check both.

          If provided without a value, defaults to `anchor-only`.

      --include-mail[=<false|true>]
          Also check email addresses

      --include-verbatim[=<false|true>]
          Find links in verbatim sections like `pre`- and `code` blocks

      --include-wikilinks[=<false|true>]
          Check WikiLinks in Markdown files, this requires specifying --base-url

      --index-files <INDEX_FILES>
          When checking locally, resolves directory links to a separate index file.
          The argument is a comma-separated list of index file names to search for. Index
          names are relative to the link's directory and attempted in the order given.

          If `--index-files` is specified, then at least one index file must exist in
          order for a directory link to be considered valid. Additionally, the special
          name `.` can be used in the list to refer to the directory itself.

          If unspecified (the default behavior), index files are disabled and directory
          links are considered valid as long as the directory exists on disk.

          Example 1: `--index-files index.html,readme.md` looks for index.html or readme.md
                     and requires that at least one exists.

          Example 2: `--index-files index.html,.` will use index.html if it exists, but
                     still accept the directory link regardless.

          Example 3: `--index-files ''` will reject all directory links because there are
                     no valid index files. This will require every link to explicitly name
                     a file.

          Note: This option only takes effect on `file://` URIs which exist and point to a directory.

  -m, --max-redirects <MAX_REDIRECTS>
          Maximum number of allowed redirects

          [default: 10]

      --max-cache-age <MAX_CACHE_AGE>
          Discard all cached requests older than this duration

          [default: 1d]

      --max-concurrency <MAX_CONCURRENCY>
          Maximum number of concurrent network requests

          [default: 128]

      --max-retries <MAX_RETRIES>
          Maximum number of retries per request

          [default: 3]

      --min-tls <MIN_TLS>
          Minimum accepted TLS Version

          [possible values: TLSv1_0, TLSv1_1, TLSv1_2, TLSv1_3]

      --mode <MODE>
          Set the output display mode. Determines how results are presented in the terminal

          [default: color]

          [possible values: plain, color, emoji, task]

  -n, --no-progress[=<false|true>]
          Do not show progress bar.
          This is recommended for non-interactive shells (e.g. for continuous integration)

      --no-ignore[=<false|true>]
          Do not skip files that would otherwise be ignored by '.gitignore', '.ignore', or the global ignore file

  -o, --output <OUTPUT>
          Output file of status report

      --offline[=<false|true>]
          Only check local files and block network requests

  -p, --preprocess <COMMAND>
          Preprocess input files with the given command.

          For each file input, this flag causes lychee to execute `COMMAND PATH` and process
          its standard output instead of the original contents of PATH. This allows you to
          convert files that would otherwise not be understood by lychee. The preprocessor
          COMMAND is only run on input files, not on standard input or URLs.

          To invoke programs with custom arguments or to use multiple preprocessors, use a
          wrapper program such as a shell script. An example script looks like this:

          ```
          #!/usr/bin/env bash
          case "$1" in
          *.pdf)
              exec pdftohtml -i -s -stdout "$1"
              ;;
          *.odt|*.docx|*.epub|*.ipynb)
              exec pandoc "$1" --to=html --wrap=none
              ;;
          *)
              # identity function, output input without changes
              exec cat
              ;;
          esac
          ```

  -q, --quiet...
          Less output per occurrence (e.g. `-q` or `-qq`)

  -r, --retry-wait-time <RETRY_WAIT_TIME>
          Minimum wait time in seconds between retries of failed requests

          [default: 1]

      --remap <REMAP>
          Remap URI matching pattern to different URI

      --require-https[=<false|true>]
          When HTTPS is available, treat HTTP links as errors

      --root-dir <ROOT_DIR>
          Root directory to use when checking absolute links in local files. This option is
          required if absolute links appear in local files, otherwise those links will be
          flagged as errors. This must be an absolute path (i.e., one beginning with `/`).

          If specified, absolute links in local files are resolved by prefixing the given
          root directory to the requested absolute link. For example, with a root-dir of
          `/root/dir`, a link to `/page.html` would be resolved to `/root/dir/page.html`.

          This option can be specified alongside `--base-url`. If both are given, an
          absolute link is resolved by constructing a URL from three parts: the domain
          name specified in `--base-url`, followed by the `--root-dir` directory path,
          followed by the absolute link's own path.

  -s, --scheme <SCHEME>
          Only test links with the given schemes (e.g. https).
          Omit to check links with any other scheme.
          At the moment, we support http, https, file, and mailto.

      --skip-missing[=<false|true>]
          Skip missing input files (default is to error if they don't exist)

      --suggest[=<false|true>]
          Suggest link replacements for broken links, using a web archive. The web archive can be specified with `--archive`

  -t, --timeout <TIMEOUT>
          Website timeout in seconds from connect to response finished

          [default: 20]

  -T, --threads <THREADS>
          Number of threads to utilize. Defaults to number of cores available to the system

  -u, --user-agent <USER_AGENT>
          User agent

          [default: lychee/x.y.z]

  -v, --verbose...
          Set verbosity level; more output per occurrence (e.g. `-v` or `-vv`)

  -V, --version
          Print version

  -X, --method <METHOD>
          Request method

          [default: get]
```

</details>

### Exit codes

0   Success. The operation was completed successfully as instructed.

1   Missing inputs or any unexpected runtime failures or configuration errors

2   Link check failures. At least one non-excluded link failed the check.

3   Encountered errors in the config file.

### Ignoring and excluding links

You can exclude links from getting checked by specifying regex patterns
with `--exclude` (e.g. `--exclude example\.(com|org)`) or by putting
them into a file called `.lycheeignore`.
To exclude files and directories from being scanned use `--exclude-path`.
For more detailed explanations, check out our comprehensive
[guide on excluding links](https://lychee.cli.rs/recipes/excluding-links/).

### Caching

If the `--cache` flag is set, lychee will cache responses in a file called
`.lycheecache` in the current directory. If the file exists and the flag is set,
then the cache will be loaded on startup. This can greatly speed up future runs.
Note that by default lychee will not store any data on disk.
This is explained in more detail in [our documentation](https://lychee.cli.rs/recipes/caching/).

## Supported file formats

lychee supports HTML and Markdown file formats.
For any other file format, lychee falls back to a "plain text" mode.
This means that [linkify](https://github.com/robinst/linkify)
attempts to extract URLs on a best-effort basis.

For non-plaintext files (pdf, epub, docx, etc.) or for files
which don't work well with the fallback extraction method (csv, ipynb, etc.)
you can make use of the `--preprocess` option.

Take a look at [lychee-all](https://github.com/lycheeverse/lychee-all) for more information.

## Library usage

You can use lychee as a library for your own projects!
Take a look at the [library documentation](https://docs.rs/lychee-lib/latest/lychee_lib/).
Also check out the [examples](examples) directory for small practical examples.
These examples can be run with `cargo run --example <example>`.

## GitHub Action Usage

A GitHub Action that uses lychee is available as a separate repository: [lycheeverse/lychee-action](https://github.com/lycheeverse/lychee-action)
which includes usage instructions.

## Pre-commit Usage

Lychee can also be used as a [pre-commit](https://pre-commit.com/) hook.

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/lycheeverse/lychee.git
    rev: v0.15.1
    hooks:
      - id: lychee
        # Optionally include additional CLI arguments
        args: ["--no-progress", "--exclude", "file://"]
```

Rather than running on staged-files only, Lychee can be run against an entire repository.

```yaml
- id: lychee
  args: ["--no-progress", "."]
  pass_filenames: false
```

## Contributing to lychee

We'd be thankful for any contribution. \
We try to keep the issue tracker up-to-date so you can quickly find a task to work on.

Try one of these links to get started:

- [good first issues](https://github.com/lycheeverse/lychee/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
- [help wanted](https://github.com/lycheeverse/lychee/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)

For more detailed instructions, head over to [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## Troubleshooting and Workarounds

We collect a list of common workarounds for various websites in our [troubleshooting guide](./docs/TROUBLESHOOTING.md).

## Users

<details><summary><b>Here is a list of some notable projects who are using lychee.</b></summary>

- https://github.com/InnerSourceCommons/InnerSourcePatterns
- https://github.com/opensearch-project/OpenSearch
- https://github.com/ramitsurana/awesome-kubernetes
- https://github.com/papers-we-love/papers-we-love
- https://github.com/pingcap/docs
- https://github.com/microsoft/WhatTheHack
- https://github.com/nix-community/awesome-nix
- https://github.com/balena-io/docs
- https://github.com/launchdarkly/LaunchDarkly-Docs
- https://github.com/pawroman/links
- https://github.com/analysis-tools-dev/static-analysis
- https://github.com/analysis-tools-dev/dynamic-analysis
- https://github.com/mre/idiomatic-rust
- https://github.com/bencherdev/bencher
- https://github.com/sindresorhus/execa
- https://github.com/tldr-pages/tldr-maintenance
- https://github.com/git-ecosystem/git-credential-manager
- https://github.com/git/git-scm.com
- https://github.com/OWASP/threat-dragon
- https://github.com/oxc-project/oxc
- https://github.com/hugsy/gef
- https://github.com/mermaid-js/mermaid
- https://github.com/hashicorp/consul
- https://github.com/Unleash/unleash
- https://github.com/fastify/fastify
- https://github.com/nuxt/nuxt
- https://github.com/containerd/containerd
- https://github.com/rolldown/rolldown
- https://github.com/rerun-io/rerun
- https://github.com/0xAX/asm
- https://github.com/mainmatter/100-exercises-to-learn-rust
- https://github.com/GoogleCloudPlatform/generative-ai
- https://github.com/DioxusLabs/dioxus
- https://github.com/ministryofjustice/modernisation-platform
- https://github.com/orhun/binsider
- https://github.com/NVIDIA/aistore
- https://github.com/gradle/gradle
- https://github.com/duobaseio/forui
- https://github.com/FreeBSD-Ask/FreeBSD-Ask
- https://github.com/prosekit/prosekit
- https://github.com/tldr-pages/tldr
- https://gitlab.torproject.org/tpo/web/marble/support
- https://github.com/lycheeverse/lychee (yes, lychee is checked with lychee 🤯)

If you are using lychee for your project, **please add it here**.

</details>

## Credits

The first prototype of lychee was built in [episode 10 of Hello
Rust](https://hello-rust.github.io/10/). Thanks to all GitHub and Patreon sponsors
for supporting the development since the beginning. Also, thanks to all the
great contributors who have since made this project more mature.

## License

lychee is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/lycheeverse/lychee/blob/master/LICENSE-APACHE) or
  https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/lycheeverse/lychee/blob/master/LICENSE-MIT) or https://opensource.org/license/MIT)

at your option.

<br><hr>
[🔼 Back to top](#back-to-top)
