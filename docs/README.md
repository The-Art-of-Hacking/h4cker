<a name="back-to-top"></a>
![lychee](assets/logo.svg)

[![Homepage](https://img.shields.io/badge/Homepage-Online-EA3A97)](https://lycheeverse.github.io)
[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-lychee-blue.svg?colorA=24292e&colorB=0366d6&style=flat&longCache=true&logo=data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAM6wAADOsB5dZE0gAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAERSURBVCiRhZG/SsMxFEZPfsVJ61jbxaF0cRQRcRJ9hlYn30IHN/+9iquDCOIsblIrOjqKgy5aKoJQj4O3EEtbPwhJbr6Te28CmdSKeqzeqr0YbfVIrTBKakvtOl5dtTkK+v4HfA9PEyBFCY9AGVgCBLaBp1jPAyfAJ/AAdIEG0dNAiyP7+K1qIfMdonZic6+WJoBJvQlvuwDqcXadUuqPA1NKAlexbRTAIMvMOCjTbMwl1LtI/6KWJ5Q6rT6Ht1MA58AX8Apcqqt5r2qhrgAXQC3CZ6i1+KMd9TRu3MvA3aH/fFPnBodb6oe6HM8+lYHrGdRXW8M9bMZtPXUji69lmf5Cmamq7quNLFZXD9Rq7v0Bpc1o/tp0fisAAAAASUVORK5CYII=)](https://github.com/marketplace/actions/lychee-broken-link-checker)
[![Rust](https://github.com/hello-rust/lychee/workflows/CI/badge.svg)](https://github.com/lycheeverse/lychee/actions/workflows/ci.yml)
[![docs.rs](https://docs.rs/lychee-lib/badge.svg)](https://docs.rs/lychee-lib)
[![Check Links](https://github.com/lycheeverse/lychee/actions/workflows/links.yml/badge.svg)](https://github.com/lycheeverse/lychee/actions/workflows/links.yml)
[![Docker Pulls](https://img.shields.io/docker/pulls/lycheeverse/lychee?color=%23099cec&logo=Docker)](https://hub.docker.com/r/lycheeverse/lychee)

⚡ A fast, async, stream-based link checker written in Rust.\
Finds broken hyperlinks and mail addresses inside Markdown, HTML,
reStructuredText, or any other text file or website!

Available as a command-line utility, a library and a [GitHub Action](https://github.com/lycheeverse/lychee-action).

![Lychee demo](./assets/screencast.svg)

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->
## Table of Contents

- [Development](#development)
- [Installation](#installation)
- [Features](#features)
- [Commandline usage](#commandline-usage)
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

After [installing Rust](https://www.rust-lang.org/tools/install) use [Cargo](https://doc.rust-lang.org/cargo/) for building and testing.
On Linux the OpenSSL package [is required](https://github.com/seanmonstar/reqwest?tab=readme-ov-file#requirements) to compile `reqwest`, a dependency of lychee.
For Nix we provide a flake so you can use `nix develop` and `nix build`.

## Installation

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

### NixOS

```sh
nix-env -iA nixos.lychee
```

### Nixpkgs

- [`lychee` package](https://search.nixos.org/packages?show=lychee&query=lychee) for configurations, Nix shells, etc.

- Let Nix check a packaged site with \
  [`testers.lycheeLinkCheck`](https://nixos.org/manual/nixpkgs/stable/#tester-lycheeLinkCheck) `{ site = …; }`

### FreeBSD

```sh
pkg install lychee
```

### Scoop

```sh
scoop install lychee
```

### Termux

```sh
pkg install lychee
```

### Alpine Linux

```sh
 # available for Alpine Edge in testing repositories
apk add lychee
```

### WinGet (Windows)

```sh
winget install --id lycheeverse.lychee
```

### Chocolatey (Windows)

```sh
choco install lychee
```

### Conda

```sh
conda install lychee -c conda-forge
```

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

Lychee supports several feature flags:

- `native-tls` enables the platform-native TLS crate [native-tls](https://crates.io/crates/native-tls).
- `vendored-openssl` compiles and statically links a copy of OpenSSL. See the corresponding feature of the [openssl](https://crates.io/crates/openssl) crate.
- `rustls-tls` enables the alternative TLS crate [rustls](https://crates.io/crates/rustls).
- `email-check` enables checking email addresses using the [check-if-email-exists](https://crates.io/crates/check-if-email-exists) crate. This feature requires the `native-tls` feature.
- `check_example_domains` allows checking example domains such as `example.com`. This feature is useful for testing.

By default, `native-tls` and `email-check` are enabled.

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
| Include patterns     | ![yes]️ | ![yes]        | ![no]    | ![yes]                | ![no]        | ![no]                | ![no]                 | ![no]  |
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

Recursively check all links in supported files inside the current directory

```sh
lychee .
```

You can also specify various types of inputs:

```sh
# check links in specific local file(s):
lychee README.md
lychee test.html info.txt

# check links on a website:
lychee https://endler.dev

# check links in directory but block network requests
lychee --offline path/to/directory

# check links in a remote file:
lychee https://raw.githubusercontent.com/lycheeverse/lychee/master/README.md

# check links in local files via shell glob:
lychee ~/projects/*/README.md

# check links in local files (lychee supports advanced globbing and ~ expansion):
lychee "~/projects/big_project/**/README.*"

# ignore case when globbing and check result for each link:
lychee --glob-ignore-case "~/projects/**/[r]eadme.*"

# check links from epub file (requires atool: https://www.nongnu.org/atool)
acat -F zip {file.epub} "*.xhtml" "*.html" | lychee -
```

lychee parses other file formats as plaintext and extracts links using [linkify](https://github.com/robinst/linkify).
This generally works well if there are no format or encoding specifics,
but in case you need dedicated support for a new file format, please consider creating an issue.

### Docker Usage

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

There is an extensive list of command line parameters to customize the behavior.
See below for a full list.

```help-message
lychee is a fast, asynchronous link checker which detects broken URLs and mail addresses in local files and websites. It supports Markdown and HTML and works well with many plain text file formats.

lychee is powered by lychee-lib, the Rust library for link checking.

Usage: lychee [OPTIONS] [inputs]...

Arguments:
  [inputs]...
          Inputs for link checking (where to get links to check from). These can be:
          files (e.g. `README.md`), file globs (e.g. `'~/git/*/README.md'`), remote URLs
          (e.g. `https://example.com/README.md`), or standard input (`-`). Alternatively,
          use `--files-from` to read inputs from a file.

          NOTE: Use `--` to separate inputs from options that allow multiple arguments.

Options:
  -a, --accept <ACCEPT>
          A List of accepted status codes for valid links

          The following accept range syntax is supported: [start]..[[=]end]|code. Some valid
          examples are:

          - 200 (accepts the 200 status code only)
          - ..204 (accepts any status code < 204)
          - ..=204 (accepts any status code <= 204)
          - 200..=204 (accepts any status code from 200 to 204 inclusive)
          - 200..205 (accepts any status code from 200 to 205 excluding 205, same as 200..=204)

          Use "lychee --accept '200..=204, 429, 500' <inputs>..." to provide a comma-
          separated list of accepted status codes. This example will accept 200, 201,
          202, 203, 204, 429, and 500 as valid status codes.

          [default: 100..=103,200..=299]

      --archive <ARCHIVE>
          Specify the use of a specific web archive. Can be used in combination with `--suggest`

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

  -c, --config <CONFIG_FILE>
          Configuration file to use

          [default: lychee.toml]

      --cache
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
          Tell lychee to read cookies from the given file. Cookies will be stored in the
          cookie jar and sent with requests. New cookies will be stored in the cookie jar
          and existing cookies will be updated.

      --default-extension <EXTENSION>
          This is the default file extension that is applied to files without an extension.

          This is useful for files without extensions or with unknown extensions. The extension will be used to determine the file type for processing. Examples: --default-extension md, --default-extension html

      --dump
          Don't perform any link checking. Instead, dump all the links extracted from inputs that would be checked

      --dump-inputs
          Don't perform any link extraction and checking. Instead, dump all input sources from which links would be collected

  -E, --exclude-all-private
          Exclude all private IPs from checking.
          Equivalent to `--exclude-private --exclude-link-local --exclude-loopback`

      --exclude <EXCLUDE>
          Exclude URLs and mail addresses from checking. The values are treated as regular expressions

      --exclude-file <EXCLUDE_FILE>
          Deprecated; use `--exclude-path` instead

      --exclude-link-local
          Exclude link-local IP address range from checking

      --exclude-loopback
          Exclude loopback IP address range and localhost from checking

      --exclude-path <EXCLUDE_PATH>
          Exclude paths from getting checked. The values are treated as regular expressions

      --exclude-private
          Exclude private IP address ranges from checking

      --extensions <EXTENSIONS>
          Test the specified file extensions for URIs when checking files locally.

          Multiple extensions can be separated by commas. Note that if you want to check filetypes,
          which have multiple extensions, e.g. HTML files with both .html and .htm extensions, you need to
          specify both extensions explicitly.

          [default: md,mkd,mdx,mdown,mdwn,mkdn,mkdown,markdown,html,htm,txt]

  -f, --format <FORMAT>
          Output format of final status report

          [default: compact]
          [possible values: compact, detailed, json, markdown, raw]

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

          [possible values: man]

      --github-token <GITHUB_TOKEN>
          GitHub API token to use when checking github.com links, to avoid rate limiting

          [env: GITHUB_TOKEN]

      --glob-ignore-case
          Ignore case when expanding filesystem path glob inputs

  -h, --help
          Print help (see a summary with '-h')

  -H, --header <HEADER:VALUE>
          Set custom header for requests

          Some websites require custom headers to be passed in order to return valid responses.
          You can specify custom headers in the format 'Name: Value'. For example, 'Accept: text/html'.
          This is the same format that other tools like curl or wget use.
          Multiple headers can be specified by using the flag multiple times.

      --hidden
          Do not skip hidden directories and files

  -i, --insecure
          Proceed for server connections considered insecure (invalid TLS)

      --include <INCLUDE>
          URLs to check (supports regex). Has preference over all excludes

      --include-fragments
          Enable the checking of fragments in links

      --include-mail
          Also check email addresses

      --include-verbatim
          Find links in verbatim sections like `pre`- and `code` blocks

      --include-wikilinks
          Check WikiLinks in Markdown files

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

          [default: 5]

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

  -n, --no-progress
          Do not show progress bar.
          This is recommended for non-interactive shells (e.g. for continuous integration)

      --no-ignore
          Do not skip files that would otherwise be ignored by '.gitignore', '.ignore', or the global ignore file

  -o, --output <OUTPUT>
          Output file of status report

      --offline
          Only check local files and block network requests

  -p, --preprocess <COMMAND>
          Preprocess input files.
          For each file input, this flag causes lychee to execute `COMMAND PATH` and process
          its standard output instead of the original contents of PATH. This allows you to
          convert files that would otherwise not be understood by lychee. The preprocessor
          COMMAND is only run on input files, not on standard input or URLs.

          To invoke programs with custom arguments or to use multiple preprocessors, use a
          wrapper program such as a shell script. An example script looks like this:

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

  -q, --quiet...
          Less output per occurrence (e.g. `-q` or `-qq`)

  -r, --retry-wait-time <RETRY_WAIT_TIME>
          Minimum wait time in seconds between retries of failed requests

          [default: 1]

      --remap <REMAP>
          Remap URI matching pattern to different URI

      --require-https
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
          Only test links with the given schemes (e.g. https). Omit to check links with
          any other scheme. At the moment, we support http, https, file, and mailto.

      --skip-missing
          Skip missing input files (default is to error if they don't exist)

      --suggest
          Suggest link replacements for broken links, using a web archive. The web archive can be specified with `--archive`

  -t, --timeout <TIMEOUT>
          Website timeout in seconds from connect to response finished

          [default: 20]

  -T, --threads <THREADS>
          Number of threads to utilize. Defaults to number of cores available to the system

  -u, --user-agent <USER_AGENT>
          User agent

          [default: lychee/0.20.1]

  -v, --verbose...
          Set verbosity level; more output per occurrence (e.g. `-v` or `-vv`)

  -V, --version
          Print version

  -X, --method <METHOD>
          Request method

          [default: get]
```

### Exit codes

0   Success. The operation was completed successfully as instructed.

1   Missing inputs or any unexpected runtime failures or configuration errors

2   Link check failures. At least one non-excluded link failed the check.

3   Encountered errors in the config file.

### Ignoring links

You can exclude links from getting checked by specifying regex patterns
with `--exclude` (e.g. `--exclude example\.(com|org)`).

Here are some examples:

```bash
# Exclude LinkedIn URLs (note that we match on the full URL, including the schema to avoid false-positives)
lychee --exclude '^https://www\.linkedin\.com'

# Exclude LinkedIn and Archive.org URLs
lychee --exclude '^https://www\.linkedin\.com' --exclude '^https://web\.archive\.org/web/'

# Exclude all links to PDF files
lychee --exclude '\.pdf$' .

# Exclude links to specific domains
lychee --exclude '(facebook|twitter|linkedin)\.com' .

# Exclude links with certain URL parameters
lychee --exclude '\?utm_source=' .

# Exclude all mailto links
lychee --exclude '^mailto:' .
```

For excluding files/directories from being scanned use `lychee.toml`
and `exclude_path`.

```toml
exclude_path = ["some/path", "*/dev/*"]
```

If a file named `.lycheeignore` exists in the current working directory, its
contents are excluded as well. The file allows you to list multiple regular
expressions for exclusion (one pattern per line).

For more advanced usage and detailed explanations, check out our comprehensive [guide on excluding links](https://lychee.cli.rs/recipes/excluding-links/).

### Caching

If the `--cache` flag is set, lychee will cache responses in a file called
`.lycheecache` in the current directory. If the file exists and the flag is set,
then the cache will be loaded on startup. This can greatly speed up future runs.
Note that by default lychee will not store any data on disk.

## Library usage

You can use lychee as a library for your own projects!
Here is a "hello world" example:

```rust
use lychee_lib::Result;

#[tokio::main]
async fn main() -> Result<()> {
  let response = lychee_lib::check("https://github.com/lycheeverse/lychee").await?;
  println!("{response}");
  Ok(())
}
```

This is equivalent to the following snippet, in which we build our own client:

```rust
use lychee_lib::{ClientBuilder, Result, Status};

#[tokio::main]
async fn main() -> Result<()> {
  let client = ClientBuilder::default().client()?;
  let response = client.check("https://github.com/lycheeverse/lychee").await?;
  assert!(response.status().is_success());
  Ok(())
}
```

The client builder is very customizable:

```rust, ignore
let client = lychee_lib::ClientBuilder::builder()
    .includes(includes)
    .excludes(excludes)
    .max_redirects(cfg.max_redirects)
    .user_agent(cfg.user_agent)
    .allow_insecure(cfg.insecure)
    .custom_headers(headers)
    .method(method)
    .timeout(timeout)
    .github_token(cfg.github_token)
    .scheme(cfg.scheme)
    .accepted(accepted)
    .build()
    .client()?;
```

All options that you set will be used for all link checks.
See the [builder documentation](https://docs.rs/lychee-lib/latest/lychee_lib/struct.ClientBuilder.html)
for all options. For more information, check out the [examples](examples)
directory. The examples can be run with `cargo run --example <example>`.

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

Here is a list of some notable projects who are using lychee.

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
- https://github.com/forus-labs/forui
- https://github.com/FreeBSD-Ask/FreeBSD-Ask
- https://github.com/prosekit/prosekit
- https://github.com/lycheeverse/lychee (yes, lychee is checked with lychee 🤯)

If you are using lychee for your project, **please add it here**.

## Credits

The first prototype of lychee was built in [episode 10 of Hello
Rust](https://hello-rust.github.io/10/). Thanks to all GitHub and Patreon sponsors
for supporting the development since the beginning. Also, thanks to all the
great contributors who have since made this project more mature.

## License

lychee is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](https://github.com/lycheeverse/lychee/blob/master/LICENSE-APACHE) or
  https://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](https://github.com/lycheeverse/lychee/blob/master/LICENSE-MIT) or https://opensource.org/licenses/MIT)

at your option.

<br><hr>
[🔼 Back to top](#back-to-top)
