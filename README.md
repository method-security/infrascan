<div align="center">
<h1>infrascan</h1>

[![GitHub Release][release-img]][release]
[![Verify][verify-img]][verify]
[![Go Report Card][go-report-img]][go-report]
[![License: Apache-2.0][license-img]][license]
[![Acceptable Use Policy][acceptable-use-policy-img]][acceptable-use-policy]

[![GitHub Downloads][github-downloads-img]][release]
[![Docker Pulls][docker-pulls-img]][docker-pull]

</div>

infrascan is an Infrastructure and Wireless signal scanning and enumeration tool that provides security teams with data-rich insights into infrastructure resources and targets. Designed with data-modeling and data-integration needs in mind, infrascan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The types of scans that infrascan can conduct are constantly growing. For the most up to date listing, please see the documentation [here](https://method-security.github.io/infrascan/docs/index.html)

To learn more about infrascan, please see the [Documentation site](https://method-security.github.io/infrascan/) for the most detailed information.

## Quick Start

### Get infrascan

For the full list of available installation options, please see the [Installation](./docs/getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/infrascan`
- `docker run ghcr.io/method-security/infrascan`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/infrascan/releases/latest) page
- [Installation documentation](./docs/getting-started/installation.md)

#### Examples

TODO
```bash
```

### Developer Setup

`infrascan` uses [Fern](https://buildwithfern.com/learn/sdks/overview/introduction) for creating multi-language bindings. This is used for structuring input and output amongst tools.

1. Install Fern: https://buildwithfern.com/learn/sdks/overview/quickstart

2. Generate your fern types with:

```bash
fern generate --group local
```

3. Ensure dependencies are installed and tested with:

```bash
./godelw verify
```

### Building a Statically Compiled Container for Local Testing
(Reference reusable-build.yaml)

1. Build ARM64 builder image: `docker buildx build . --platform linux/arm64 --load --tag armbuilder -f Dockerfile.builder`

2. Build ARM64 image: `docker run -v .:/app/infrascan -e GOARCH=arm64 -e GOOS=linux --rm armbuilder goreleaser build --single-target -f .goreleaser/goreleaser-build.yml --snapshot --clean`

3. `cp dist/linux_arm64/build-linux_linux_arm64/infrascan .`

4. `docker buildx build . --platform linux/arm64 --load --tag infrascan:local -f Dockerfile`

5. Open shell: `docker run -it --rm --entrypoint /bin/bash infrascan:local`

6. OR run command without shell example: `docker run infrascan:local discover dns certs --domain example.com -o json`

### Setting up Cursor / VSCode to properly lint Go files

Because there is CGO used in this project, it can be tricky to get the linters to fully recognize some of the C based dependencies. This sets up Cursor to inherit your shell init (e.g. `.zshrc`).

To ensure linting is working:
1. Setup Cursor shell command from inside Cursor (or Code):
- Open Command Palette
- Search for `Shell Command: Install (cursor) shell command` and run it
- Close cursor
2. Run Cursor from a terminal in this target repo folder with `cursor .`
3. Fix your user settings to point to your proper go executable
- take note of `which go`
- Open user settings with Command Palette -> Preferences: Open User Settings (JSON)
- Add:
```
"go.alternateTools": {
    "go": <your go path here>
}
```
4. Restart the Go Language Server

## Contributing

Interested in contributing to infrascan? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie infrascan into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

infrascan is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).

[verify]: https://github.com/Method-Security/infrascan/actions/workflows/verify.yml
[verify-img]: https://github.com/Method-Security/infrascan/actions/workflows/verify.yml/badge.svg
[go-report]: https://goreportcard.com/report/github.com/Method-Security/infrascan
[go-report-img]: https://goreportcard.com/badge/github.com/Method-Security/infrascan
[release]: https://github.com/Method-Security/infrascan/releases
[releases]: https://github.com/Method-Security/infrascan/releases/latest
[release-img]: https://img.shields.io/github/release/Method-Security/infrascan.svg?logo=github
[github-downloads-img]: https://img.shields.io/github/downloads/Method-Security/infrascan/total?logo=github
[docker-pulls-img]: https://img.shields.io/docker/pulls/methodsecurity/infrascan?logo=docker&label=docker%20pulls%20%2F%20infrascan
[docker-pull]: https://hub.docker.com/r/methodsecurity/infrascan
[license]: https://github.com/Method-Security/infrascan/blob/main/LICENSE
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[acceptable-use-policy]: https://github.com/Method-Security/infrascan/blob/main/ACCEPTABLE_USE_POLICY.md
[acceptable-use-policy-img]: https://img.shields.io/badge/acceptable_use_policy