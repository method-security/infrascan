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

## Architecture

### Wireless Scanning Modes

The `discover waps` command supports two scanning modes:

**Active Mode (default):** Uses platform-specific system utilities (`airport` on macOS, `iw`/`iwlist` on Linux, `netsh wlan` on Windows) to enumerate nearby networks. These tools emit probe requests, making the scanning device detectable to nearby wireless intrusion detection systems. This mode works out of the box without special privileges on most systems.

**Passive Mode (`--passive`):** Intended for true zero-RF-emission scanning where the device only listens for beacon frames without transmitting. This mode requires:
- A wireless interface configured in monitor mode
- Elevated privileges (root on Linux/macOS, Administrator on Windows)
- Platform-specific packet capture capabilities

When passive mode is requested but requirements are not met, the command fails with a descriptive error explaining what's needed for the current platform.

| Platform | Active Mode Tool | Passive Mode Requirements |
|----------|-----------------|---------------------------|
| Linux    | `iw dev <iface> scan` | Monitor mode interface (e.g., `wlan0mon`), root privileges, libpcap |
| macOS    | `airport -s` | Root privileges, CoreWLAN with hardware support (limited availability) |
| Windows  | `netsh wlan show networks` | Npcap with monitor mode, compatible wireless adapter |

### Platform-Specific Build Tags

The wireless access point discovery (`discover waps`) uses platform-specific system utilities to enumerate nearby networks. Because these tools and their output formats differ significantly between operating systems, the scanning logic is split into separate files using Go build tags (e.g., `//go:build darwin`). This ensures that only the relevant platform code is compiled into the final binary, keeping the executable lean and avoiding any cross-platform import issues.

The main orchestration code in `waps.go` references all platform-specific scan functions (`scanDarwin`, `scanLinux`, `scanWindows`) in a runtime switch statement. Since Go's compiler requires all referenced functions to be defined at compile time—even if they're unreachable at runtime—we provide stub implementations for the non-target platforms. For example, when compiling on macOS, the `scanLinux` and `scanWindows` stubs return an error indicating they're unavailable. This pattern allows the codebase to compile cleanly on any platform while ensuring users get a clear error message if they somehow invoke the wrong code path.

The same pattern applies to privilege checking functions (`isUnixRoot`, `isWindowsAdmin`) which are implemented differently per platform to check for the elevated privileges required by passive mode.

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