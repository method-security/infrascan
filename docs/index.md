# infrascan Documentation

Hello and welcome to the infrascan documentation. While we always want to provide the most comprehensive documentation possible, we thought you may find the below sections a helpful place to get started.

- The [Getting Started](./getting-started/basic-usage.md) section provides onboarding material
- The [Development](./development/setup.md) header is the best place to get started on developing on top of and with infrascan
- See the [Docs](./docs/index.md) section for a comprehensive rundown of infrascan capabilities

# About infrascan

infrascan has been designed to provide security teams with an easy-to-use yet data-rich suite of open source intelligence (OSINT) capabilities to help them better understand the internet exposure of the networks they defend. Designed with data-modeling and data-integration needs in mind, infrascan can be used on its own as an interactive CLI, orchestrated as part of a broader data pipeline, or leveraged from within the Method Platform.

The types of scans that infrascan can conduct are constantly growing. For the most up to date listing, please see the documentation [here](./docs/index.md)

To learn more about infrascan, please see the [Documentation site](https://method-security.github.io/infrascan/) for the most detailed information.

## Quick Start

### Get infrascan

For the full list of available installation options, please see the [Installation](./getting-started/installation.md) page. For convenience, here are some of the most commonly used options:

- `docker run methodsecurity/infrascan`
- `docker run ghcr.io/method-security/infrascan`
- Download the latest binary from the [Github Releases](https://github.com/Method-Security/infrascan/releases/latest) page
- [Installation documentation](./getting-started/installation.md)

#### Examples

```bash
infrascan discover dns records --domain example.com
```

```bash
infrascan discover dns certs --domain example.com
```

## Contributing

Interested in contributing to infrascan? Please see our organization wide [Contribution](https://method-security.github.io/community/contribute/discussions.html) page.

## Want More?

If you're looking for an easy way to tie infrascan into your broader cybersecurity workflows, or want to leverage some autonomy to improve your overall security posture, you'll love the broader Method Platform.

For more information, visit us [here](https://method.security)

## Community

infrascan is a Method Security open source project.

Learn more about Method's open source source work by checking out our other projects [here](https://github.com/Method-Security) or our organization wide documentation [here](https://method-security.github.io).

Have an idea for a Tool to contribute? Open a Discussion [here](https://github.com/Method-Security/Method-Security.github.io/discussions).
