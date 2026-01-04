# Capabilities

infrascan offers a variety of techniques that allow security teams to discover, enumerate, and connect to infrastructure (WiFi, Bluetooth, NFC, IoT) targets. Each of the below pages offers you an in depth look at a infrascan capability related to a unique technique.

## Top Level Commands

infrascan organizes functionality under three primary command groups and their modules:

### discover

- **WAPs** – Wireless Access Point discovery and enumeration
  - `infrascan discover waps` – Discover nearby wireless access points via 802.11 reconnaissance

### connect

- **WAP** – Wireless Access Point connection and authentication testing
  - `infrascan connect wap` – Test wireless access point security through controlled connection attempts

## Top Level Flags

infrascan has several top level flags that can be used on any subcommand. These include:

```bash
Flags:
  -h, --help                 help for infrascan
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```

## Version Command

Run `infrascan version` to get the exact version information for your binary

## Output Formats

For more information on the various output formats that are supported by infrascan, see the [Output Formats](https://method-security.github.io/docs/output.html) page in our organization wide documentation.
