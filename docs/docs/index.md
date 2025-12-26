# Capabilities

infrascan offers a variety of techniques that allow security teams to leverage open source intelligence (OSINT) capabilities to better understand their internet facing exposure. Each of the below pages offers you an in depth look at a infrascan capability related to a unique technique.

## Top Level Commands

infrascan organizes functionality under three primary command groups and their modules:

### discover

- **ASN** – ASN information discovery using BGPView API
  - `infrascan discover asn` – Get detailed ASN information including CIDRs, country, and metadata
- **CDN** – CDN provider detection for IP addresses and domains
  - `infrascan discover cdn` – Check if domains/IPs belong to known CDN providers
- **DNS** – Comprehensive DNS intelligence gathering
  - `infrascan discover dns certs` – Retrieve SSL/TLS certificates for domains
  - `infrascan discover dns records` – Fetch DNS records (A, AAAA, MX, TXT, etc.)
  - `infrascan discover dns forward` – Perform forward DNS lookups
  - `infrascan discover dns reverse` – Perform reverse DNS lookups on IPs/CIDRs
  - `infrascan discover dns subdomain active` – Actively discover subdomains via brute-force
  - `infrascan discover dns subdomain correlation` – Correlate subdomains across domains
  - `infrascan discover dns subdomain passive` – Passively discover subdomains from external sources
- **IP** – IP address and network intelligence
  - `infrascan discover ip domain-asn` – Perform reverse DNS and ASN lookups
- **Shodan** – Query the Shodan search engine
  - `infrascan discover shodan hostname` – Search Shodan for specific hostnames

### enumerate

- **DNS** – Active DNS enumeration techniques
  - `infrascan enumerate dns zonetransfer` – Attempt AXFR zone transfers

### pentest

- **DNS** – DNS-focused penetration testing
  - `infrascan pentest dns takeover` – Detect subdomain takeover vulnerabilities

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
