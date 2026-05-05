# Discover

This command performs 802.11 reconnaissance to discover nearby wireless
access points. It extracts information from beacon frames including:

  - Identity: BSSID, SSID (including hidden network detection)
  - Radio: Channel, frequency band, signal strength, channel width
  - Security: Authentication method, encryption, WPA version, PMF policy
  - Capabilities: WiFi generation (4/5/6/7), MIMO support
  - Vendor: OUI-based manufacturer identification

## Usage

```bash
infrascan discover [command]
```

## Available Commands

- **waps**: Discover nearby wireless access points

## Commands

### WAPs

The `discover waps` command supports two scanning modes:

**Active Mode (default):** Uses platform-specific system utilities (`airport` on macOS, `iw`/`iwlist/nmcli` on Linux, `netsh wlan` on Windows) to enumerate nearby networks. These tools emit probe requests, making the scanning device detectable to nearby wireless intrusion detection systems. This mode works out of the box without special privileges on most systems. IMPORTANT: THIS PERFORMS A SINGLE POINT IN TIME SCAN.

**Passive Mode (`--passive`):** Intended for true zero-RF-emission scanning where the device only listens for beacon frames without transmitting. This mode requires:
- A wireless interface configured in monitor mode
- Elevated privileges (root on Linux/macOS, Administrator on Windows)
- Platform-specific packet capture capabilities

When passive mode is requested but requirements are not met, the command fails with a descriptive error explaining what's needed for the current platform.

Different platforms have different active and passive requirements and limitation:

| Platform | Active Mode Tool | Passive Mode Requirements |
|----------|-----------------|---------------------------|
| Linux    | Runs through a prioritized list of scanning techniques: (if root) iw → nmcli → iwlist, (if not root) nmcli → iw → iwlist | Monitor mode interface (e.g., `wlan0mon`), root privileges, libpcap; Current limitation: not fully tested |
| macOS    | `airport -s` Current limitation: without proper app packaging and signing it cannot see clear text SSID and BSSID values due to how System Privacy on the APIs is controlled  | Not possible |
| Windows  | `netsh wlan show networks` Current limitation: not fully tested | Npcap with monitor mode, compatible wireless adapter; Current limitation: not fully tested |

### Preparing a Linux network interface for passive scanning

```bash
# Stop NetworkManager
sudo systemctl stop NetworkManager

# Configure monitor mode with TX disabled
sudo ip link set wlo1 down
sudo iw dev wlo1 set type monitor
sudo iw dev wlo1 set monitor none    # Key: disables TX
sudo ip link set wlo1 up

# Disable power save
sudo iw dev wlo1 set power_save off
```

#### Usage

```bash
# Scan using default interface (active mode, emits RF)
infrascan discover waps

# Scan with specific interface
infrascan discover waps --interface en0

# Scan for specific SSID
infrascan discover waps --target-ssid "CorpWiFi"

# Passive mode - zero RF emissions (requires monitor mode)
infrascan discover waps --passive --interface wlan0mon

# Scan with custom timeout
infrascan discover waps --timeout 60`
```

#### Help Text

```bash
Discover and enumerate wireless access points in the environment.

This command performs 802.11 reconnaissance to discover nearby wireless
access points. It extracts information from beacon frames including:

  - Identity: BSSID, SSID (including hidden network detection)
  - Radio: Channel, frequency band, signal strength, channel width
  - Security: Authentication method, encryption, WPA version, PMF policy
  - Capabilities: WiFi generation (4/5/6/7), MIMO support
  - Vendor: OUI-based manufacturer identification

Usage:
  infrascan discover waps [flags]

Flags:
  -h, --help                 help for waps
      --interface string     Network interface to use for scanning (auto-detected if not specified)
      --passive              Enable passive mode (zero RF emissions, requires monitor mode and elevated privileges)
      --target-ssid string   Target SSID to discover (optional, filters results)
      --timeout int          Timeout in seconds for the discovery scan (default 30)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```
