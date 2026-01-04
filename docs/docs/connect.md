# Infrastructure Connection

## Wireless Access Point Connection

Test wireless access point security by attempting a full connection with authentication. This tool is useful for first directly interacting with a wireless access point to ensure it behaves as expected (correct authentication, network type, etc.). It does not have to be used to test valid credentials. However, if valid credentials are obtained or owned, it can secondarily be used to test the validity of those credentials and connect to a target network.

This command performs a complete 802.11 connection test including:
  - Layer 2 association with the access point
  - Full 4-way handshake (for WPA/WPA2/WPA3 networks)
  - Credential validation (PSK or EAP)
  - DHCP acquisition and captive portal detection
  - Optional platform connectivity verification

The tool will:
  - Save your current WiFi connection (if any)
  - Attempt to connect using the provided credentials
  - Perform the complete authentication handshake
  - Record the negotiated security properties
  - Detect captive portals and authentication requirements
  - Optionally test HTTP connectivity to a platform URL
  - (Depending on flags set) Return to original WiFi (if there was one) or 
    stay connected to target network on success

This tool attempts to leverage various platform specific network utilities to manipulate WiFi connectivity as summarized in the next several Linux/Windows/Darwin sections.

### Linux Utilized Network Utilities

#### Connection Utilities (tried in order based on conditions)

| Utility | When Used | Purpose | Root Required |
|---------|-----------|---------|---------------|
| `nmcli` (NetworkManager) | Open networks, PSK when popups allowed, EAP networks | Creates temporary connection profile, activates it | No |
| `wpa_supplicant` + `nmcli` | PSK networks in desktop session when `--allow-desktop-popups=false` | Bypasses NetworkManager to avoid password prompt dialogs on auth failure. Temporarily marks interface unmanaged. | Yes |
| `wpa_supplicant` standalone | Fallback when `nmcli` unavailable | Direct 802.11 authentication without NetworkManager | Yes |

#### DHCP Clients (tried in order until one succeeds)

| Utility | Common On | Flags Used |
|---------|-----------|------------|
| `dhcpcd` | Arch, Gentoo, some Ubuntu | `-4` (IPv4), `-1` (oneshot), `-w` (wait for carrier), `-t 60` (timeout) |
| `dhclient` | Debian, Ubuntu | `-v` (verbose), `-1` (try once) |
| `udhcpc` | BusyBox/embedded systems | `-i` (interface), `-n` (exit if no lease), `-q` (quit after lease) |

#### DNS Configuration (for systemd-resolved systems)

| Utility | Purpose |
|---------|---------|
| `resolvectl dns` | Configures DNS servers for the interface when DHCP doesn't auto-configure systemd-resolved |
| `resolvectl domain` | Sets interface as default DNS route (`~.`) |

#### Supporting Utilities

| Utility | Purpose |
|---------|---------|
| `iw` | Detect wireless interfaces, check link state, force disconnect |
| `iwconfig` | Fallback interface detection when `iw` unavailable |
| `ip` | Get/set interface state, check IP addresses, get gateway |
| `wpa_cli` | Monitor `wpa_supplicant` connection state and handshake progress |
| `pkill` | Terminate existing `wpa_supplicant` processes on interface |

#### Decision Flow

```
┌─────────────────────────────────────────┐
│           Credential Type?              │
└─────────────────────────────────────────┘
           │
    ┌──────┴──────┬──────────────┐
    ▼             ▼              ▼
  OPEN          PSK            EAP
    │             │              │
    ▼             ▼              ▼
  nmcli     Desktop Session?   nmcli
    │         │       │        (EAP)
    │        Yes      No
    │         │       │
    │         ▼       ▼
    │     Root?    nmcli
    │      │  │
    │     Yes No
    │      │  │
    │      ▼  ▼
    │  wpa_supplicant  Error:
    │  (no-NM path)   need sudo
    │
    └──────────────────────────────────────►  Connection
```

### Usage

```bash
# Test the behavior of a WPA2 PSK protected WiFi network
infrascan connect wap --target-ssid testssid --test-psk testssidpsk --test-only --output json

# Connect to a WPA2 PSK protected WiFi network with valid credentials and test connectivity back to a central platform
#
# Useful for ensuring there is internet (or equivalent) access on a target network
infrascan connect wap --target-ssid testssid --test-psk testssidpsk --test-only --test-platform-connectivity --platform-url https://platform.com --output json

# Connect to a WPA2 PSK protected WiFi network with valid credentials and remain connected to that target network
infrascan connect wap --target-ssid testssid --test-psk testssidpsk --test-only=false

# Connect to a WPA2 PSK protected WiFi network with valid credentials and remain connected to that target network
# only if there is central platform connectivity verified
#
# Useful for ensuring network switching only when connectivity to tool is not lost
infrascan connect wap --target-ssid testssid --test-psk testssidpsk --test-only --test-platform-connectivity --platform-url https://platform.com --return-to-original-wifi-if-no-platform-connectivity --output json

# Test the behavior of an open (no auth) WiFi network
infrascan connect wap --target-ssid testopenssid --test-only --output json
```

### Help Text

```bash
Test wireless access point security by attempting a full connection with authentication.

Test wireless access point security by attempting a full connection with authentication. This tool is useful
for first directly interacting with a wireless access point to ensure it behaves as expected (correct authentication,
network type, etc.). It does not have to be used to test valid credentials. However, if valid credentials are
obtained or owned, it can secondarily be used to test the validity of those credentials and connect to a target network.

Usage:
  infrascan connect wap [flags]

Flags:
      --allow-desktop-popups                                  Allow desktop/OS password prompts (NetworkManager secret agent) on authentication failures. By default, infrascan uses a non-NetworkManager path when running as root to avoid GUI prompts.
  -h, --help                                                  help for wap
      --interface string                                      Network interface to use (auto-detected if not specified)
      --platform-url string                                   URL to test for platform connectivity (e.g., https://api.example.com/health). Required when --test-platform-connectivity is set. Follows redirects, expects HTTP 200.
      --return-to-original-wifi-if-no-platform-connectivity   Only applies when --test-only=false. Use =true to disconnect from target and restore original WiFi when platform connectivity fails.
      --target-bssid string                                   Target BSSID to connect to (optional, for specific AP)
      --target-ssid string                                    Target SSID to connect to
      --test-eap-identity string                              EAP identity for WPA-Enterprise testing
      --test-eap-password string                              EAP password for WPA-Enterprise testing
      --test-only                                             Test connection and restore original WiFi when done. Use --test-only=false (with =) to stay connected on success. (default true)
      --test-platform-connectivity                            After successful connection, test HTTP connectivity to --platform-url
      --test-psk string                                       PSK/password to test for WPA-Personal networks
      --timeout int                                           Timeout in seconds for connection attempt (default 60)

Global Flags:
  -o, --output string        Output format (signal, json, yaml). Default value is signal (default "signal")
  -f, --output-file string   Path to output file. If blank, will output to STDOUT
  -q, --quiet                Suppress output
  -v, --verbose              Verbose output
```