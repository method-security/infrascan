# Basic Usage

## Binaries

Running as a binary allows you to skip dealing with any container related networking issues and leverage the same network interface that the host machine is using.

```bash
# Scan using default interface (active mode, emits RF)
infrascan discover waps

# Test the behavior of a WPA2 PSK protected WiFi network
infrascan connect wap --target-ssid testssid --test-psk testssidpsk --test-only
```

## Docker

Running infrascan within a Docker container should typically work similarly to running directly on a host, however, you may encounter some issues related to access to network interfaces.
