# Basic Usage

## Binaries

Running as a binary allows you to skip dealing with any container related networking issues and leverage the same network interface that the host machine is using.

```bash
infrascan discover waps
```

## Docker

Running infrascan within a Docker container should typically work similarly to running directly on a host, however, you may encounter some issues related to access to network interfaces.
