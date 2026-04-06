# lan-scanner

A multi threaded network discovery and port scanning tool for local area networks. Combines multiple discovery protocols view devices on your network.

## Features

- **ARP scanning** — sweeps the local subnet to discover all active hosts
- **mDNS discovery** — finds services advertised via Multicast DNS (Bonjour/Zeroconf)
- **SSDP discovery** — detects UPnP devices (IoT, media servers, etc.)
- **TCP port scanning** — SYN scans specified ports on discovered devices using a thread pool
- **OUI lookup** — resolves MAC addresses to manufacturer names
- **Service identification** — maps open ports to known service names

## Dependencies

- `libpcap`
- `libnet`
- `gcc`
- `python3` (for generating OUI/port databases during build)

## Build & Run

```bash
# Release build (downloads OUI + port databases automatically)
make release

# Debug build
make debug

# Run (requires root for raw sockets)
sudo ./build/lanscan.out --full
```

## Usage

```
sudo lanscan [OPTIONS]
  --arp              ARP host discovery
  --mdns             mDNS service discovery
  --ssdp             SSDP/UPnP discovery
  --tcp -p PORT,...  TCP port scan (e.g. -p 22,80,443)
  --full             Run all protocols
  -h, --help         Show help
```

## How It Works

The scanner runs each protocol in its own thread, using libpcap for packet capture and libnet for packet injection. Discovered devices are stored in a thread safe hash table keyed by MAC address. TCP port scanning uses a thread pool to parallelize connection attempts across all discovered hosts.
