# NetBuddy v1.3

**Passive Network Broadcast Listener**

NetBuddy is a passive network reconnaissance tool designed for penetration testers and security professionals. It silently captures and analyzes broadcast and multicast traffic to build a live picture of the network environment without sending a single packet. It is designed to run safely in the background alongside active scanning tools such as Nmap and Nessus without generating false positives.

```
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║              N E T B U D D Y   v 1 . 3               ║
  ║        Passive Network Broadcast Listener            ║
  ║              ms08067xp@gmail.com                     ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
```

---

## Features

- **Subnet Discovery** — builds a live map of IP subnets visible from the current network position based on observed traffic
- **VLAN Tag Detection** — detects 802.1Q tagged frames and identifies which VLAN IDs are present, indicating trunk port access or network segmentation visibility
- **Protocol Activity** — tracks and counts over 80 protocols across broadcast, management, database, remote access, industrial, container, and VPN categories
- **Notable Protocol Alerting** — highlights security-relevant protocols in real time including plaintext services, unauthenticated databases, industrial control protocols, and exposed management interfaces
- **Hostname Discovery** — passively extracts hostnames from mDNS, LLMNR, NBNS, and DHCP traffic without querying anything
- **ARP Table** — builds a MAC-to-IP mapping from observed ARP traffic, sorted by IP address
- **Scanner Noise Filtering** — automatically excludes all traffic involving the local machine's IP addresses in both source and destination directions, preventing Nmap and Nessus scan traffic from generating false positives
- **Live Refreshing Display** — terminal UI refreshes on a configurable interval showing all discovered data
- **File Output** — saves a full report on exit including all sections, protocol counts, and a timestamped event log

---

## Requirements

- Python 3.7+
- scapy
- Root / administrator privileges (required for raw packet capture)

```bash
pip3 install scapy
```

---

## Installation

```bash
git clone https://github.com/ms08067/netbuddy.git
cd netbuddy
pip3 install scapy
```

---

## Usage

```bash
# List available network interfaces
sudo python3 net_listener.py --list-interfaces

# Basic usage — listen on eth0
sudo python3 net_listener.py -i eth0

# Listen for 5 minutes and save results to file
sudo python3 net_listener.py -i eth0 -t 300 -o results.txt

# Exclude an additional scanner IP (e.g. dedicated Nessus appliance)
sudo python3 net_listener.py -i eth0 --scanner-ips 192.168.1.50

# Exclude multiple additional scanner IPs
sudo python3 net_listener.py -i eth0 --scanner-ips 192.168.1.50,192.168.1.51

# Faster display refresh
sudo python3 net_listener.py -i eth0 --refresh 3
```

---

## Options

| Flag | Description |
|------|-------------|
| `-i`, `--interface` | Network interface to listen on |
| `-t`, `--timeout` | Stop after N seconds (default: run until Ctrl+C) |
| `-o`, `--output` | Save results to file on exit |
| `--refresh` | Display refresh interval in seconds (default: 5) |
| `--scanner-ips` | Additional IPs to exclude, comma-separated |
| `--list-interfaces` | List available interfaces and exit |

---

## Controls

| Key | Action |
|-----|--------|
| `Ctrl+C` | Stop capture and save results |

---

## Protocol Coverage

NetBuddy tracks the following protocol categories. Protocols marked **Notable** are highlighted in red in the live display.

### Broadcast / Discovery
`mDNS` `LLMNR` `NBNS` `NBDS` `DHCP` `NTP` `SSDP` `WS-Discovery` `CAPWAP`

### Plaintext / Legacy *(Notable)*
`FTP` `Telnet` `TFTP` `Finger` `rexec` `rlogin` `RSH` `NNTP` `POP3` `IMAP` `SMTP`

### Remote Access
`SSH` `RDP` `VNC` `Radmin` `AnyDesk` `NETCONF-SSH`

### Web
`HTTP` *(Notable)* `HTTPS` `HTTP-Alt` `HTTPS-Alt`

### File Sharing *(Notable)*
`SMB` `NFS` `RPC-portmap` `AFP` `rsync` `FTP-Data`

### Databases *(Notable)*
`MSSQL` `MSSQL-Browser` `MySQL` `PostgreSQL` `Oracle-TNS` `MongoDB` `Redis` `CouchDB` `Elasticsearch` `Neo4j` `InfluxDB`

### Directory / Authentication
`LDAP` `LDAPS` `Kerberos` `MSRPC` *(Notable)*

### Network Management *(Notable)*
`DNS` `SNMP` `SNMP-Trap` `BGP` `RIP` `RIPng` `RADIUS` `NetFlow` `IPFIX`

### Monitoring / Middleware
`Grafana` `Kibana` `ActiveMQ` `AMQP` `RabbitMQ` `Kafka` `Zookeeper`

### VPN / Tunneling
`IKE-ISAKMP` `IKE-NAT-T` `L2TP` `OpenVPN` `WireGuard` `PPTP`

### Container / Cloud *(Notable)*
`Docker` `Docker-TLS` `Kubernetes` `Kubelet` `etcd` `Consul` `Erlang-EPMD` `Memcached`

### Industrial / ICS *(Notable)*
`Modbus` `DNP3` `EtherNet/IP` `S7-ISO-TSAP` `OMRON-FINS` `OPC-UA` `IEC-60870-5-104` `FF-HSE` `PROFINET` `BACnet` `Niagara-Fox`

---

## Scanner Noise Filtering

NetBuddy automatically detects all IP addresses assigned to the local machine at startup and excludes any packet where the local IP appears as either the source or destination. This means you can run Nmap, Nessus, or any other active scanning tool simultaneously without polluting the passive capture results.

```
Excluded IPs are shown at startup:

  [*] Excluded : 127.0.0.1, 192.168.9.25
```

To additionally exclude a dedicated scanner appliance with its own IP:

```bash
sudo python3 net_listener.py -i eth0 --scanner-ips 192.168.1.100
```

---

## Output File

When `-o` is specified, NetBuddy saves a structured plain text report on exit:

```
============================================================
  NetBuddy v1.3 -- Passive Network Broadcast Listener
  Generated : 2026-05-24 14:32:01
  Interface : eth0
  Packets   : 48291
  Filtered  : 12834
============================================================

DISCOVERED SUBNETS
----------------------------------------
  192.168.1.0/24         3421 packets
  192.168.4.0/24          891 packets
  172.19.1.0/24            12 packets

VLAN TAGS
----------------------------------------
  VLAN 10: 192.168.10.5, 192.168.10.12
  VLAN 20: 192.168.20.1

PROTOCOL COUNTS
----------------------------------------
  ARP                      8821
  mDNS                     4312
  LLMNR                    1204
  ...

NOTABLE DETECTIONS
----------------------------------------
  192.168.1.45:1024 -> 192.168.1.200:23 [Telnet]
  192.168.4.10:502 -> 192.168.4.255:502 [Modbus]
  ...
```

---

## Use Cases

- **Penetration testing** — run passively in the background while conducting active assessments to capture ambient network intelligence
- **Network segmentation validation** — confirm which subnets are reachable from a given network position
- **VLAN trunk detection** — identify if a port is configured as a trunk and which VLANs are visible
- **OT/ICS environment mapping** — detect industrial protocols present on the wire without sending any commands to devices
- **Hostname enumeration** — collect hostnames from passive mDNS, LLMNR, NBNS, and DHCP traffic without querying DNS
- **Protocol risk assessment** — identify plaintext or unauthenticated services active on the network

---

## Legal Disclaimer

NetBuddy is intended for use on networks and systems for which you have explicit written authorization. Unauthorized use against networks or systems you do not own or have permission to test is illegal and unethical. The author assumes no liability for misuse.

---

## Author

Scott Drew
[ms08067xp@gmail.com](mailto:ms08067xp@gmail.com)

---

## License

MIT License — see [LICENSE](LICENSE) for details.
