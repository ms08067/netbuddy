#!/usr/bin/env python3
"""
NetBuddy v1.3 - Passive Network Broadcast & Protocol Listener
Author: Scott Drew <ms08067xp@gmail.com>

Passively captures broadcast and multicast traffic to discover subnets,
VLAN tags, protocol activity, hostnames, and notable services without
sending any packets. Traffic involving the local machine is automatically
filtered to prevent false positives when running alongside active tools
such as Nmap or Nessus.

Usage:
  sudo python3 net_listener.py -i eth0
  sudo python3 net_listener.py -i eth0 -t 300 -o results.txt
  sudo python3 net_listener.py -i eth0 --scanner-ips 192.168.1.50
  sudo python3 net_listener.py --list-interfaces

Controls:
  Ctrl+C  Stop capture and save results

Requirements:
  pip3 install scapy
"""

import argparse
import datetime
import ipaddress
import signal
import socket
import sys
import threading
import time
from collections import Counter, defaultdict

try:
    from scapy.all import (
        ARP, DHCP, DNS, Dot1Q, IP, IPv6,
        TCP, UDP, conf, get_if_addr, get_if_list, sniff
    )
    from scapy.layers.llmnr import LLMNRQuery
except ImportError:
    print("[-] scapy not found.  pip3 install scapy")
    sys.exit(1)

conf.verb = 0


def get_local_ips():
    local = {"127.0.0.1", "0.0.0.0"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            local.add(info[4][0])
    except Exception:
        pass
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0":
                local.add(ip)
        except Exception:
            pass
    return local


LOCAL_IPS = get_local_ips()


class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    GREY    = "\033[90m"
    TEAL    = "\033[36m"


PROTOCOL_PORTS = {
    5353:  "mDNS",
    5355:  "LLMNR",
    137:   "NBNS",
    138:   "NBDS",
    67:    "DHCP",
    68:    "DHCP",
    123:   "NTP",
    1900:  "SSDP",
    3702:  "WS-Discovery",
    5246:  "CAPWAP",
    5247:  "CAPWAP",
    21:    "FTP",
    20:    "FTP-Data",
    23:    "Telnet",
    69:    "TFTP",
    79:    "Finger",
    512:   "rexec",
    513:   "rlogin",
    514:   "RSH-Syslog",
    119:   "NNTP",
    143:   "IMAP",
    110:   "POP3",
    25:    "SMTP",
    587:   "SMTP-Submission",
    22:    "SSH",
    2222:  "SSH-Alt",
    3389:  "RDP",
    5900:  "VNC",
    5901:  "VNC",
    5902:  "VNC",
    5800:  "VNC-HTTP",
    4899:  "Radmin",
    7070:  "AnyDesk",
    830:   "NETCONF-SSH",
    80:    "HTTP",
    443:   "HTTPS",
    8080:  "HTTP-Alt",
    8443:  "HTTPS-Alt",
    8888:  "HTTP-Alt",
    8008:  "HTTP-Alt",
    9090:  "HTTP-Alt",
    139:   "SMB",
    445:   "SMB",
    2049:  "NFS",
    111:   "RPC-portmap",
    548:   "AFP",
    873:   "rsync",
    1433:  "MSSQL",
    1434:  "MSSQL-Browser",
    3306:  "MySQL",
    5432:  "PostgreSQL",
    1521:  "Oracle-TNS",
    27017: "MongoDB",
    6379:  "Redis",
    5984:  "CouchDB",
    9200:  "Elasticsearch",
    9300:  "Elasticsearch",
    7474:  "Neo4j",
    8086:  "InfluxDB",
    389:   "LDAP",
    636:   "LDAPS",
    88:    "Kerberos",
    464:   "Kerberos-Passwd",
    135:   "MSRPC",
    593:   "MSRPC-HTTP",
    53:    "DNS",
    161:   "SNMP",
    162:   "SNMP-Trap",
    179:   "BGP",
    520:   "RIP",
    521:   "RIPng",
    646:   "LDP",
    1812:  "RADIUS",
    1813:  "RADIUS-Acct",
    6514:  "Syslog-TLS",
    2055:  "NetFlow",
    4739:  "IPFIX",
    3000:  "Grafana",
    5601:  "Kibana",
    8161:  "ActiveMQ",
    61616: "ActiveMQ-TCP",
    5672:  "AMQP",
    15672: "RabbitMQ-Mgmt",
    9092:  "Kafka",
    2181:  "Zookeeper",
    500:   "IKE-ISAKMP",
    4500:  "IKE-NAT-T",
    1701:  "L2TP",
    1194:  "OpenVPN",
    51820: "WireGuard",
    1723:  "PPTP",
    2375:  "Docker",
    2376:  "Docker-TLS",
    6443:  "Kubernetes",
    10250: "Kubelet",
    2379:  "etcd",
    2380:  "etcd",
    8500:  "Consul",
    8300:  "Consul-RPC",
    4369:  "Erlang-EPMD",
    11211: "Memcached",
    515:   "LPD",
    631:   "IPP",
    4444:  "Shell-Common",
    4445:  "Shell-Common",
    502:   "Modbus",
    20000: "DNP3",
    44818: "EtherNet-IP",
    102:   "S7-ISO-TSAP",
    9600:  "OMRON-FINS",
    4840:  "OPC-UA",
    4843:  "OPC-UA-TLS",
    2404:  "IEC-60870-5-104",
    1089:  "FF-HSE",
    1090:  "FF-HSE",
    1091:  "FF-HSE",
    34964: "PROFINET",
    47808: "BACnet",
    1911:  "Niagara-Fox",
    4911:  "Niagara-Fox-TLS",
}

NOTABLE = {
    "FTP", "FTP-Data", "Telnet", "TFTP", "Finger",
    "rexec", "rlogin", "RSH-Syslog", "NNTP", "POP3",
    "IMAP", "SMTP", "HTTP",
    "Redis", "MongoDB", "Memcached", "Elasticsearch",
    "CouchDB", "InfluxDB", "Neo4j",
    "Docker", "Docker-TLS", "Kubernetes", "Kubelet",
    "etcd", "Erlang-EPMD",
    "SNMP", "SNMP-Trap", "MSRPC", "NFS", "RPC-portmap",
    "MSSQL-Browser", "Oracle-TNS",
    "Modbus", "DNP3", "EtherNet-IP", "S7-ISO-TSAP",
    "OMRON-FINS", "OPC-UA", "IEC-60870-5-104",
    "FF-HSE", "PROFINET", "BACnet", "Niagara-Fox",
    "Shell-Common",
}


class State:
    def __init__(self):
        self.lock            = threading.Lock()
        self.subnets         = defaultdict(int)
        self.src_ips         = defaultdict(int)
        self.protocol_counts = Counter()
        self.vlan_tags       = defaultdict(set)
        self.hostnames       = {}
        self.arp_table       = {}
        self.notable_hits    = []
        self.total_packets   = 0
        self.filtered_count  = 0
        self.start_time      = time.time()
        self.log_lines       = []
        self.excluded_ips    = set()


state = State()
args  = None


def subnet24(ip):
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except Exception:
        return None


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def log(msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    state.log_lines.append(f"  [{ts}] {msg}")


def divider(label, color=C.CYAN):
    pad = max(0, 54 - len(label) - 4)
    return f"{color}{C.BOLD}  -- {label} {'-' * pad}{C.RESET}"


def handle_packet(pkt):
    with state.lock:
        state.total_packets += 1

        if pkt.haslayer(Dot1Q):
            vlan_id = pkt[Dot1Q].vlan
            if pkt.haslayer(IP):
                src = pkt[IP].src
                is_new = vlan_id not in state.vlan_tags
                state.vlan_tags[vlan_id].add(src)
                if is_new:
                    log(f"VLAN TAG DETECTED -- VLAN {vlan_id} | First host: {src}")

        if pkt.haslayer(ARP):
            state.protocol_counts["ARP"] += 1
            src = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            if src and src != "0.0.0.0" and src not in state.excluded_ips:
                state.arp_table[src] = mac
                state.src_ips[src] += 1

        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst

            if src in state.excluded_ips or dst in state.excluded_ips:
                state.filtered_count += 1
                return

            state.src_ips[src] += 1

            net = subnet24(src)
            if net and is_private(src):
                new = net not in state.subnets
                state.subnets[net] += 1
                if new:
                    log(f"NEW SUBNET -- {net}  (first host: {src})")

            if pkt.haslayer(UDP):
                dport = pkt[UDP].dport
                sport = pkt[UDP].sport

                for port in (dport, sport):
                    if port in PROTOCOL_PORTS:
                        proto = PROTOCOL_PORTS[port]
                        state.protocol_counts[proto] += 1
                        if proto in NOTABLE:
                            hit = f"{src}:{sport} -> {dst}:{dport} [{proto}]"
                            if hit not in state.notable_hits:
                                state.notable_hits.append(hit)
                                log(f"NOTABLE -- {hit}")

                if dport == 5353 and pkt.haslayer(DNS):
                    try:
                        dns = pkt[DNS]
                        for i in range(dns.ancount):
                            rr = dns.an[i]
                            if hasattr(rr, "rrname") and hasattr(rr, "rdata"):
                                name = rr.rrname.decode("utf-8", errors="ignore").rstrip(".")
                                if src and src not in state.hostnames:
                                    state.hostnames[src] = name
                                    log(f"mDNS: {src} -> {name}")
                    except Exception:
                        pass

                if dport == 5355 and pkt.haslayer(DNS):
                    try:
                        dns = pkt[DNS]
                        for i in range(dns.qdcount):
                            q = dns.qd[i]
                            if hasattr(q, "qname"):
                                name = q.qname.decode("utf-8", errors="ignore").rstrip(".")
                                log(f"LLMNR query: {src} -> {name!r}")
                    except Exception:
                        pass

                if dport == 137 and pkt.haslayer(DNS):
                    try:
                        dns = pkt[DNS]
                        for i in range(dns.qdcount):
                            q = dns.qd[i]
                            if hasattr(q, "qname"):
                                name = q.qname.decode("utf-8", errors="ignore").strip()
                                if name and src and src not in state.hostnames:
                                    state.hostnames[src] = name
                                    log(f"NBNS: {src} -> {name}")
                    except Exception:
                        pass

                if dport in (67, 68) and pkt.haslayer(DHCP):
                    try:
                        for opt in pkt[DHCP].options:
                            if isinstance(opt, tuple) and opt[0] == "hostname":
                                name = opt[1].decode("utf-8", errors="ignore")
                                if src and src not in state.hostnames:
                                    state.hostnames[src] = name
                                    log(f"DHCP: {src} -> {name}")
                    except Exception:
                        pass

            if pkt.haslayer(TCP):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                for port in (dport, sport):
                    if port in PROTOCOL_PORTS:
                        proto = PROTOCOL_PORTS[port]
                        state.protocol_counts[proto] += 1
                        if proto in NOTABLE:
                            hit = f"{src}:{sport} -> {dst}:{dport} [{proto}]"
                            if hit not in state.notable_hits:
                                state.notable_hits.append(hit)
                                log(f"NOTABLE -- {hit}")

        if pkt.haslayer(IPv6):
            state.protocol_counts["IPv6"] += 1


def display_summary():
    elapsed    = int(time.time() - state.start_time)
    mins, secs = divmod(elapsed, 60)

    print("\033[2J\033[H", end="")

    print(f"{C.TEAL}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║                                                      ║")
    print("  ║              N E T B U D D Y   v 1 . 3               ║")
    print("  ║        Passive Network Broadcast Listener            ║")
    print("  ║              ms08067xp@gmail.com                     ║")
    print("  ║                                                      ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"{C.RESET}")
    print(f"  {C.GREY}Interface : {args.interface}   "
          f"Runtime: {mins:02d}:{secs:02d}   "
          f"Packets: {state.total_packets}   "
          f"Filtered: {state.filtered_count}{C.RESET}")
    print(f"  {C.GREY}Ctrl+C to stop and save results{C.RESET}\n")

    print(divider(f"Discovered Subnets ({len(state.subnets)})", C.GREEN))
    if state.subnets:
        for net, count in sorted(state.subnets.items(), key=lambda x: x[1], reverse=True):
            print(f"  {C.GREEN}{net:<22}{C.RESET}  {count:>7} pkts")
    else:
        print(f"  {C.GREY}  None detected yet{C.RESET}")

    print(divider(f"VLAN Tags ({len(state.vlan_tags)})", C.MAGENTA))
    if state.vlan_tags:
        for vlan_id, ips in sorted(state.vlan_tags.items()):
            print(f"  {C.MAGENTA}VLAN {vlan_id:<6}{C.RESET}  "
                  f"{len(ips)} host(s)   "
                  f"{C.GREY}{', '.join(sorted(ips))}{C.RESET}")
    else:
        print(f"  {C.GREY}  No 802.1Q tags observed -- likely access port{C.RESET}")

    print(divider("Protocol Activity", C.CYAN))
    if state.protocol_counts:
        for proto, count in state.protocol_counts.most_common(30):
            color = C.RED if proto in NOTABLE else C.CYAN
            print(f"  {color}{proto:<24}{C.RESET}  {count:>7}")
    else:
        print(f"  {C.GREY}  No protocols observed yet{C.RESET}")

    print(divider(f"Notable Detections ({len(state.notable_hits)})", C.RED))
    if state.notable_hits:
        for hit in state.notable_hits[-15:]:
            print(f"  {C.RED}{hit}{C.RESET}")
    else:
        print(f"  {C.GREY}  None detected{C.RESET}")

    print(divider(f"Hostnames ({len(state.hostnames)})", C.YELLOW))
    if state.hostnames:
        for ip, name in list(state.hostnames.items()):
            print(f"  {C.YELLOW}{ip:<18}{C.RESET}  {name}")
    else:
        print(f"  {C.GREY}  None discovered yet{C.RESET}")

    print(divider(f"ARP Table ({len(state.arp_table)} hosts)", C.BLUE))
    if state.arp_table:
        try:
            items = sorted(state.arp_table.items(),
                           key=lambda x: [int(p) for p in x[0].split(".") if p.isdigit()])
        except Exception:
            items = list(state.arp_table.items())
        for ip, mac in items:
            name = state.hostnames.get(ip, "")
            print(f"  {C.BLUE}{ip:<18}{C.RESET}  {mac}  {C.GREY}{name}{C.RESET}")
    else:
        print(f"  {C.GREY}  No ARP entries yet{C.RESET}")

    print(divider("Recent Events", C.GREY))
    if state.log_lines:
        for line in state.log_lines[-10:]:
            if "NEW SUBNET" in line:
                color = C.GREEN
            elif "VLAN TAG" in line:
                color = C.MAGENTA
            elif "NOTABLE" in line:
                color = C.RED
            elif any(x in line for x in ("mDNS", "LLMNR", "NBNS", "DHCP")):
                color = C.CYAN
            else:
                color = C.GREY
            print(f"{color}{line}{C.RESET}")
    else:
        print(f"  {C.GREY}  No events yet{C.RESET}")

    print()


def display_loop():
    while True:
        time.sleep(args.refresh)
        with state.lock:
            display_summary()


def save_results(path):
    with open(path, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("  NetBuddy v1.3 -- Passive Network Broadcast Listener\n")
        f.write("  ms08067xp@gmail.com\n")
        f.write(f"  Generated : {datetime.datetime.now()}\n")
        f.write(f"  Interface : {args.interface}\n")
        f.write(f"  Packets   : {state.total_packets}\n")
        f.write(f"  Filtered  : {state.filtered_count}\n")
        f.write("=" * 60 + "\n\n")

        f.write("DISCOVERED SUBNETS\n" + "-" * 40 + "\n")
        for net, count in sorted(state.subnets.items()):
            f.write(f"  {net:<22} {count} packets\n")

        f.write("\nVLAN TAGS\n" + "-" * 40 + "\n")
        if state.vlan_tags:
            for vid, ips in sorted(state.vlan_tags.items()):
                f.write(f"  VLAN {vid}: {', '.join(sorted(ips))}\n")
        else:
            f.write("  None detected\n")

        f.write("\nPROTOCOL COUNTS\n" + "-" * 40 + "\n")
        for proto, count in state.protocol_counts.most_common():
            flag = " *NOTABLE*" if proto in NOTABLE else ""
            f.write(f"  {proto:<24} {count}{flag}\n")

        f.write("\nNOTABLE DETECTIONS\n" + "-" * 40 + "\n")
        for hit in state.notable_hits:
            f.write(f"  {hit}\n")

        f.write("\nHOSTNAMES\n" + "-" * 40 + "\n")
        for ip, name in state.hostnames.items():
            f.write(f"  {ip:<18} {name}\n")

        f.write("\nARP TABLE\n" + "-" * 40 + "\n")
        for ip, mac in sorted(state.arp_table.items()):
            name = state.hostnames.get(ip, "")
            f.write(f"  {ip:<18} {mac}  {name}\n")

        f.write("\nEVENT LOG\n" + "-" * 40 + "\n")
        for line in state.log_lines:
            f.write(f"  {line}\n")

    print(f"\n{C.GREEN}  [+] Results saved: {path}{C.RESET}")


def signal_handler(sig, frame):
    print(f"\n\n{C.YELLOW}  [!] Stopping...{C.RESET}")
    with state.lock:
        display_summary()
    if args.output:
        save_results(args.output)
    sys.exit(0)


def parse_args():
    p = argparse.ArgumentParser(
        prog="net_listener.py",
        description="NetBuddy v1.3 - Passive Network Broadcast & VLAN Listener",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 net_listener.py -i eth0
  sudo python3 net_listener.py -i eth0 -t 300 -o results.txt
  sudo python3 net_listener.py -i eth0 --scanner-ips 192.168.1.50
  sudo python3 net_listener.py --list-interfaces
        """
    )
    p.add_argument("-i", "--interface",
                   help="Network interface to listen on")
    p.add_argument("-t", "--timeout",
                   type=int, default=0,
                   help="Stop after N seconds (default: run until Ctrl+C)")
    p.add_argument("-o", "--output",
                   default=None,
                   help="Save results to file on exit")
    p.add_argument("--refresh",
                   type=int, default=5,
                   help="Display refresh interval in seconds (default: 5)")
    p.add_argument("--scanner-ips",
                   default=None,
                   help="Additional IPs to exclude, comma-separated (e.g. dedicated scanner)")
    p.add_argument("--list-interfaces",
                   action="store_true",
                   help="List available interfaces and exit")
    return p.parse_args()


BPF_FILTER = (
    "broadcast or multicast or arp or "
    "(udp and ("
    "port 5353 or port 5355 or port 137 or port 138 or "
    "port 67 or port 68 or port 123 or port 1900 or "
    "port 161 or port 162 or port 520 or port 521 or "
    "port 502 or port 20000 or port 44818 or port 102 or "
    "port 4840 or port 47808 or port 69 or port 514 or "
    "port 2055 or port 4739 or port 500 or port 4500"
    ")) or "
    "(tcp and ("
    "port 21 or port 22 or port 23 or port 25 or "
    "port 53 or port 80 or port 110 or port 143 or "
    "port 389 or port 443 or port 445 or port 502 or "
    "port 1433 or port 1521 or port 3306 or port 3389 or "
    "port 5432 or port 5900 or port 6379 or port 8080 or "
    "port 27017 or port 44818 or port 102 or port 4840 or "
    "port 2375 or port 6443 or port 11211 or port 9200 or "
    "port 2049 or port 111 or port 512 or port 513"
    "))"
)


if __name__ == "__main__":
    args = parse_args()

    if args.list_interfaces:
        print(f"\n{C.CYAN}  Available interfaces:{C.RESET}")
        for iface in get_if_list():
            print(f"    {iface}")
        sys.exit(0)

    if not args.interface:
        print("[-] Specify -i <interface>.  Use --list-interfaces to see options.")
        sys.exit(1)

    signal.signal(signal.SIGINT, signal_handler)

    state.excluded_ips = set(LOCAL_IPS)
    if args.scanner_ips:
        for ip in args.scanner_ips.split(","):
            state.excluded_ips.add(ip.strip())

    print(f"\n{C.TEAL}{C.BOLD}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║                                                      ║")
    print("  ║              N E T B U D D Y   v 1 . 3               ║")
    print("  ║        Passive Network Broadcast Listener            ║")
    print("  ║              ms08067xp@gmail.com                     ║")
    print("  ║                                                      ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"{C.RESET}")
    print(f"  {C.CYAN}[*] Interface   : {args.interface}{C.RESET}")
    print(f"  {C.CYAN}[*] Timeout     : {'%ds' % args.timeout if args.timeout else 'until Ctrl+C'}{C.RESET}")
    print(f"  {C.CYAN}[*] Output      : {args.output or 'none'}{C.RESET}")
    print(f"  {C.CYAN}[*] Excluded    : {', '.join(sorted(state.excluded_ips))}{C.RESET}")
    print(f"  {C.CYAN}[*] Starting capture...{C.RESET}\n")

    dl = threading.Thread(target=display_loop, daemon=True)
    dl.start()

    try:
        sniff(
            iface=args.interface,
            prn=handle_packet,
            store=False,
            timeout=args.timeout if args.timeout else None,
            filter=BPF_FILTER,
        )
    except PermissionError:
        print(f"{C.RED}[-] Permission denied -- run as root{C.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{C.RED}[-] Capture error: {e}{C.RESET}")
        sys.exit(1)

    with state.lock:
        display_summary()
    if args.output:
        save_results(args.output)
