#!/usr/bin/env python3
"""
iphone_finder.py - list iPhones/iPads on your Wi-Fi and the public IP they use.

How it works
------------
1. Works out your local subnet (or uses --network).
2. Probes every host on the subnet on TCP port 62078 (the iOS "lockdownd"
   sync port). Only iPhones / iPads normally have this port open.
3. Asks each responding host for its Bonjour (mDNS) name, e.g.
   "Omars-iPhone.local", and reads its MAC address from the ARP table.
4. Looks up the network's public IP address.

Important: devices behind a home router share ONE public IP address (NAT).
Every iPhone on your Wi-Fi therefore reaches the internet from the same public
IP as the router. The script reports that shared address. The only exception
is a phone that is also using a VPN or iCloud Private Relay, whose traffic
leaves from the VPN/relay provider's address instead; that cannot be seen from
the LAN.

Only use this on networks you own or are authorised to scan.

Usage
-----
    python3 iphone_finder.py                    # auto-detect subnet
    python3 iphone_finder.py --network 192.168.1.0/24
    python3 iphone_finder.py --json

Standard library only; Python 3.8+. Works on Windows, macOS and Linux.
"""

import argparse
import ipaddress
import json
import random
import re
import socket
import struct
import subprocess
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

IOS_SYNC_PORT = 62078
PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)
MDNS_ADDR = ("224.0.0.251", 5353)


# --------------------------------------------------------------------------- #
# Network discovery
# --------------------------------------------------------------------------- #
def local_ip():
    """Return the LAN IP of the interface used for the default route."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packet is sent; this just selects the outgoing interface.
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()


def default_network(ip):
    """Assume a /24, which is what almost every home router hands out."""
    return ipaddress.ip_network(f"{ip}/24", strict=False)


def port_open(ip, port, timeout):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except OSError:
        return False


def arp_table():
    """Return {ip: mac} from the OS ARP cache."""
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].lower()
        return table
    except OSError:
        pass
    try:
        out = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return table
    for line in out.splitlines():
        ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
        mac = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})", line)
        if ip and mac:
            octets = re.split(r"[:-]", mac.group(1))
            table[ip.group(1)] = ":".join(o.zfill(2) for o in octets).lower()
    return table


def is_randomised_mac(mac):
    """iOS 'Private Wi-Fi Address' sets the locally-administered bit."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


# --------------------------------------------------------------------------- #
# mDNS / Bonjour reverse lookup (e.g. 192.168.1.23 -> "Omars-iPhone.local")
# --------------------------------------------------------------------------- #
def _encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def _read_name(data, offset, depth=0):
    labels = []
    while depth < 20:
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            name, _ = _read_name(data, pointer, depth + 1)
            labels.append(name)
            return ".".join(labels), offset + 2
        offset += 1
        labels.append(data[offset:offset + length].decode(errors="replace"))
        offset += length
    raise ValueError("name too deep")


def mdns_hostname(ip, timeout=1.5):
    """Send a unicast-response mDNS PTR query for the IP's reverse name."""
    rev = ".".join(reversed(str(ip).split("."))) + ".in-addr.arpa"
    qid = random.randint(0, 0xFFFF)
    header = struct.pack("!HHHHHH", qid, 0, 1, 0, 0, 0)
    # QTYPE=PTR(12), QCLASS=IN with the "unicast response" bit set.
    question = _encode_name(rev) + struct.pack("!HH", 12, 0x8001)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        # Ask the device directly first, then fall back to multicast.
        for dest in ((str(ip), 5353), MDNS_ADDR):
            try:
                sock.sendto(header + question, dest)
                data, _ = sock.recvfrom(4096)
            except OSError:
                continue
            name = _parse_ptr_answer(data)
            if name:
                return name
    finally:
        sock.close()
    return None


def _parse_ptr_answer(data):
    try:
        qd, an = struct.unpack("!HH", data[4:8])
        offset = 12
        for _ in range(qd):
            _, offset = _read_name(data, offset)
            offset += 4
        for _ in range(an):
            _, offset = _read_name(data, offset)
            rtype, _, _, rdlen = struct.unpack("!HHIH", data[offset:offset + 10])
            offset += 10
            if rtype == 12:
                name, _ = _read_name(data, offset)
                return name
            offset += rdlen
    except (ValueError, IndexError, struct.error):
        pass
    return None


# --------------------------------------------------------------------------- #
# Public IP
# --------------------------------------------------------------------------- #
def public_ip(timeout=5):
    for url in PUBLIC_IP_SERVICES:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "curl/8"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                candidate = r.read().decode().strip()
            ipaddress.ip_address(candidate)
            return candidate
        except (OSError, ValueError):
            continue
    return None


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def scan(network, timeout, workers):
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        flags = pool.map(lambda h: port_open(h, IOS_SYNC_PORT, timeout), hosts)
        candidates = [str(h) for h, ok in zip(hosts, flags) if ok]
    with ThreadPoolExecutor(max_workers=16) as pool:
        names = list(pool.map(mdns_hostname, candidates))
    arp = arp_table()
    devices = []
    for ip, name in zip(candidates, names):
        mac = arp.get(ip)
        devices.append({
            "lan_ip": ip,
            "hostname": name,
            "mac": mac,
            "private_wifi_address": is_randomised_mac(mac) if mac else None,
            "kind": _guess_kind(name),
        })
    return devices


def _guess_kind(name):
    n = (name or "").lower()
    if "iphone" in n:
        return "iPhone"
    if "ipad" in n:
        return "iPad"
    return "iPhone/iPad (port 62078 open)"


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--network", help="subnet to scan, e.g. 192.168.1.0/24")
    ap.add_argument("--timeout", type=float, default=0.6,
                    help="per-host TCP timeout in seconds (default 0.6)")
    ap.add_argument("--workers", type=int, default=128)
    ap.add_argument("--json", action="store_true", help="print JSON output")
    args = ap.parse_args()

    try:
        my_ip = local_ip()
    except OSError:
        sys.exit("Could not determine local IP. Are you connected to Wi-Fi?")
    network = (ipaddress.ip_network(args.network, strict=False)
               if args.network else default_network(my_ip))
    if network.num_addresses > 4096:
        sys.exit(f"{network} is too large; pass a /20 or smaller with --network")

    if not args.json:
        print(f"This computer: {my_ip}   Scanning: {network} "
              f"({network.num_addresses - 2} hosts) ...")

    devices = scan(network, args.timeout, args.workers)
    pub = public_ip()
    for d in devices:
        d["public_ip"] = pub

    if args.json:
        print(json.dumps({"network": str(network), "public_ip": pub,
                          "devices": devices}, indent=2))
        return

    print(f"\nPublic IP of this Wi-Fi network: {pub or 'unavailable'}")
    print("(All devices behind your router share this address via NAT.)\n")
    if not devices:
        print("No iPhones/iPads found. Make sure they are awake and on the "
              "same Wi-Fi, then run again.")
        return
    print(f"{'LAN IP':<16}{'Device':<30}{'MAC':<19}{'Public IP'}")
    print("-" * 80)
    for d in devices:
        label = d["hostname"] or d["kind"]
        mac = d["mac"] or "?"
        if d["private_wifi_address"]:
            mac += "*"
        print(f"{d['lan_ip']:<16}{label[:29]:<30}{mac:<19}{d['public_ip'] or '?'}")
    if any(d["private_wifi_address"] for d in devices):
        print("\n* Private (randomised) Wi-Fi address, the iOS default.")
    print("\nNote: a phone using a VPN or iCloud Private Relay appears online "
          "from that provider's IP instead.")


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        sys.exit("Python 3.8+ required")
    main()
