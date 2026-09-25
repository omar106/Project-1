#!/usr/bin/env python3
"""
iphone_finder.py - list the iPhones/iPads on your own Wi-Fi and the public IP
they share.

About the public IP
-------------------
Devices behind a home router do not have public IPs of their own. They share
the router's single public address through NAT, so every iPhone on your Wi-Fi
reaches the internet from the same address. This tool reports that shared
address alongside each device's LAN address. A phone using a VPN or iCloud
Private Relay leaves from that provider's address instead, which cannot be
observed from the LAN.

How devices are identified
--------------------------
Four independent signals, the same ones established open-source tooling uses:

1. mDNS/Bonjour service discovery. iOS advertises `_apple-mobdev2._tcp`, the
   service libimobiledevice and pymobiledevice3 browse to find iOS devices
   over Wi-Fi, plus `_companion-link._tcp`, `_device-info._tcp`,
   `_airplay._tcp` and `_raop._tcp`.
2. Model identifiers from those services' TXT records (`model=iPhone14,2`,
   `rpMd=`, `am=`), which name the exact hardware.
3. TCP port 62078, the iOS lockdownd sync service reachable over Wi-Fi.
4. MAC vendor (OUI) lookup, read from the system's IEEE OUI database when one
   is installed. This is a weak signal: since iOS 14 iPhones default to a
   randomised "Private Wi-Fi Address" per network, so the OUI usually does not
   say Apple. Randomised addresses are flagged as such.

Only run this against networks you own or are authorised to scan.

Usage
-----
    python3 iphone_finder.py                      # auto-detect the subnet
    python3 iphone_finder.py --network 192.168.1.0/24
    python3 iphone_finder.py --all-apple          # Macs, TVs, Watches too
    python3 iphone_finder.py --deep --json

Standard library only; Python 3.8+. Runs on Linux, macOS and Windows.
"""

import argparse
import ipaddress
import json
import os
import random
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
LOCKDOWND_PORT = 62078          # iOS lockdownd, reachable over Wi-Fi
MDNS_GROUP = "224.0.0.251"
MDNS_PORT = 5353

# Service types that iOS devices advertise. _apple-mobdev2._tcp is the one
# libimobiledevice/pymobiledevice3 use for Wi-Fi device discovery.
IOS_SERVICES = (
    "_apple-mobdev2._tcp.local",
    "_companion-link._tcp.local",
    "_device-info._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_rdlink._tcp.local",
)

# TXT keys that carry an Apple hardware identifier, e.g. "iPhone14,2".
MODEL_KEYS = ("model", "rpMd", "am", "device")

PUBLIC_IP_SERVICES = (
    "https://api.ipify.org",
    "https://ifconfig.me/ip",
    "https://icanhazip.com",
    "https://checkip.amazonaws.com",
)

# Where distributions install the IEEE OUI database. Used when present.
OUI_DATABASES = (
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/share/arp-scan/ieee-oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/wireshark/manuf",
    "/usr/share/hwdata/oui.txt",
    "/opt/homebrew/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
)

# A compact set of long-standing, widely published Apple OUI assignments, used
# only when no system OUI database is installed. Deliberately partial: IEEE has
# issued hundreds of Apple prefixes, and since iOS 14 iPhones randomise their
# Wi-Fi MAC per network anyway, so OUI is a supporting hint, never a test.
# Install nmap or arp-scan for the authoritative table.
APPLE_OUI_FALLBACK = (
    "00:03:93 00:05:02 00:0a:27 00:0a:95 00:0d:93 00:10:fa 00:14:51 "
    "00:16:cb 00:17:f2 00:19:e3 00:1b:63 00:1e:c2 00:1f:5b 00:1f:f3 "
    "00:21:e9 00:22:41 00:23:12 00:23:6c 00:23:df 00:25:00 00:25:4b "
    "00:25:bc 00:26:08 00:26:4a 00:26:b0 00:26:bb 00:30:65 00:50:e4 "
    "00:a0:40 08:00:07 28:cf:da 28:cf:e9 28:e7:cf 3c:07:54 40:30:04 "
    "44:2a:60 48:74:6e 60:33:4b 64:b9:e8 68:a8:6d 70:56:81 78:ca:39 "
    "7c:6d:62 84:38:35 88:c6:63 8c:58:77 90:84:0d 98:03:d8 a4:b1:97 "
    "ac:bc:32 b8:17:c2 bc:52:b7 c8:2a:14 d0:23:db d8:30:62 dc:2b:2a "
    "e0:b9:ba e4:ce:8f f4:f1:5a f8:1e:df"
)
_HEX6 = re.compile(r"^[0-9a-f]{6}$")
_APPLE_OUI_FALLBACK = frozenset(
    p for p in (o.replace(":", "").lower() for o in APPLE_OUI_FALLBACK.split())
    if _HEX6.match(p)
)

# DNS record types
T_A, T_PTR, T_TXT, T_SRV = 1, 12, 16, 33


# --------------------------------------------------------------------------- #
# DNS wire format
# --------------------------------------------------------------------------- #
def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        raw = label.encode("utf-8")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def read_name(data, offset, depth=0):
    """Decode a possibly compressed DNS name. Returns (name, offset_after)."""
    labels = []
    while True:
        if depth > 20 or offset >= len(data):
            raise ValueError("malformed name")
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack("!H", data[offset:offset + 2])[0] & 0x3FFF
            suffix, _ = read_name(data, pointer, depth + 1)
            labels.append(suffix)
            return ".".join(labels), offset + 2
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", "replace"))
        offset += length


def build_query(qname, qtype, unicast_response=True):
    """An mDNS query. The QU bit asks for a unicast reply to our own port,
    which avoids binding port 5353 (usually held by avahi/mDNSResponder).
    """
    header = struct.pack("!HHHHHH", random.randint(0, 0xFFFF), 0, 1, 0, 0, 0)
    qclass = 0x8001 if unicast_response else 0x0001
    return header + encode_name(qname) + struct.pack("!HH", qtype, qclass)


def parse_message(data):
    """Yield (name, rtype, rdata_offset, rdlen) for every record in a reply."""
    qd, an, ns, ar = struct.unpack("!HHHH", data[4:12])
    offset = 12
    for _ in range(qd):
        _, offset = read_name(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        name, offset = read_name(data, offset)
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH",
                                                    data[offset:offset + 10])
        offset += 10
        yield name, rtype, offset, rdlen
        offset += rdlen


def decode_txt(data, offset, rdlen):
    """TXT rdata is a sequence of length-prefixed strings: key=value pairs."""
    out = {}
    end = offset + rdlen
    while offset < end:
        length = data[offset]
        offset += 1
        chunk = data[offset:offset + length].decode("utf-8", "replace")
        offset += length
        key, _, value = chunk.partition("=")
        if key:
            out[key] = value
    return out


# --------------------------------------------------------------------------- #
# mDNS collection
# --------------------------------------------------------------------------- #
class MdnsRecords:
    """Everything learned from mDNS, indexed for correlation."""

    def __init__(self):
        self.ptr = {}       # service type -> {instance names}
        self.srv = {}       # instance -> hostname
        self.addr = {}      # hostname -> {ip}
        self.txt = {}       # instance -> {key: value}
        self.rev = {}       # ip -> hostname (from reverse PTR)

    def ingest(self, data):
        try:
            records = list(parse_message(data))
        except (ValueError, IndexError, struct.error):
            return
        for name, rtype, off, rdlen in records:
            try:
                if rtype == T_PTR:
                    target, _ = read_name(data, off)
                    if name.endswith(".in-addr.arpa"):
                        ip = ".".join(reversed(
                            name[:-len(".in-addr.arpa")].split(".")))
                        self.rev[ip] = target
                    else:
                        self.ptr.setdefault(name, set()).add(target)
                elif rtype == T_SRV:
                    host, _ = read_name(data, off + 6)
                    self.srv[name] = host
                elif rtype == T_A and rdlen == 4:
                    ip = socket.inet_ntoa(data[off:off + 4])
                    self.addr.setdefault(name, set()).add(ip)
                elif rtype == T_TXT:
                    entry = self.txt.setdefault(name, {})
                    entry.update(decode_txt(data, off, rdlen))
            except (ValueError, IndexError, struct.error, OSError):
                continue

    def ips_for_instance(self, instance):
        host = self.srv.get(instance)
        return set(self.addr.get(host, ())) if host else set()


def collect_mdns(service_types, extra_hosts=(), duration=3.0):
    """Browse for services and reverse-resolve hosts, on one socket.

    Queries go to the multicast group and, for known hosts, straight to the
    device as unicast mDNS, which iOS answers even when multicast is filtered.
    """
    records = MdnsRecords()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    except OSError:
        pass
    sock.settimeout(0.4)

    queries = [build_query(svc, T_PTR) for svc in service_types]
    for host in extra_hosts:
        rev = ".".join(reversed(str(host).split("."))) + ".in-addr.arpa"
        queries.append(build_query(rev, T_PTR))
        queries.append(build_query(f"{host}", T_A))

    try:
        for packet in queries:
            for dest in [(MDNS_GROUP, MDNS_PORT)] + [
                    (str(h), MDNS_PORT) for h in extra_hosts]:
                try:
                    sock.sendto(packet, dest)
                except OSError:
                    pass

        deadline = time.monotonic() + duration
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            records.ingest(data)

        # Resolve the hostnames that the browse turned up but did not address.
        pending = [h for inst, h in records.srv.items()
                   if h not in records.addr]
        if pending:
            for host in set(pending):
                try:
                    sock.sendto(build_query(host, T_A),
                                (MDNS_GROUP, MDNS_PORT))
                except OSError:
                    pass
            deadline = time.monotonic() + 1.5
            while time.monotonic() < deadline:
                try:
                    data, _ = sock.recvfrom(9000)
                except socket.timeout:
                    continue
                except OSError:
                    break
                records.ingest(data)
    finally:
        sock.close()
    return records


# --------------------------------------------------------------------------- #
# Host discovery
# --------------------------------------------------------------------------- #
def local_ip():
    """The LAN address of the interface holding the default route."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))       # sends nothing; selects a route
        return sock.getsockname()[0]
    finally:
        sock.close()


def tcp_open(ip, port, timeout):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout):
            return True
    except OSError:
        return False


def sweep(network, timeout, workers):
    """Probe every host on the subnet. Returns the set with 62078 open.

    The sweep doubles as ARP population: a TCP SYN forces the kernel to
    resolve each address at the link layer, so the ARP cache is warm
    afterwards even for hosts that refused the connection.
    """
    hosts = list(network.hosts())
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(
            lambda h: tcp_open(h, LOCKDOWND_PORT, timeout), hosts)
        return {str(h) for h, ok in zip(hosts, results) if ok}


def arp_table():
    """{ip: mac} from the OS ARP cache."""
    table = {}
    try:
        with open("/proc/net/arp") as handle:
            next(handle, None)
            for line in handle:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = normalise_mac(parts[3])
        if table:
            return table
    except OSError:
        pass
    for command in (["ip", "neigh"], ["arp", "-an"], ["arp", "-a"]):
        try:
            out = subprocess.run(command, capture_output=True, text=True,
                                 timeout=10).stdout
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            ip = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            mac = re.search(r"([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})",
                            line)
            if ip and mac:
                table[ip.group(1)] = normalise_mac(mac.group(1))
        if table:
            break
    return table


def normalise_mac(mac):
    octets = re.split(r"[:-]", mac.strip())
    return ":".join(o.rjust(2, "0").lower() for o in octets)


def is_randomised_mac(mac):
    """iOS Private Wi-Fi Address sets the locally-administered bit (bit 1)."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError, AttributeError):
        return False


def load_oui_database():
    """Parse whichever IEEE OUI database the system has. {oui: vendor}."""
    for path in OUI_DATABASES:
        if not os.path.isfile(path):
            continue
        table = {}
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # nmap-mac-prefixes: "001122 Vendor"
                    # oui.txt:           "00-11-22   (hex)\t\tVendor"
                    # wireshark manuf:   "00:11:22\tVendor\t# comment"
                    parts = line.split(None, 1)
                    if len(parts) != 2:
                        continue
                    digits = re.sub(r"[^0-9a-fA-F]", "", parts[0])
                    if len(digits) < 6:
                        continue
                    prefix = digits[:6].lower()
                    vendor = parts[1].replace("(hex)", "")
                    vendor = vendor.split("#")[0].strip()
                    vendor = vendor.split("\t")[0].strip()
                    if vendor:
                        table.setdefault(prefix, vendor)
        except OSError:
            continue
        if table:
            return table, path
    return {}, None


def vendor_for(mac, oui_db):
    """Vendor for a MAC in any separator style, or None if unknown."""
    if not mac:
        return None
    prefix = re.sub(r"[^0-9a-fA-F]", "", mac)[:6].lower()
    if len(prefix) != 6:
        return None
    if prefix in oui_db:
        return oui_db[prefix]
    if prefix in _APPLE_OUI_FALLBACK:
        return "Apple, Inc."
    return None


# --------------------------------------------------------------------------- #
# Model classification
# --------------------------------------------------------------------------- #
FAMILIES = (
    ("iphone", "iPhone"),
    ("ipad", "iPad"),
    ("ipod", "iPod touch"),
    ("watch", "Apple Watch"),
    ("appletv", "Apple TV"),
    ("audioaccessory", "HomePod"),
    ("realitydevice", "Apple Vision Pro"),
    ("macbookair", "Mac"),
    ("macbookpro", "Mac"),
    ("macbook", "Mac"),
    ("imac", "Mac"),
    ("macpro", "Mac"),
    ("macmini", "Mac"),
    ("mac", "Mac"),
)
MOBILE_FAMILIES = {"iPhone", "iPad", "iPod touch"}


def family_from_model(model):
    """'iPhone14,2' -> 'iPhone'. Returns None for board ids like 'J314sAP'."""
    if not model:
        return None
    key = model.lower().replace(" ", "").replace("-", "")
    for needle, family in FAMILIES:
        if key.startswith(needle):
            return family
    return None


def family_from_name(name):
    lowered = (name or "").lower()
    for needle, family in FAMILIES:
        if needle in lowered:
            return family
    return None


def pretty_name(instance_or_host):
    """'Omars-iPhone._apple-mobdev2._tcp.local' -> 'Omars-iPhone'."""
    if not instance_or_host:
        return None
    label = instance_or_host.split("._")[0]
    if label.endswith(".local"):
        label = label[:-len(".local")]
    # _apple-mobdev2 instances are named by a hex id, not by the device name.
    return label or None


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #
def build_devices(records, lockdown_hosts, arp, oui_db, network):
    """Merge every signal into one record per LAN address."""
    devices = {}

    def slot(ip):
        return devices.setdefault(ip, {
            "lan_ip": ip, "hostname": None, "model": None, "family": None,
            "mac": None, "vendor": None, "private_wifi_address": None,
            "services": set(), "signals": set(),
        })

    def in_scope(ip):
        try:
            return ipaddress.ip_address(ip) in network
        except ValueError:
            return False

    # mDNS: every advertised instance, mapped to the addresses it resolves to.
    for service, instances in records.ptr.items():
        for instance in instances:
            ips = records.ips_for_instance(instance)
            txt = records.txt.get(instance, {})
            model = next((txt[k] for k in MODEL_KEYS if txt.get(k)), None)
            name = (pretty_name(records.srv.get(instance))
                    or pretty_name(instance))
            for ip in ips:
                if not in_scope(ip):
                    continue
                dev = slot(ip)
                dev["services"].add(service.replace(".local", ""))
                dev["signals"].add("mdns")
                if model and not dev["model"]:
                    dev["model"] = model
                if name and (not dev["hostname"] or "iphone" in name.lower()):
                    dev["hostname"] = name

    # Reverse PTR names for anything the sweep found.
    for ip, name in records.rev.items():
        if in_scope(ip):
            dev = slot(ip)
            if not dev["hostname"]:
                dev["hostname"] = pretty_name(name)

    # Hosts with lockdownd listening.
    for ip in lockdown_hosts:
        dev = slot(ip)
        dev["services"].add(f"lockdownd:{LOCKDOWND_PORT}")
        dev["signals"].add("lockdownd")

    # MAC, vendor, randomisation.
    for ip, dev in devices.items():
        mac = arp.get(ip)
        mac = normalise_mac(mac) if mac else None
        dev["mac"] = mac
        dev["private_wifi_address"] = is_randomised_mac(mac) if mac else None
        vendor = vendor_for(mac, oui_db)
        dev["vendor"] = vendor
        if vendor and "apple" in vendor.lower():
            dev["signals"].add("oui")

    # Family and confidence.
    for dev in devices.values():
        dev["family"] = (family_from_model(dev["model"])
                         or family_from_name(dev["hostname"]))
        strong = ("mdns" in dev["signals"] and
                  any(s.startswith("_apple-mobdev2") for s in dev["services"]))
        if strong or (dev["family"] and "mdns" in dev["signals"]):
            dev["confidence"] = "high"
        elif ("lockdownd" in dev["signals"]
                and dev["signals"] & {"mdns", "oui"}):
            dev["confidence"] = "high"
        elif dev["signals"] & {"lockdownd", "oui"}:
            dev["confidence"] = "likely"
        else:
            dev["confidence"] = "possible"
        dev["services"] = sorted(dev["services"])
        dev["signals"] = sorted(dev["signals"])

    return devices


def is_apple(dev):
    return bool(dev["family"] or dev["signals"])


def is_mobile(dev):
    if dev["family"]:
        return dev["family"] in MOBILE_FAMILIES
    # No model string: lockdownd alone means an iPhone/iPad in practice.
    return "lockdownd" in dev["signals"]


# --------------------------------------------------------------------------- #
# Public IP
# --------------------------------------------------------------------------- #
def public_ip(timeout=5):
    for url in PUBLIC_IP_SERVICES:
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "iphone_finder/2"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                candidate = response.read().decode().strip()
            ipaddress.ip_address(candidate)
            return candidate
        except (OSError, ValueError):
            continue
    return None


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #
def print_table(devices, shared_ip, oui_path):
    print(f"\nPublic IP of this network: {shared_ip or 'unavailable'}")
    print("All devices behind the router share it through NAT.\n")
    if not devices:
        print("No iPhones or iPads found. Wake the phones, confirm they "
              "are on this Wi-Fi, then run again with --deep.")
        return
    widths = (16, 24, 13, 20, 12)
    headers = ("LAN IP", "Device", "Model", "MAC", "Confidence")
    print("".join(h.ljust(w) for h, w in zip(headers, widths)) + "Public IP")
    print("-" * (sum(widths) + len("Public IP")))
    for dev in devices:
        mac = dev["mac"] or "?"
        if dev["private_wifi_address"]:
            mac += " *"
        row = (
            dev["lan_ip"],
            (dev["hostname"] or dev["family"] or "unknown")[:23],
            (dev["model"] or dev["family"] or "-")[:12],
            mac[:18],
            dev["confidence"],
        )
        print("".join(str(c).ljust(w) for c, w in zip(row, widths))
              + (dev["public_ip"] or "?"))
    if any(d["private_wifi_address"] for d in devices):
        print("\n* Private (randomised) Wi-Fi Address, the iOS default since "
              "iOS 14. It does not identify Apple and changes per network.")
    print("\nSignals per device:")
    for dev in devices:
        print(f"  {dev['lan_ip']:<16}{', '.join(dev['services']) or 'none'}")
    if not oui_path:
        print("\nNo system OUI database found; vendor lookup used the "
              "built-in partial Apple list. Install nmap or arp-scan "
              "for the full one.")
    print("\nA phone on a VPN or iCloud Private Relay reaches the internet "
          "from that provider's address, not the one above.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Find iPhones/iPads on your Wi-Fi and the public IP they "
                    "share.")
    parser.add_argument("--network",
                        help="subnet to scan, e.g. 192.168.1.0/24")
    parser.add_argument("--timeout", type=float, default=0.6,
                        help="per-host TCP timeout, seconds (default 0.6)")
    parser.add_argument("--workers", type=int, default=128,
                        help="concurrent probes (default 128)")
    parser.add_argument("--mdns-wait", type=float, default=3.0,
                        help="seconds to collect mDNS replies (default 3)")
    parser.add_argument("--deep", action="store_true",
                        help="slower and more thorough: longer waits")
    parser.add_argument("--all-apple", action="store_true",
                        help="also list Macs, Apple TVs, Watches and HomePods")
    parser.add_argument("--no-public-ip", action="store_true",
                        help="skip the outbound public-IP lookup")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.deep:
        args.timeout = max(args.timeout, 1.5)
        args.mdns_wait = max(args.mdns_wait, 8.0)

    try:
        here = local_ip()
    except OSError:
        sys.exit("Could not determine this machine's LAN address. "
                 "Are you connected to Wi-Fi?")
    network = (ipaddress.ip_network(args.network, strict=False)
               if args.network else ipaddress.ip_network(f"{here}/24",
                                                         strict=False))
    if network.num_addresses > 4096:
        sys.exit(f"{network} is too large to sweep; pass a /20 or smaller.")

    quiet = args.json
    if not quiet:
        print(f"This machine: {here}   Subnet: {network} "
              f"({network.num_addresses - 2} addresses)")
        print(f"Probing TCP {LOCKDOWND_PORT} and browsing mDNS ...")

    lockdown_hosts = sweep(network, args.timeout, args.workers)
    arp = arp_table()
    # Browse mDNS, and ask every host the sweep saw at the link layer directly.
    known = sorted(set(lockdown_hosts) | {ip for ip in arp if
                                          ipaddress.ip_address(ip) in network})
    records = collect_mdns(IOS_SERVICES, known, args.mdns_wait)
    arp = arp_table() or arp          # refresh after mDNS traffic
    oui_db, oui_path = load_oui_database()

    devices = build_devices(records, lockdown_hosts, arp, oui_db, network)
    selected = [d for d in devices.values()
                if is_apple(d) and (args.all_apple or is_mobile(d))]
    selected.sort(key=lambda d: ipaddress.ip_address(d["lan_ip"]))

    shared_ip = None if args.no_public_ip else public_ip()
    for dev in selected:
        dev["public_ip"] = shared_ip

    if args.json:
        print(json.dumps({
            "scanner_ip": here,
            "network": str(network),
            "public_ip": shared_ip,
            "public_ip_is_shared_via_nat": True,
            "oui_database": oui_path,
            "devices": selected,
        }, indent=2, sort_keys=True))
    else:
        print_table(selected, shared_ip, oui_path)
    return 0


if __name__ == "__main__":
    if sys.version_info < (3, 8):
        sys.exit("Python 3.8 or newer is required.")
    sys.exit(main())
