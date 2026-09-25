# iphone_finder.py

Lists the iPhones and iPads on your own Wi-Fi network, with the public IP
address they use.

Standard library only. Python 3.8 or newer. Runs on Linux, macOS and Windows.

## The public IP, in one paragraph

Phones on your Wi-Fi do not have public IP addresses of their own. Your router
holds a single public address and shares it with every device behind it through
NAT, so all of them reach the internet from that one address. This tool reports
it next to each device's private LAN address. A phone using a VPN or iCloud
Private Relay is the exception: its traffic leaves from that provider's address
instead, and nothing on the LAN can observe it.

## Usage

```bash
python3 iphone_finder.py                       # detect the subnet and scan it
python3 iphone_finder.py --network 192.168.1.0/24
python3 iphone_finder.py --deep                # longer waits, catches sleepy phones
python3 iphone_finder.py --all-apple           # Macs, Apple TVs, Watches, HomePods
python3 iphone_finder.py --json                # machine-readable output
python3 iphone_finder.py --no-public-ip        # stay entirely on the LAN
```

Run it from a computer joined to the same Wi-Fi. No root or admin rights are
needed. Sample output:

```
LAN IP          Device                  Model        MAC                 Confidence  Public IP
----------------------------------------------------------------------------------------------
192.168.1.42    Omars-iPhone            iPhone14,2   ba:3d:1c:77:0e:a9 * high        94.200.x.x
192.168.1.51    Office-iPad             iPad13,4     7a:11:c4:2e:9b:05 * high        94.200.x.x

* Private (randomised) Wi-Fi Address, the iOS default since iOS 14.
```

## How devices are identified

Four independent signals, the same ones established open-source tooling relies
on. Each device's `Confidence` column reflects how many agreed.

| Signal | What it is |
| --- | --- |
| `_apple-mobdev2._tcp` | The mDNS/Bonjour service iOS advertises for Wi-Fi sync. This is what `libimobiledevice` and `pymobiledevice3` browse to find iOS devices over the network, so it is the strongest signal available. |
| TXT record models | `_device-info._tcp`, `_companion-link._tcp`, `_airplay._tcp` and `_raop._tcp` carry the hardware identifier in their TXT records (`model=iPhone14,2`, `rpMd=`, `am=`). This is what yields the exact model and tells an iPhone from an iPad. |
| TCP 62078 | The iOS `lockdownd` sync service, reachable over Wi-Fi. Effectively only iPhones and iPads listen here. |
| MAC vendor (OUI) | Read from the system IEEE OUI database when one is installed (`nmap`, `arp-scan`, Wireshark, `ieee-data`). A *weak* signal, see below. |

mDNS queries are sent with the unicast-response (QU) bit set, so replies arrive
on an ephemeral port. That avoids having to bind port 5353, which `avahi` or
`mDNSResponder` normally holds. Queries go to the multicast group and also
directly to each host the sweep saw, because iOS answers unicast mDNS even
where multicast is filtered.

## Limitations worth knowing

- **Randomised MACs.** Since iOS 14, iPhones default to a Private Wi-Fi Address
  per network. The MAC is locally administered, changes per network, and does
  *not* carry Apple's OUI. The tool detects and flags these rather than
  pretending the vendor lookup worked. This is why identification leans on mDNS
  and port 62078, not on the MAC.
- **Sleeping phones.** A locked, idle iPhone may not answer promptly. Use
  `--deep`, or wake the screen and re-run.
- **Client isolation.** Guest networks and "AP isolation" block device-to-device
  traffic, so nothing will be found. Run from the main network.
- **`_apple-mobdev2` is iOS-specific.** Apple TV (tvOS 26 and later) does not
  advertise it; those devices are found via `_airplay._tcp` instead, and only
  appear with `--all-apple`.
- **Subnet size.** Sweeps are capped at a /20. Pass `--network` for anything
  unusual.

## Scope

Use this only on networks you own or are authorised to scan. It is a LAN
administration tool: it works because the devices have joined a network you
control. It cannot and will not find devices that have not joined your network,
and there is no way to read a public IP for someone else's phone.

## Tests

```bash
python3 -m unittest discover tools -v      # from the repository root
```

34 tests covering the DNS/mDNS wire format (name compression, PTR/SRV/TXT/A
decoding, malformed and truncated input), all three on-disk OUI database
formats, MAC normalisation and randomisation detection, model classification,
signal correlation and confidence scoring, and the CLI's JSON output.
