#!/usr/bin/env python3
"""Tests for iphone_finder.py. Run: python3 -m unittest discover tools -v"""

import os
import socket
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import iphone_finder as ifi  # noqa: E402


def dns_message(records, questions=0):
    """Build a DNS/mDNS reply. records: list of (name, rtype, rdata)."""
    header = struct.pack("!HHHHHH", 0x1234, 0x8400, questions,
                         len(records), 0, 0)
    body = b""
    for name, rtype, rdata in records:
        body += (ifi.encode_name(name)
                 + struct.pack("!HHIH", rtype, 0x8001, 120, len(rdata))
                 + rdata)
    return header + body


def txt_rdata(pairs):
    out = b""
    for item in pairs:
        raw = item.encode()
        out += bytes([len(raw)]) + raw
    return out


def srv_rdata(target, port=62078):
    return struct.pack("!HHH", 0, 0, port) + ifi.encode_name(target)


class NameCodec(unittest.TestCase):
    def test_roundtrip(self):
        for name in ("Omars-iPhone.local", "_apple-mobdev2._tcp.local",
                     "a.b.c"):
            decoded, offset = ifi.read_name(ifi.encode_name(name), 0)
            self.assertEqual(decoded, name)
            self.assertEqual(offset, len(ifi.encode_name(name)))

    def test_compression_pointer(self):
        data = ifi.encode_name("iPhone.local") + b"\x04test\xc0\x00"
        name, _ = ifi.read_name(data, len(ifi.encode_name("iPhone.local")))
        self.assertEqual(name, "test.iPhone.local")

    def test_malformed_name_raises(self):
        with self.assertRaises(ValueError):
            ifi.read_name(b"\x05abc", 0)       # length exceeds the buffer


class RecordParsing(unittest.TestCase):
    def test_a_record(self):
        msg = dns_message([("Omars-iPhone.local", ifi.T_A,
                            socket.inet_aton("192.168.1.42"))])
        store = ifi.MdnsRecords()
        store.ingest(msg)
        self.assertEqual(store.addr["Omars-iPhone.local"], {"192.168.1.42"})

    def test_reverse_ptr_becomes_hostname(self):
        msg = dns_message([("42.1.168.192.in-addr.arpa", ifi.T_PTR,
                            ifi.encode_name("Omars-iPhone.local"))])
        store = ifi.MdnsRecords()
        store.ingest(msg)
        self.assertEqual(store.rev["192.168.1.42"], "Omars-iPhone.local")

    def test_service_browse_ptr(self):
        msg = dns_message([("_apple-mobdev2._tcp.local", ifi.T_PTR,
                            ifi.encode_name("abc._apple-mobdev2._tcp.local"))])
        store = ifi.MdnsRecords()
        store.ingest(msg)
        self.assertIn("abc._apple-mobdev2._tcp.local",
                      store.ptr["_apple-mobdev2._tcp.local"])

    def test_srv_and_txt_resolve_to_ip(self):
        instance = "Omars-iPhone._device-info._tcp.local"
        msg = dns_message([
            ("_device-info._tcp.local", ifi.T_PTR, ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("Omars-iPhone.local")),
            (instance, ifi.T_TXT,
             txt_rdata(["model=iPhone14,2", "osxvers=21"])),
            ("Omars-iPhone.local", ifi.T_A, socket.inet_aton("192.168.1.42")),
        ])
        store = ifi.MdnsRecords()
        store.ingest(msg)
        self.assertEqual(store.ips_for_instance(instance), {"192.168.1.42"})
        self.assertEqual(store.txt[instance]["model"], "iPhone14,2")

    def test_truncated_message_is_ignored(self):
        store = ifi.MdnsRecords()
        store.ingest(b"\x12\x34\x84\x00\x00\x00\x00\x01")   # claims 1 answer
        self.assertEqual(store.addr, {})

    def test_garbage_does_not_raise(self):
        store = ifi.MdnsRecords()
        for blob in (b"", b"\x00", b"\xff" * 64, os.urandom(120)):
            store.ingest(blob)


class QueryBuilding(unittest.TestCase):
    def test_unicast_response_bit(self):
        packet = ifi.build_query("_apple-mobdev2._tcp.local", ifi.T_PTR)
        qclass = struct.unpack("!H", packet[-2:])[0]
        self.assertEqual(qclass, 0x8001)
        self.assertEqual(struct.unpack("!H", packet[4:6])[0], 1)   # 1 question

    def test_multicast_response_bit(self):
        packet = ifi.build_query("x.local", ifi.T_A, unicast_response=False)
        self.assertEqual(struct.unpack("!H", packet[-2:])[0], 0x0001)


class MacHandling(unittest.TestCase):
    def test_normalise(self):
        self.assertEqual(ifi.normalise_mac("A8-6D-AA-1-2-3"),
                         "a8:6d:aa:01:02:03")
        self.assertEqual(ifi.normalise_mac("f0:18:98:AB:CD:EF"),
                         "f0:18:98:ab:cd:ef")

    def test_randomised_detection(self):
        # Locally-administered bit set -> iOS Private Wi-Fi Address.
        for mac in ("ba:12:34:56:78:9a", "02:00:00:00:00:01",
                    "a6:ff:ff:ff:ff:ff"):
            self.assertTrue(ifi.is_randomised_mac(mac), mac)
        for mac in ("f0:18:98:00:00:01", "28:cf:da:11:22:33",
                    "00:00:00:00:00:00"):
            self.assertFalse(ifi.is_randomised_mac(mac), mac)

    def test_randomised_detection_bad_input(self):
        for mac in (None, "", "not-a-mac", "zz:11:22:33:44:55"):
            self.assertFalse(ifi.is_randomised_mac(mac))

    def test_vendor_from_fallback(self):
        self.assertIn("Apple", ifi.vendor_for("28:cf:da:00:11:22", {}))
        self.assertIsNone(ifi.vendor_for("aa:bb:cc:dd:ee:ff", {}))
        self.assertIsNone(ifi.vendor_for(None, {}))

    def test_vendor_prefers_system_database(self):
        db = {"28cfda": "Example Corp"}
        self.assertEqual(ifi.vendor_for("28:cf:da:00:11:22", db),
                         "Example Corp")


class OuiDatabase(unittest.TestCase):
    """The three on-disk formats iphone_finder reads."""

    FORMATS = {
        "nmap-mac-prefixes": "28CFDA Apple\n001122 Example Inc\n",
        "ieee-oui.txt": "28-CF-DA   (hex)\t\tApple, Inc.\n"
                        "\t\t\t1 Infinite Loop\n",
        "wireshark-manuf": "# comment line\n"
                           "28:CF:DA\tApple\tApple, Inc.\n",
    }

    def _load(self, text):
        with tempfile.NamedTemporaryFile(
                "w", suffix=".txt", delete=False) as fh:
            fh.write(text)
            name = fh.name
        original = ifi.OUI_DATABASES
        try:
            ifi.OUI_DATABASES = (name,)
            return ifi.load_oui_database()
        finally:
            ifi.OUI_DATABASES = original
            os.unlink(name)

    def test_each_format_yields_apple(self):
        for label, text in self.FORMATS.items():
            with self.subTest(format=label):
                table, path = self._load(text)
                self.assertIsNotNone(path)
                self.assertIn("28cfda", table)
                self.assertIn("Apple", table["28cfda"])

    def test_address_continuation_lines_skipped(self):
        table, _ = self._load("28-CF-DA   (hex)\t\tApple, Inc.\n"
                              "       170 WEST TASMAN DRIVE\n")
        self.assertEqual(list(table), ["28cfda"])

    def test_missing_files_return_empty(self):
        original = ifi.OUI_DATABASES
        try:
            ifi.OUI_DATABASES = ("/nonexistent/oui/db",)
            self.assertEqual(ifi.load_oui_database(), ({}, None))
        finally:
            ifi.OUI_DATABASES = original


class Classification(unittest.TestCase):
    def test_family_from_model(self):
        cases = {
            "iPhone14,2": "iPhone", "iPhone8,1": "iPhone",
            "iPad13,4": "iPad", "iPod9,1": "iPod touch",
            "Watch6,1": "Apple Watch", "AppleTV11,1": "Apple TV",
            "AudioAccessory5,1": "HomePod", "MacBookPro18,3": "Mac",
            "RealityDevice14,1": "Apple Vision Pro",
        }
        for model, family in cases.items():
            self.assertEqual(ifi.family_from_model(model), family, model)

    def test_board_id_has_no_family(self):
        for model in ("J314sAP", "", None, "Unknown9,9"):
            self.assertIsNone(ifi.family_from_model(model))

    def test_family_from_hostname(self):
        self.assertEqual(ifi.family_from_name("Omars-iPhone"), "iPhone")
        self.assertEqual(ifi.family_from_name("office-ipad-2"), "iPad")
        self.assertIsNone(ifi.family_from_name("printer"))

    def test_pretty_name(self):
        self.assertEqual(
            ifi.pretty_name("Omars-iPhone._apple-mobdev2._tcp.local"),
            "Omars-iPhone")
        self.assertEqual(ifi.pretty_name("Omars-iPhone.local"), "Omars-iPhone")
        self.assertIsNone(ifi.pretty_name(None))


class DeviceCorrelation(unittest.TestCase):
    NET = __import__("ipaddress").ip_network("192.168.1.0/24")

    def _store(self, records):
        store = ifi.MdnsRecords()
        store.ingest(dns_message(records))
        return store

    def test_mobdev2_device_is_high_confidence(self):
        instance = "a1b2._apple-mobdev2._tcp.local"
        store = self._store([
            ("_apple-mobdev2._tcp.local", ifi.T_PTR,
             ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("Omars-iPhone.local")),
            ("Omars-iPhone.local", ifi.T_A, socket.inet_aton("192.168.1.42")),
        ])
        devices = ifi.build_devices(
            store, {"192.168.1.42"},
            {"192.168.1.42": "ba:11:22:33:44:55"}, {}, self.NET)
        dev = devices["192.168.1.42"]
        self.assertEqual(dev["confidence"], "high")
        self.assertEqual(dev["hostname"], "Omars-iPhone")
        self.assertTrue(dev["private_wifi_address"])
        self.assertTrue(ifi.is_mobile(dev))

    def test_model_from_txt_sets_family(self):
        instance = "Omars-iPhone._device-info._tcp.local"
        store = self._store([
            ("_device-info._tcp.local", ifi.T_PTR, ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("Omars-iPhone.local")),
            (instance, ifi.T_TXT, txt_rdata(["model=iPhone14,2"])),
            ("Omars-iPhone.local", ifi.T_A, socket.inet_aton("192.168.1.42")),
        ])
        dev = ifi.build_devices(store, set(), {}, {}, self.NET)["192.168.1.42"]
        self.assertEqual(dev["model"], "iPhone14,2")
        self.assertEqual(dev["family"], "iPhone")
        self.assertEqual(dev["confidence"], "high")

    def test_companion_link_model_key(self):
        instance = "x._companion-link._tcp.local"
        store = self._store([
            ("_companion-link._tcp.local", ifi.T_PTR,
             ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("ipad.local")),
            (instance, ifi.T_TXT, txt_rdata(["rpMd=iPad13,4", "rpVr=360.4"])),
            ("ipad.local", ifi.T_A, socket.inet_aton("192.168.1.50")),
        ])
        dev = ifi.build_devices(store, set(), {}, {}, self.NET)["192.168.1.50"]
        self.assertEqual(dev["family"], "iPad")

    def test_lockdownd_only_is_likely_and_mobile(self):
        devices = ifi.build_devices(ifi.MdnsRecords(), {"192.168.1.77"},
                                    {}, {}, self.NET)
        dev = devices["192.168.1.77"]
        self.assertEqual(dev["confidence"], "likely")
        self.assertTrue(ifi.is_mobile(dev))
        self.assertIsNone(dev["family"])

    def test_lockdownd_plus_apple_oui_is_high(self):
        devices = ifi.build_devices(ifi.MdnsRecords(), {"192.168.1.77"},
                                    {"192.168.1.77": "28:cf:da:00:11:22"},
                                    {}, self.NET)
        self.assertEqual(devices["192.168.1.77"]["confidence"], "high")

    def test_mac_is_not_apple_when_randomised(self):
        devices = ifi.build_devices(ifi.MdnsRecords(), {"192.168.1.77"},
                                    {"192.168.1.77": "ba:cf:da:00:11:22"},
                                    {}, self.NET)
        dev = devices["192.168.1.77"]
        self.assertIsNone(dev["vendor"])
        self.assertTrue(dev["private_wifi_address"])

    def test_addresses_outside_the_subnet_are_dropped(self):
        instance = "tv._airplay._tcp.local"
        store = self._store([
            ("_airplay._tcp.local", ifi.T_PTR, ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("tv.local")),
            ("tv.local", ifi.T_A, socket.inet_aton("10.0.0.5")),
        ])
        self.assertEqual(ifi.build_devices(store, set(), {}, {}, self.NET), {})

    def test_mac_only_appears_for_known_hosts(self):
        devices = ifi.build_devices(ifi.MdnsRecords(), {"192.168.1.9"},
                                    {"192.168.1.9": "F0-18-98-1-2-3"},
                                    {"f01898": "Apple, Inc."}, self.NET)
        self.assertEqual(devices["192.168.1.9"]["vendor"], "Apple, Inc.")

    def test_apple_tv_excluded_unless_all_apple(self):
        instance = "tv._airplay._tcp.local"
        store = self._store([
            ("_airplay._tcp.local", ifi.T_PTR, ifi.encode_name(instance)),
            (instance, ifi.T_SRV, srv_rdata("tv.local")),
            (instance, ifi.T_TXT, txt_rdata(["model=AppleTV11,1"])),
            ("tv.local", ifi.T_A, socket.inet_aton("192.168.1.60")),
        ])
        dev = ifi.build_devices(store, set(), {}, {}, self.NET)["192.168.1.60"]
        self.assertEqual(dev["family"], "Apple TV")
        self.assertTrue(ifi.is_apple(dev))
        self.assertFalse(ifi.is_mobile(dev))


class Cli(unittest.TestCase):
    def test_oversized_network_is_refused(self):
        with self.assertRaises(SystemExit):
            ifi.main(["--network", "10.0.0.0/8", "--no-public-ip"])

    def test_json_output_on_empty_subnet(self):
        import contextlib
        import io as _io
        import json
        buffer = _io.StringIO()
        with contextlib.redirect_stdout(buffer):
            ifi.main(["--network", "127.0.0.0/30", "--no-public-ip",
                      "--mdns-wait", "0.2", "--timeout", "0.05", "--json"])
        payload = json.loads(buffer.getvalue())
        self.assertEqual(payload["network"], "127.0.0.0/30")
        self.assertIsNone(payload["public_ip"])
        self.assertTrue(payload["public_ip_is_shared_via_nat"])
        self.assertIsInstance(payload["devices"], list)


if __name__ == "__main__":
    unittest.main(verbosity=2)
