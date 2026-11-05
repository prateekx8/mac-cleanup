"""Tests for macguard_capture: pcap reading, flow reassembly, protocol decoders, capture plumbing (no root needed)."""
import argparse
import io
import json
import os
import socket
import struct
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macguard as mg  # noqa: E402
import macguard_capture as cap  # noqa: E402
from test_macguard import TempHome  # noqa: E402

MAC = "192.168.1.10"
ESP = "192.168.1.50"
NET = "93.184.216.34"


def csum(b):
    if len(b) % 2:
        b += b"\0"
    s = sum(struct.unpack(f"!{len(b) // 2}H", b))
    s = (s >> 16) + (s & 0xFFFF)
    return ~(s + (s >> 16)) & 0xFFFF


def ip4(src, dst, proto, l4):
    h = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(l4), 1, 0, 64, proto, 0,
                    socket.inet_aton(src), socket.inet_aton(dst))
    return h[:10] + struct.pack("!H", csum(h)) + h[12:] + l4


def ip6(src, dst, proto, l4):
    return struct.pack("!IHBB", 0x60000000, len(l4), proto, 64) + socket.inet_pton(socket.AF_INET6, src) + \
        socket.inet_pton(socket.AF_INET6, dst) + l4


def tcp(sp, dp, seq, payload=b"", flags=0x18):
    return struct.pack("!HHIIBBHHH", sp, dp, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sp, dp, payload):
    return struct.pack("!HHHH", sp, dp, 8 + len(payload), 0) + payload


def eth(pkt, v6=False):
    return b"\x11" * 6 + b"\x22" * 6 + struct.pack("!H", 0x86DD if v6 else 0x0800) + pkt


def write_pcap(path, frames, link=1, nano=False, big=False):
    e = ">" if big else "<"
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    with open(path, "wb") as fh:
        fh.write(struct.pack(e + "IHHiIII", magic, 2, 4, 0, 0, 65535, link))
        for n, f in enumerate(frames):
            fh.write(struct.pack(e + "IIII", 1700000000 + n, 0, len(f), len(f)) + f)


def client_hello(sni, alpn=("h2",), tls13=True):
    ext = b""
    name = sni.encode()
    ext += struct.pack("!HH", 0, len(name) + 5) + struct.pack("!HBH", len(name) + 3, 0, len(name)) + name
    al = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
    ext += struct.pack("!HHH", 16, len(al) + 2, len(al)) + al
    if tls13:
        ext += struct.pack("!HH", 43, 3) + b"\x02\x03\x04"
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + struct.pack("!H", len(ext)) + ext
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def mqtt_connect(client, user=False):
    vh = struct.pack("!H", 4) + b"MQTT" + bytes([4, 0xC2 if user else 0x02]) + struct.pack("!H", 60)
    pl = struct.pack("!H", len(client)) + client.encode()
    if user:
        pl += struct.pack("!H", 3) + b"bob" + struct.pack("!H", 6) + b"hunter"
    body = vh + pl
    return bytes([0x10, len(body)]) + body


def mqtt_publish(topic, payload):
    body = struct.pack("!H", len(topic)) + topic.encode() + payload
    return bytes([0x30, len(body)]) + body


def dns_query(name, qid=1, answer=None):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    msg = struct.pack("!HHHHHH", qid, 0x8180 if answer else 0x0100, 1, 1 if answer else 0, 0, 0) + q
    if answer:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(answer)
    return msg


def coap_get(path, payload=b""):
    opts, last = b"", 0
    for seg in path.strip("/").split("/"):
        delta = 11 - last
        opts += bytes([(delta << 4) | len(seg)]) + seg.encode()
        last = 11
    return bytes([0x40, 0x01, 0x12, 0x34]) + opts + ((b"\xff" + payload) if payload else b"")


class TestPcapReading(TempHome):
    def setUp(self):
        super().setUp()
        self.pcap = os.path.join(self.tmp, "t.pcap")

    def flows(self, frames, **kw):
        write_pcap(self.pcap, frames, **kw)
        return cap.flows_from(self.pcap, mine={MAC})

    def test_http_flow_reassembled_out_of_order_with_retransmit(self):
        req = b"POST /api/led HTTP/1.1\r\nHost: esp32.local\r\nContent-Type: application/json\r\nAuthorization: Basic eDp5\r\n\r\n{\"on\":true}"
        a, b = req[:30], req[30:]
        frames = [eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1000, flags=0x02))),
                  eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1001 + len(a), b))),   # second half first
                  eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1001, a))),
                  eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1001, a))),              # retransmit
                  eth(ip4(ESP, MAC, 6, tcp(80, 50000, 5000, b"HTTP/1.1 200 OK\r\n\r\nok")))]
        fl = self.flows(frames)
        self.assertEqual(len(fl), 1)
        self.assertEqual((fl[0].client, fl[0].server, fl[0].sport), (MAC, ESP, 80))
        self.assertEqual(fl[0].stream("out"), req)
        d = cap.describe(fl[0], {"50000": {"proc": "curl", "pid": 9}})
        self.assertEqual(d["app"], "HTTP")
        self.assertEqual(d["process"], "curl")
        self.assertIn("POST esp32.local/api/led", d["details"][0])
        self.assertIn("credentials", d["details"][0])
        self.assertIn("response: 200 OK", d["details"])
        self.assertIn('{"on":true}', d["preview_out"]["text"])
        self.assertFalse(d["encrypted"])

    def test_tls_shows_sni_but_no_payload(self):
        fl = self.flows([eth(ip4(MAC, NET, 6, tcp(50001, 443, 1, client_hello("api.example.com"))))])
        d = cap.describe(fl[0], {})
        self.assertTrue(d["encrypted"])
        self.assertEqual(d["app"], "TLS 1.3")
        self.assertIn("api.example.com", d["details"][0])
        self.assertIn("h2", d["details"][0])
        self.assertEqual(d["preview_out"]["text"], "")

    def test_mqtt_connect_and_publish(self):
        data = mqtt_connect("esp32-kitchen", user=True) + mqtt_publish("home/kitchen/temp", b'{"c":21.5}')
        fl = self.flows([eth(ip4(MAC, ESP, 6, tcp(50002, 1883, 1, data)))])
        d = cap.describe(fl[0], {})
        self.assertEqual(d["app"], "MQTT")
        self.assertIn("CONNECT client esp32-kitchen · with username", d["details"])
        self.assertTrue(any(x.startswith("PUBLISH home/kitchen/temp") and "21.5" in x for x in d["details"]))

    def test_dns_and_mdns(self):
        fl = self.flows([eth(ip4(MAC, "192.168.1.1", 17, udp(53000, 53, dns_query("iot.example.com")))),
                         eth(ip4("192.168.1.1", MAC, 17, udp(53, 53000, dns_query("iot.example.com", answer="1.2.3.4"))))])
        d = cap.describe(fl[0], {})
        self.assertEqual(d["app"], "DNS")
        self.assertIn("? iot.example.com", d["details"])
        self.assertIn("iot.example.com -> 1.2.3.4", d["details"])

    def test_coap(self):
        fl = self.flows([eth(ip4(MAC, ESP, 17, udp(53001, 5683, coap_get("/sensors/temp", b"x"))))])
        d = cap.describe(fl[0], {})
        self.assertEqual(d["app"], "CoAP")
        self.assertEqual(d["details"][0], "GET /sensors/temp · x")

    def test_ipv6_loopback_raw_and_nanosecond_bigendian(self):
        v6 = ip6("fe80::1", "fe80::2", 6, tcp(50003, 8080, 1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
        self.assertEqual(cap.describe(self.flows([eth(v6, v6=True)], nano=True, big=True)[0], {})["app"], "HTTP")
        lo = struct.pack("<I", 2) + ip4("127.0.0.1", "127.0.0.1", 17, udp(5000, 6000, b"hello"))
        self.assertEqual(self.flows([lo], link=0)[0].stream("out"), b"hello")
        self.assertEqual(self.flows([ip4(MAC, ESP, 17, udp(1, 2, b"raw"))], link=101)[0].stream("out"), b"raw")

    def test_binary_payload_gets_hex_preview(self):
        fl = self.flows([eth(ip4(MAC, ESP, 17, udp(40000, 9999, bytes(range(40)))))])
        d = cap.describe(fl[0], {})
        self.assertEqual(d["preview_out"]["kind"], "hex")
        self.assertTrue(d["preview_out"]["text"].startswith("0000  00 01 02"))

    def test_bad_files(self):
        with open(self.pcap, "wb") as fh:
            fh.write(b"\x0a\x0d\x0d\x0a" + b"\0" * 40)
        with self.assertRaisesRegex(ValueError, "pcapng"):
            list(cap.read_pcap(self.pcap))
        with open(self.pcap, "wb") as fh:
            fh.write(b"nope" * 10)
        with self.assertRaisesRegex(ValueError, "not a pcap"):
            list(cap.read_pcap(self.pcap))
        with open(self.pcap, "wb") as fh:  # truncated record is ignored, not a crash
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + b"\0" * 10)
        self.assertEqual(list(cap.read_pcap(self.pcap)), [])
        self.assertIsNone(cap.tls_hello(b"\x16\x03\x01\x00\x10\x01garbage"))


class TestCaptureFlow(TempHome):
    def setUp(self):
        super().setUp()
        self.dir = os.path.join(self.home, ".macguard", "captures")
        for p in (mock.patch.object(cap, "CAPTURE_DIR", self.dir),
                  mock.patch.object(cap, "KEYLOG", os.path.join(self.home, ".macguard", "sslkeys.log")),
                  mock.patch.object(cap, "interfaces", lambda: ["lo0", "en0"]),
                  mock.patch.object(cap, "default_iface", lambda: "en0"),
                  mock.patch.object(cap, "local_addrs", lambda: {MAC}),
                  mock.patch.object(mg, "sockets", lambda: [dict(lport=50002, proc="mosquitto_pub", pid=42)])):
            p.start()
            self.addCleanup(p.stop)
        self.scripts = []

    def fake_admin(self, frames):
        def run(script, reason):
            self.scripts.append((script, reason))
            path = script.split(" -w ")[1].split(" ")[0].strip("'")
            write_pcap(path, frames)
            return True, ""
        return run

    def test_filter_building_and_validation(self):
        self.assertEqual(cap.build_filter(), "")
        self.assertEqual(cap.build_filter("all", host=ESP, port=1883), f"host {ESP} and port 1883")
        self.assertTrue(cap.build_filter("local").startswith("(net 10.0.0.0/8"))
        for bad in (dict(host="1.2.3.4; rm -rf ~"), dict(custom="port 80 `id`"), dict(custom="$(id)"),
                    dict(port=70000), dict(preset="nope")):
            with self.assertRaises(ValueError):
                cap.build_filter(**bad)

    def test_script_quotes_everything(self):
        s = cap.capture_script("en0", 5, "host 1.2.3.4 and port 80", "/x y/z.pcap", 501)
        self.assertIn("-w '/x y/z.pcap' 'host 1.2.3.4 and port 80'", s)
        self.assertIn("chown 501", s)
        self.assertIn("-lt 5 ]", s)

    def test_capture_saves_meta_maps_processes_and_analyzes(self):
        frames = [eth(ip4(MAC, NET, 6, tcp(50002, 1883, 1, mqtt_connect("dev", user=True) + mqtt_publish("t", b"v"))))]
        with mock.patch.object(cap, "run_as_admin", self.fake_admin(frames)):
            meta = cap.capture(3, preset="all", host=NET)
        self.assertIn("en0", self.scripts[0][1])
        self.assertIn(f"host {NET}", self.scripts[0][0])
        self.assertEqual(meta["ports"]["50002"]["proc"], "mosquitto_pub")
        self.assertEqual(cap.list_captures()[0]["id"], meta["id"])
        rep = cap.analyze(cid=meta["id"])
        self.assertEqual(rep["flows"], 1)
        self.assertEqual(rep["items"][0]["process"], "mosquitto_pub")
        titles = [f["title"] for f in rep["findings"]]
        self.assertIn("Unencrypted MQTT to the internet", titles)
        self.assertTrue(cap.flow_bytes(meta["id"], 0, "out").startswith(b"\x10\x1c\x00\x04MQTT"))
        self.assertIn("capture", open(mg.EVENTS_LOG).read())

    def test_capture_errors(self):
        with self.assertRaisesRegex(ValueError, "no interface"):
            cap.capture(3, iface="bogus0")
        with mock.patch.object(cap, "run_as_admin", lambda s, r: (False, "cancelled")):
            with self.assertRaisesRegex(RuntimeError, "cancelled"):
                cap.capture(3)
        with mock.patch.object(cap, "run_as_admin", lambda s, r: (True, "")):
            with self.assertRaisesRegex(RuntimeError, "wrote nothing"):
                cap.capture(3)
        for bad in ("../x", "20260101-000000", ""):
            with self.assertRaises((ValueError, FileNotFoundError)):
                cap.capture_path(bad)

    def test_prune_keeps_newest(self):
        os.makedirs(self.dir)
        for n in range(5):
            write_pcap(os.path.join(self.dir, f"2026010{n + 1}-000000.pcap"), [])
        cap.prune(keep=2)
        self.assertEqual([c["id"] for c in cap.list_captures()], ["20260105-000000", "20260104-000000"])

    def test_cli_show_and_file(self):
        frames = [eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1, b"GET /status HTTP/1.1\r\nHost: esp\r\n\r\n")))]
        path = os.path.join(self.tmp, "x.pcap")
        write_pcap(path, frames)
        args = argparse.Namespace(list=False, show=None, file=path, payload=True, limit=5)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cap.cmd_capture(args)
        out = buf.getvalue()
        self.assertIn("1 flows", out)
        self.assertIn("GET esp/status", out)
        self.assertIn("sent:", out)
        with redirect_stdout(io.StringIO()) as b2:
            cap.cmd_capture(argparse.Namespace(list=True))
        self.assertIn("SSLKEYLOGFILE", b2.getvalue())

    def test_mcp_tools(self):
        import macguard_mcp as mcp
        self.assertIn("SSLKEYLOGFILE", json.dumps(mcp.t_capture_list({})))
        with self.assertRaisesRegex(ValueError, "confirm"):
            mcp.t_packet_capture({})
        frames = [eth(ip4(MAC, ESP, 6, tcp(50000, 80, 1, b"GET /a HTTP/1.1\r\nHost: esp\r\n\r\n")))]
        with mock.patch.object(cap, "run_as_admin", self.fake_admin(frames)):
            r = mcp.t_packet_capture({"confirm": True, "seconds": 2, "preset": "local"})
        rep = mcp.t_capture_analyze({"id": r["id"], "payloads": False})
        self.assertEqual(rep["items"][0]["app"], "HTTP")
        self.assertEqual(rep["items"][0]["preview_out"]["text"], "")
        names = {t[0] for t in mcp.TOOLS}
        self.assertTrue({"capture_list", "capture_analyze", "packet_capture"} <= names)


if __name__ == "__main__":
    unittest.main()
