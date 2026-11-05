"""Packet capture for macguard: record what this Mac sends and receives, then read it back.

Capturing needs root (macOS keeps /dev/bpf* root-only), so tcpdump runs behind the normal macOS admin
password dialog (or sudo on a terminal). Reading is pure stdlib: pcap -> IPv4/IPv6 -> TCP/UDP flows,
with plaintext decoded (HTTP, MQTT, DNS/mDNS, CoAP, SSDP, raw text) and TLS reduced to the server
name it asked for. TLS contents are not decrypted here; export the pcap plus an SSLKEYLOGFILE to
Wireshark for that (see KEYLOG).
"""
import datetime as dt
import ipaddress
import json
import os
import re
import shlex
import socket
import struct
import subprocess
import threading
import time

import macguard as mg

CAPTURE_DIR = os.path.join(mg.STATE_DIR, "captures")
KEYLOG = os.path.join(mg.STATE_DIR, "sslkeys.log")
KEEP_CAPTURES = 20
MAX_SECONDS = 300
MAX_PACKETS = 200000
STREAM_KEEP = 256 << 10   # bytes of payload kept per flow direction
PREVIEW = 4096            # bytes shown per direction
LOCAL_NETS = "net 10.0.0.0/8 or net 172.16.0.0/12 or net 192.168.0.0/16 or net 169.254.0.0/16 or net fe80::/10"
PRESETS = {"all": "", "local": LOCAL_NETS, "plaintext": "port 80 or port 1883 or port 5683 or port 53 or port 5353 "
           "or port 1900 or port 23 or port 21 or port 8080"}
FILTER_OK = re.compile(r"^[A-Za-z0-9 .:/_()!&|<>=-]{0,300}$")
HOST_OK = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")
HTTP_START = re.compile(rb"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT|HTTP/1\.[01]) ")


# ---------- capturing ----------

def build_filter(preset="all", host=None, port=None, custom=None):
    parts = []
    if preset not in PRESETS:
        raise ValueError(f"unknown preset {preset!r}")
    if PRESETS[preset]:
        parts.append(f"({PRESETS[preset]})")
    if host:
        if not HOST_OK.match(host):
            raise ValueError("bad host")
        parts.append(f"host {host}")
    if port:
        port = int(port)
        if not 0 < port < 65536:
            raise ValueError("bad port")
        parts.append(f"port {port}")
    if custom:
        if not FILTER_OK.match(custom):
            raise ValueError("filter has characters tcpdump filters never need")
        parts.append(f"({custom})")
    return " and ".join(parts)


def interfaces():
    _, out, _ = mg.run(["ifconfig", "-l"])
    return out.split()


def default_iface():
    return mg.gateway()[1] or "en0"


def capture_script(iface, seconds, filt, path, uid):
    """Shell run as root: tcpdump for `seconds` (or until MAX_PACKETS), then hand the file to the user."""
    q = shlex.quote
    return (f"/usr/sbin/tcpdump -i {q(iface)} -s 0 -U -n -c {MAX_PACKETS} -w {q(path)} {q(filt)} 2>{q(path + '.err')} & p=$!; "
            f"i=0; while [ $i -lt {int(seconds)} ] && kill -0 $p 2>/dev/null; do sleep 1; i=$((i+1)); done; "
            f"kill -INT $p 2>/dev/null; wait $p; "
            f"chown {int(uid)} {q(path)} {q(path + '.err')} 2>/dev/null; chmod 600 {q(path)} 2>/dev/null; true")


def run_as_admin(script, reason):
    """Root via the user's own approval: already root, sudo on a terminal, else the macOS password dialog."""
    if os.geteuid() == 0:
        return subprocess.run(["/bin/sh", "-c", script]).returncode == 0, ""
    if os.isatty(0):
        r = subprocess.run(["sudo", "/bin/sh", "-c", script])
        return r.returncode == 0, "" if r.returncode == 0 else "sudo failed"
    esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')
    osa = f'do shell script "{esc(script)}" with prompt "{esc(reason)}" with administrator privileges'
    r = subprocess.run(["osascript", "-e", osa], capture_output=True, text=True)
    if r.returncode != 0:
        return False, "cancelled" if "-128" in r.stderr else (r.stderr.strip() or "admin prompt failed")
    return True, ""


def capture(seconds=30, iface=None, preset="all", host=None, port=None, custom=None, note=""):
    """Record packets; returns the capture's metadata (id, file, filter, processes seen)."""
    seconds = max(1, min(MAX_SECONDS, int(seconds)))
    iface = iface or default_iface()
    if iface not in interfaces():
        raise ValueError(f"no interface {iface!r}")
    filt = build_filter(preset, host, port, custom)
    os.makedirs(CAPTURE_DIR, mode=0o700, exist_ok=True)
    cid = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(CAPTURE_DIR, cid + ".pcap")
    # map local ports to processes while tcpdump runs (packets carry no process info)
    ports, stop = {}, threading.Event()

    def watch():
        while not stop.is_set():
            for s in mg.sockets():
                if s["lport"] and s["proc"]:
                    ports[str(s["lport"])] = {"proc": s["proc"], "pid": s["pid"]}
            stop.wait(1)
    t = threading.Thread(target=watch, daemon=True)
    t.start()
    started = time.time()
    try:
        ok, err = run_as_admin(capture_script(iface, seconds, filt, path, os.getuid()),
                               f"Mac Cleanup wants to capture network packets on {iface} for {seconds} seconds.")
    finally:
        stop.set()
        t.join(5)
    errfile = path + ".err"
    tcpdump_err = ""
    if os.path.exists(errfile):
        with open(errfile) as fh:
            tcpdump_err = fh.read().strip()
        os.remove(errfile)
    if not ok:
        raise RuntimeError(err)
    if not os.path.exists(path) or os.path.getsize(path) < 24:
        msg = [l for l in tcpdump_err.splitlines() if "listening on" not in l and "packets" not in l]
        raise RuntimeError("tcpdump wrote nothing" + (f": {msg[-1]}" if msg else ""))
    meta = {"id": cid, "file": path, "iface": iface, "filter": filt, "seconds": seconds, "note": note,
            "started": started, "ports": ports, "size": os.path.getsize(path)}
    with open(path[:-5] + ".json", "w") as fh:
        json.dump(meta, fh)
    os.chmod(path[:-5] + ".json", 0o600)
    mg.log_event("capture", f"{cid} {iface} {seconds}s filter={filt or 'all'} {mg.human(meta['size'])}")
    prune()
    return meta


def prune(keep=KEEP_CAPTURES):
    for c in list_captures()[keep:]:
        for ext in (".pcap", ".json"):
            p = os.path.join(CAPTURE_DIR, c["id"] + ext)
            if os.path.exists(p):
                os.remove(p)


def list_captures():
    if not os.path.isdir(CAPTURE_DIR):
        return []
    out = []
    for f in sorted(os.listdir(CAPTURE_DIR), reverse=True):
        if not f.endswith(".pcap"):
            continue
        cid = f[:-5]
        meta = load_meta(cid)
        out.append({"id": cid, "size": os.path.getsize(os.path.join(CAPTURE_DIR, f)), "iface": meta.get("iface"),
                    "filter": meta.get("filter", ""), "seconds": meta.get("seconds"), "note": meta.get("note", ""),
                    "started": meta.get("started")})
    return out


def capture_path(cid):
    if not re.fullmatch(r"[0-9]{8}-[0-9]{6}", cid or ""):
        raise ValueError("bad capture id")
    p = os.path.join(CAPTURE_DIR, cid + ".pcap")
    if not os.path.exists(p):
        raise FileNotFoundError(cid)
    return p


def load_meta(cid):
    try:
        with open(os.path.join(CAPTURE_DIR, cid + ".json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def keylog_status():
    return {"path": KEYLOG, "exists": os.path.exists(KEYLOG),
            "size": os.path.getsize(KEYLOG) if os.path.exists(KEYLOG) else 0,
            "how": f"Start the program with SSLKEYLOGFILE={KEYLOG} (curl, Python, Chrome, Firefox and Node honor it), "
                   "capture, then open the pcap in Wireshark with that file under TLS > (Pre)-Master-Secret log."}


# ---------- reading ----------

def read_pcap(path):
    """Yields (ts, linktype, frame) from a classic pcap file (micro- or nanosecond, either byte order)."""
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 24:
            return
        magic = head[:4]
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        elif magic == b"\x0a\x0d\x0d\x0a":
            raise ValueError("pcapng is not supported; save as classic pcap (tcpdump -w does by default)")
        else:
            raise ValueError("not a pcap file")
        div = 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d") else 1e6
        link = struct.unpack(e + "I", head[20:24])[0] & 0x0FFFFFFF
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            sec, frac, caplen, _ = struct.unpack(e + "IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield sec + frac / div, link, data


def l3(link, frame):
    """Strips the link header: returns (ethertype-ish 4|6, ip packet) or None."""
    if link == 1:  # Ethernet
        if len(frame) < 14:
            return None
        et, off = struct.unpack("!H", frame[12:14])[0], 14
        while et in (0x8100, 0x88A8) and len(frame) >= off + 4:  # VLAN tags
            et, off = struct.unpack("!H", frame[off + 2:off + 4])[0], off + 4
        return {0x0800: 4, 0x86DD: 6}.get(et) and ({0x0800: 4, 0x86DD: 6}[et], frame[off:])
    if link in (0, 108):  # BSD loopback: 4-byte address family, host or network order
        if len(frame) < 4:
            return None
        fam = struct.unpack("<I", frame[:4])[0]
        fam = fam if fam < 256 else struct.unpack(">I", frame[:4])[0]
        return (4, frame[4:]) if fam == 2 else (6, frame[4:]) if fam in (24, 28, 30) else None
    if link in (12, 14, 101):  # raw IP
        v = frame[0] >> 4 if frame else 0
        return (v, frame) if v in (4, 6) else None
    return None


def ip_parse(ver, pkt):
    """(src, dst, proto, l4 bytes) or None."""
    if ver == 4 and len(pkt) >= 20:
        ihl = (pkt[0] & 15) * 4
        total = struct.unpack("!H", pkt[2:4])[0] or len(pkt)
        if struct.unpack("!H", pkt[6:8])[0] & 0x1FFF:  # later fragment: no ports in it
            return None
        return socket.inet_ntop(socket.AF_INET, pkt[12:16]), socket.inet_ntop(socket.AF_INET, pkt[16:20]), pkt[9], pkt[ihl:total]
    if ver == 6 and len(pkt) >= 40:
        nxt, off = pkt[6], 40
        plen = struct.unpack("!H", pkt[4:6])[0]
        end = 40 + plen if plen else len(pkt)
        while nxt in (0, 43, 60, 44) and len(pkt) >= off + 8:
            if nxt == 44:
                if struct.unpack("!H", pkt[off + 2:off + 4])[0] & 0xFFF8:
                    return None
                nxt, off = pkt[off], off + 8
            else:
                nxt, off = pkt[off], off + (pkt[off + 1] + 1) * 8
        return socket.inet_ntop(socket.AF_INET6, pkt[8:24]), socket.inet_ntop(socket.AF_INET6, pkt[24:40]), nxt, pkt[off:end]
    return None


def local_addrs():
    _, out, _ = mg.run(["ifconfig"])
    return {a.split("%")[0] for a in re.findall(r"inet6? (\S+)", out)}


class Flow:
    def __init__(self, proto, client, cport, server, sport, ts):
        self.proto, self.client, self.cport, self.server, self.sport = proto, client, cport, server, sport
        self.first = self.last = ts
        self.packets = {"out": 0, "in": 0}
        self.bytes = {"out": 0, "in": 0}
        self.segs = {"out": {}, "in": {}}      # tcp: seq -> payload
        self.dgrams = {"out": [], "in": []}    # udp: payloads in order
        self.kept = {"out": 0, "in": 0}

    def add(self, d, ts, payload, seq=None):
        self.last = ts
        self.packets[d] += 1
        self.bytes[d] += len(payload)
        if not payload or self.kept[d] >= STREAM_KEEP:
            return
        if seq is None:
            self.dgrams[d].append(payload)
        elif seq not in self.segs[d]:  # retransmits share a seq
            self.segs[d][seq] = payload
        else:
            return
        self.kept[d] += len(payload)

    def stream(self, d):
        if self.proto == "udp":
            return b"".join(self.dgrams[d])[:STREAM_KEEP]
        out, nxt = bytearray(), None
        for seq in sorted(self.segs[d], key=lambda s: (s - min(self.segs[d])) % (1 << 32)):
            data = self.segs[d][seq]
            if nxt is not None:
                skip = (nxt - seq) % (1 << 32)
                if skip < len(data):
                    data = data[skip:]
                elif skip < (1 << 31):
                    continue
            out += data
            nxt = (seq + len(self.segs[d][seq])) % (1 << 32)
        return bytes(out[:STREAM_KEEP])


def flows_from(path, mine=None):
    mine = local_addrs() if mine is None else mine
    flows, order = {}, []
    for ts, link, frame in read_pcap(path):
        x = l3(link, frame)
        p = x and ip_parse(*x)
        if not p:
            continue
        src, dst, proto, l4 = p
        if proto == 6 and len(l4) >= 20:
            sp, dp, seq = struct.unpack("!HHI", l4[:8])
            flags = l4[13]
            payload, name = l4[(l4[12] >> 4) * 4:], "tcp"
        elif proto == 17 and len(l4) >= 8:
            sp, dp = struct.unpack("!HH", l4[:4])
            seq, flags, payload, name = None, 0, l4[8:], "udp"
        else:
            continue
        key = (name,) + tuple(sorted([(src, sp), (dst, dp)]))
        f = flows.get(key)
        if f is None:
            # client = this Mac's side, else whoever sent a SYN, else the first sender unless it answers from a service port
            if src in mine and dst not in mine:
                c = True
            elif dst in mine and src not in mine:
                c = False
            elif name == "tcp" and flags & 0x12 == 0x02:
                c = True
            elif name == "tcp" and flags & 0x12 == 0x12:
                c = False
            else:
                c = not (sp < 1024 <= dp)
            f = flows[key] = Flow(name, *((src, sp, dst, dp) if c else (dst, dp, src, sp)), ts)
            order.append(f)
        f.add("out" if (src, sp) == (f.client, f.cport) else "in", ts, payload, seq)
    return order


# ---------- protocol decoders ----------

def text_preview(b, n=PREVIEW):
    b = b[:n]
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in b)
    if b and printable / len(b) > 0.85:
        return "text", b.decode("utf-8", "replace")
    lines = []
    for i in range(0, min(len(b), 512), 16):
        chunk = b[i:i + 16]
        lines.append(f"{i:04x}  {chunk.hex(' '):<47}  " + "".join(chr(c) if 32 <= c < 127 else "." for c in chunk))
    return "hex", "\n".join(lines)


def tls_hello(b):
    """(sni, alpn list, tls version label) from a ClientHello at the start of a stream, else None."""
    try:
        if len(b) < 43 or b[0] != 0x16 or b[5] != 1:
            return None
        p = 9 + 2 + 32
        p += 1 + b[p]
        p += 2 + struct.unpack("!H", b[p:p + 2])[0]
        p += 1 + b[p]
        end = p + 2 + struct.unpack("!H", b[p:p + 2])[0]
        p += 2
        sni, alpn, ver = None, [], "TLS 1.2"
        while p + 4 <= end and p + 4 <= len(b):
            et, el = struct.unpack("!HH", b[p:p + 4])
            v = b[p + 4:p + 4 + el]
            if et == 0 and len(v) > 5:
                sni = v[5:5 + struct.unpack("!H", v[3:5])[0]].decode("ascii", "replace")
            elif et == 16 and len(v) > 2:
                i = 2
                while i < len(v):
                    alpn.append(v[i + 1:i + 1 + v[i]].decode("ascii", "replace"))
                    i += 1 + v[i]
            elif et == 43 and b"\x03\x04" in v:
                ver = "TLS 1.3"
            p += 4 + el
        return sni, alpn, ver
    except (IndexError, struct.error):
        return None


def mqtt_messages(b, limit=40):
    """Decodes MQTT 3.1/3.1.1/5 control packets (CONNECT client id, PUBLISH topic+payload, SUBSCRIBE topics)."""
    out, p = [], 0
    names = {1: "CONNECT", 2: "CONNACK", 3: "PUBLISH", 4: "PUBACK", 8: "SUBSCRIBE", 9: "SUBACK", 10: "UNSUBSCRIBE",
             12: "PINGREQ", 13: "PINGRESP", 14: "DISCONNECT"}
    while p < len(b) and len(out) < limit:
        typ, mult, rem, i = b[p] >> 4, 1, 0, p + 1
        while i < len(b):
            rem += (b[i] & 127) * mult
            mult *= 128
            i += 1
            if not b[i - 1] & 128 or mult > 128 ** 3:
                break
        body = b[i:i + rem]
        if typ not in names or len(body) < rem:
            break
        msg = {"type": names[typ]}
        try:
            if typ == 1:
                pl = struct.unpack("!H", body[:2])[0]
                lvl = body[2 + pl]
                q = 2 + pl + 4
                if lvl == 5:
                    q += 1 + body[q]  # properties length (single byte is enough for CONNECT in practice)
                cl = struct.unpack("!H", body[q:q + 2])[0]
                msg["client_id"] = body[q + 2:q + 2 + cl].decode("utf-8", "replace")
                msg["user"] = bool(body[2 + pl + 1] & 0x80)
            elif typ == 3:
                tl = struct.unpack("!H", body[:2])[0]
                msg["topic"] = body[2:2 + tl].decode("utf-8", "replace")
                q = 2 + tl + (2 if (b[p] >> 1) & 3 else 0)
                msg["payload"] = text_preview(body[q:], 1024)[1]
            elif typ == 8:
                q, topics = 2, []
                while q + 2 <= len(body):
                    tl = struct.unpack("!H", body[q:q + 2])[0]
                    topics.append(body[q + 2:q + 2 + tl].decode("utf-8", "replace"))
                    q += 3 + tl
                msg["topics"] = topics
        except (IndexError, struct.error):
            pass
        out.append(msg)
        p = i + rem
    return out


def dns_names(msg):
    """Question names and A/AAAA answers from one DNS/mDNS message."""
    def name(p, depth=0):
        labels = []
        while p < len(msg) and depth < 20:
            n = msg[p]
            if n == 0:
                return ".".join(labels), p + 1
            if n & 0xC0 == 0xC0:
                return ".".join(labels + [name(((n & 0x3F) << 8) | msg[p + 1], depth + 1)[0]]), p + 2
            labels.append(msg[p + 1:p + 1 + n].decode("ascii", "replace"))
            p += 1 + n
        return ".".join(labels), p
    try:
        qd, an = struct.unpack("!HH", msg[4:8])
        p, qs, ans = 12, [], []
        for _ in range(min(qd, 20)):
            n, p = name(p)
            qs.append(n)
            p += 4
        for _ in range(min(an, 30)):
            n, p = name(p)
            t, _, _, ln = struct.unpack("!HHIH", msg[p:p + 10])
            rd = msg[p + 10:p + 10 + ln]
            if t == 1 and ln == 4:
                ans.append(f"{n} -> {socket.inet_ntop(socket.AF_INET, rd)}")
            elif t == 28 and ln == 16:
                ans.append(f"{n} -> {socket.inet_ntop(socket.AF_INET6, rd)}")
            p += 10 + ln
        return qs, ans
    except (IndexError, struct.error, ValueError):
        return [], []


def coap_message(b):
    if len(b) < 4 or b[0] >> 6 != 1:
        return None
    tkl, code = b[0] & 15, b[1]
    p, opt, path = 4 + tkl, 0, []
    while p < len(b) and b[p] != 0xFF:
        delta, ln = b[p] >> 4, b[p] & 15
        p += 1
        if delta == 13:
            delta, p = b[p] + 13, p + 1
        if ln == 13:
            ln, p = b[p] + 13, p + 1
        opt += delta
        if opt == 11:
            path.append(b[p:p + ln].decode("utf-8", "replace"))
        p += ln
    payload = b[p + 1:] if p < len(b) else b""
    cls = f"{code >> 5}.{code & 31:02d}"
    method = {"0.01": "GET", "0.02": "POST", "0.03": "PUT", "0.04": "DELETE"}.get(cls, cls)
    return {"code": method, "path": "/" + "/".join(path), "payload": text_preview(payload, 512)[1] if payload else ""}


def http_requests(b, limit=20):
    out = []
    for m in re.finditer(rb"(?m)^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) (\S+) HTTP/1\.[01]\r\n((?:[^\r\n]+\r\n)*)", b):
        hdrs = dict((k.strip().lower(), v.strip()) for k, _, v in
                    (l.decode("latin-1").partition(":") for l in m.group(3).split(b"\r\n") if l))
        out.append({"method": m.group(1).decode(), "path": m.group(2).decode("latin-1"), "host": hdrs.get("host", ""),
                    "type": hdrs.get("content-type", ""), "length": hdrs.get("content-length", ""),
                    "auth": "authorization" in hdrs or "cookie" in hdrs})
        if len(out) >= limit:
            break
    return out


def describe(f, procs):
    """One flow as JSON: who, how much, which protocol, and what was said (when it is readable)."""
    o, i = f.stream("out"), f.stream("in")
    first_out = f.dgrams["out"][0] if f.proto == "udp" and f.dgrams["out"] else o
    first_in = f.dgrams["in"][0] if f.proto == "udp" and f.dgrams["in"] else i
    ports = {f.cport, f.sport}
    app, details, encrypted = f.proto.upper(), [], False
    hello = tls_hello(o)
    if hello or (o[:1] == b"\x16" and o[1:2] == b"\x03") or (i[:1] in (b"\x16", b"\x17") and i[1:2] == b"\x03"):
        sni, alpn, ver = hello or (None, [], "TLS")
        app, encrypted = ver, True
        details.append(f"server name: {sni or '(none sent)'}" + (f" · ALPN {', '.join(alpn)}" if alpn else ""))
    elif HTTP_START.match(o) or HTTP_START.match(i):
        app = "HTTP"
        for r in http_requests(o):
            details.append(f"{r['method']} {r['host']}{r['path']}" + (f" · {r['type']}" if r['type'] else "") +
                           (" · sends credentials/cookies" if r["auth"] else ""))
        st = re.match(rb"HTTP/1\.[01] (\d+ [^\r\n]*)", i)
        if st:
            details.append("response: " + st.group(1).decode("latin-1"))
    elif f.proto == "udp" and ports & {53, 5353}:
        app = "mDNS" if 5353 in ports else "DNS"
        seen = []
        for d in f.dgrams["out"] + f.dgrams["in"]:
            qs, ans = dns_names(d)
            seen += [f"? {q}" for q in qs] + ans
        details += list(dict.fromkeys(seen))[:30]
    elif f.proto == "udp" and ports & {5683, 5684}:
        app = "CoAP" if 5683 in ports else "CoAP/DTLS"
        encrypted = 5684 in ports
        for d in (f.dgrams["out"] + f.dgrams["in"])[:20]:
            m = coap_message(d)
            if m:
                details.append(f"{m['code']} {m['path']}" + (f" · {m['payload'][:120]}" if m["payload"] else ""))
    elif f.proto == "tcp" and (ports & {1883} or o[:1] == b"\x10" and b"MQTT" in o[:16]):
        app = "MQTT"
        for m in mqtt_messages(o) + mqtt_messages(i):
            if m["type"] == "CONNECT":
                details.append(f"CONNECT client {m.get('client_id', '?')}" + (" · with username" if m.get("user") else ""))
            elif m["type"] == "PUBLISH":
                details.append(f"PUBLISH {m.get('topic', '?')} · {m.get('payload', '')[:160]}")
            elif m["type"] == "SUBSCRIBE":
                details.append("SUBSCRIBE " + ", ".join(m.get("topics", [])))
    elif f.proto == "tcp" and ports & {8883, 443, 993, 995, 465, 22}:
        encrypted, app = True, {22: "SSH", 8883: "MQTT/TLS"}.get(min(ports & {22, 8883}, default=0), "TLS")
    elif f.proto == "udp" and ports & {1900}:
        app = "SSDP"
        details += [l for l in first_out.decode("latin-1").splitlines()[:6] if l]
    elif f.proto == "udp" and ports & {443}:
        app, encrypted = "QUIC", True
    side = procs.get(str(f.cport)) or procs.get(str(f.sport)) or {}
    kind_o, prev_o = text_preview(first_out if f.proto == "udp" else o)
    kind_i, prev_i = text_preview(first_in if f.proto == "udp" else i)
    try:
        private = ipaddress.ip_address(f.server).is_private
    except ValueError:
        private = False
    return {"proto": f.proto, "app": app, "client": f.client, "cport": f.cport, "server": f.server, "sport": f.sport,
            "local_network": private, "process": side.get("proc") or "", "pid": side.get("pid"),
            "packets_out": f.packets["out"], "packets_in": f.packets["in"], "bytes_out": f.bytes["out"],
            "bytes_in": f.bytes["in"], "start": f.first, "duration": round(f.last - f.first, 3),
            "encrypted": encrypted, "details": details[:30],
            "preview_out": {"kind": kind_o, "text": "" if encrypted else prev_o},
            "preview_in": {"kind": kind_i, "text": "" if encrypted else prev_i}}


def analyze(cid=None, path=None, limit=200):
    """Flows of a saved capture (by id) or any classic pcap file, biggest/most readable first."""
    path = path or capture_path(cid)
    meta = load_meta(cid) if cid else {}
    flows = flows_from(path)
    rows = [dict(describe(f, meta.get("ports", {})), id=n) for n, f in enumerate(flows)]
    readable = [r for r in rows if not r["encrypted"] and (r["details"] or r["bytes_out"] + r["bytes_in"])]
    findings = []
    for r in rows:
        who = r["process"] or f"{r['client']}:{r['cport']}"
        if r["app"] == "HTTP" and any("credentials" in d for d in r["details"]):
            findings.append(("high", "Credentials sent in plaintext", f"{who} -> {r['server']}:{r['sport']} over HTTP"))
        elif r["app"] in ("HTTP", "MQTT", "CoAP") and not r["local_network"]:
            findings.append(("medium", f"Unencrypted {r['app']} to the internet", f"{who} -> {r['server']}:{r['sport']}"))
        elif r["app"] == "MQTT" and any("username" in d for d in r["details"]):
            findings.append(("medium", "MQTT login without TLS", f"{who} -> {r['server']}:{r['sport']} (password readable)"))
    apps = {}
    for r in rows:
        apps[r["app"]] = apps.get(r["app"], 0) + 1
    rows.sort(key=lambda r: (r["encrypted"], -(r["bytes_out"] + r["bytes_in"])))
    return {"id": cid, "file": path, "filter": meta.get("filter", ""), "iface": meta.get("iface"),
            "flows": len(rows), "readable": len(readable), "protocols": apps,
            "bytes": sum(r["bytes_out"] + r["bytes_in"] for r in rows),
            "findings": mg.findings_json(findings), "keylog": keylog_status(), "items": rows[:limit]}


def flow_bytes(cid, flow_id, direction):
    """Raw reassembled payload of one flow direction, for download."""
    flows = flows_from(capture_path(cid))
    if not 0 <= flow_id < len(flows) or direction not in ("out", "in"):
        raise ValueError("no such flow")
    return flows[flow_id].stream(direction)


# ---------- CLI ----------

def cmd_capture(args):
    if args.list:
        for c in list_captures():
            print(f"{c['id']}  {mg.human(c['size']):>7}  {c['iface'] or '?':<6} {c['seconds'] or '?'}s  {c['filter'] or 'all traffic'}")
        print(f"\nKey log for TLS decryption in Wireshark: {keylog_status()['how']}")
        return
    if args.file or args.show:
        rep = analyze(cid=args.show, path=args.file)
    else:
        print(f"Capturing {args.seconds}s on {args.iface or default_iface()} (asks for your admin password)...", flush=True)
        meta = capture(args.seconds, args.iface, args.preset, args.host, args.port, args.filter)
        print(f"Saved {meta['file']} ({mg.human(meta['size'])})")
        rep = analyze(cid=meta["id"])
    print(f"\n{rep['flows']} flows · {rep['readable']} readable · {mg.human(rep['bytes'])} · "
          + ", ".join(f"{k} {v}" for k, v in sorted(rep["protocols"].items(), key=lambda x: -x[1])))
    for f in rep["findings"]:
        print(f"  {f['sev'].upper():<6} {f['title']}: {f['detail']}")
    for r in rep["items"][:args.limit]:
        lock = "🔒" if r["encrypted"] else "  "
        print(f"\n{lock}#{r['id']:<3} {r['app']:<7} {r['process'] or '?':<18} {r['client']}:{r['cport']} -> {r['server']}:{r['sport']}"
              f"  ↑{mg.human(r['bytes_out'])} ↓{mg.human(r['bytes_in'])}")
        for d in r["details"][:6]:
            print(f"        {d}")
        if args.payload and r["preview_out"]["text"]:
            print("        sent:\n" + "\n".join("          " + l for l in r["preview_out"]["text"][:800].splitlines()))
