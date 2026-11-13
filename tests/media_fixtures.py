"""Synthetic media built byte by byte for the Tools tests. Never real photos, voices or disks."""
import struct
import zlib

IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"


# ---------------------------------------------------------------- CBOR / JUMBF / C2PA

def cbor(v):
    def head(major, n):
        if n < 24:
            return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size):
                return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if v is None:
        return b"\xf6"
    if isinstance(v, int):
        return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, float):
        return b"\xfb" + struct.pack(">d", v)
    if isinstance(v, bytes):
        return head(2, len(v)) + v
    if isinstance(v, str):
        e = v.encode()
        return head(3, len(e)) + e
    if isinstance(v, list):
        return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(v)


def box(typ, payload):
    return struct.pack(">I", 8 + len(payload)) + typ + payload


def superbox(label, *children, uuid=b"\x00" * 16):
    jumd = box(b"jumd", uuid + b"\x03" + label.encode() + b"\x00")
    return box(b"jumb", jumd + b"".join(children))


def c2pa_store(source="trainedAlgorithmicMedia", generator="TestGen 1.0", action="c2pa.created", v2=True):
    act = {"action": action}
    if source:
        act["digitalSourceType"] = IPTC + source
    actions = superbox("c2pa.actions.v2" if v2 else "c2pa.actions", box(b"cbor", cbor({"actions": [act]})))
    assertions = superbox("c2pa.assertions", actions)
    claim = superbox("c2pa.claim.v2", box(b"cbor", cbor({"claim_generator_info": {"name": generator, "version": "1"},
                                                          "signature": "self#jumbf=c2pa.signature"})))
    sig = superbox("c2pa.signature", box(b"cbor", cbor([b"protected", {}, None, b"sig"])))
    manifest = superbox("urn:c2pa:0000-test", assertions, claim, sig)
    return superbox("c2pa", manifest)


# ---------------------------------------------------------------- EXIF (TIFF)

def exif_tiff(make=None, model=None, software=None, taken=None, offset=None, gps=None, comment=None):
    """Little-endian TIFF with IFD0 (+ Exif IFD, + GPS IFD)."""
    ifd0 = []
    for tag, val in ((0x010F, make), (0x0110, model), (0x0131, software)):
        if val:
            ifd0.append((tag, 2, val.encode() + b"\x00"))
    exif = []
    if taken:
        exif.append((0x9003, 2, taken.encode() + b"\x00"))
    if offset:
        exif.append((0x9011, 2, offset.encode() + b"\x00"))
    if comment:
        exif.append((0x9286, 7, b"ASCII\x00\x00\x00" + comment.encode()))
    gpsd = []
    if gps:
        lat, lon = gps
        def rat(x):
            x = abs(x)
            d = int(x); m = int((x - d) * 60); s = round(((x - d) * 60 - m) * 60 * 100)
            return struct.pack("<6I", d, 1, m, 1, s, 100)
        gpsd = [(0x0001, 2, (b"N" if lat >= 0 else b"S") + b"\x00"), (0x0002, 5, rat(lat)),
                (0x0003, 2, (b"E" if lon >= 0 else b"W") + b"\x00"), (0x0004, 5, rat(lon))]

    def layout(entries, start, extra_ptrs=()):
        """Returns (ifd bytes, data bytes) with value offsets from `start`."""
        n = len(entries) + len(extra_ptrs)
        data_at = start + 2 + n * 12 + 4
        ifd, data = struct.pack("<H", n), b""
        for tag, typ, raw in sorted(entries + [(t, 4, None) for t in extra_ptrs], key=lambda e: e[0]):
            if raw is None:
                ifd += struct.pack("<HHI", tag, 4, 1) + b"PTR!"
                continue
            cnt = len(raw) // (8 if typ == 5 else 1)
            if len(raw) <= 4:
                ifd += struct.pack("<HHI", tag, typ, cnt) + raw.ljust(4, b"\x00")
            else:
                ifd += struct.pack("<HHII", tag, typ, cnt, data_at + len(data))
                data += raw + (b"\x00" if len(raw) % 2 else b"")
        return ifd + b"\x00\x00\x00\x00", data

    ptrs = ([0x8769] if exif else []) + ([0x8825] if gpsd else [])
    ifd0_b, ifd0_d = layout(ifd0, 8, ptrs)
    out = b"II*\x00" + struct.pack("<I", 8) + ifd0_b + ifd0_d
    for tag, entries in ((0x8769, exif), (0x8825, gpsd)):
        if not entries:
            continue
        at = len(out)
        b_, d_ = layout(entries, at)
        out = out.replace(struct.pack("<HHI", tag, 4, 1) + b"PTR!", struct.pack("<HHII", tag, 4, 1, at), 1)
        out += b_ + d_
    return out


def xmp(source=None, tool=None, description=None):
    attrs = ""
    if source:
        attrs += f' Iptc4xmpExt:DigitalSourceType="{IPTC}{source}"'
    if tool:
        attrs += f' xmp:CreatorTool="{tool}"'
    body = f"<dc:description><rdf:Alt><rdf:li xml:lang=\"x-default\">{description}</rdf:li></rdf:Alt></dc:description>" \
        if description else ""
    return (f'<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">'
            f'<rdf:Description rdf:about=""{attrs}>{body}</rdf:Description></rdf:RDF></x:xmpmeta>').encode()


# ---------------------------------------------------------------- images

def png(width=4, height=4, texts=None, chunks=(), color=(200, 30, 30)):
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    raw = b"".join(b"\x00" + bytes(color) * width for _ in range(height))
    out = b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
    for k, v in (texts or {}).items():
        out += chunk(b"tEXt", k.encode("latin-1") + b"\x00" + v.encode("latin-1"))
    for t, d in chunks:
        out += chunk(t, d)
    return out + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def jpeg(exif=None, xmp_packet=None, app11=(), comment=None, body=b"\x00" * 64):
    """A JPEG-shaped file (segments are real; the image data isn't decodable unless `body` is a real scan)."""
    segs = b""
    if exif:
        segs += b"\xff\xe1" + struct.pack(">H", len(exif) + 8) + b"Exif\x00\x00" + exif
    if xmp_packet:
        d = b"http://ns.adobe.com/xap/1.0/\x00" + xmp_packet
        segs += b"\xff\xe1" + struct.pack(">H", len(d) + 2) + d
    for s in app11:
        segs += b"\xff\xeb" + struct.pack(">H", len(s) + 2) + s
    if comment:
        segs += b"\xff\xfe" + struct.pack(">H", len(comment) + 2) + comment.encode()
    return b"\xff\xd8" + segs + b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00" + body + b"\xff\xd9"


def app11_segments(store, size=40):
    """Split a JUMBF manifest store over several APP11 segments (JPEG XT), repeating LBox+TBox after the first."""
    hdr, rest = store[:8], store[8:]
    out = []
    for i in range(0, len(rest), size):
        payload = rest[i:i + size]
        out.append(b"JP" + struct.pack(">HI", 1, len(out) + 1) + hdr + payload)
    return out


def insert_exif(jpeg_bytes, tiff):
    """Put an EXIF APP1 right after SOI of a real JPEG (from sips)."""
    seg = b"\xff\xe1" + struct.pack(">H", len(tiff) + 8) + b"Exif\x00\x00" + tiff
    return jpeg_bytes[:2] + seg + jpeg_bytes[2:]


# ---------------------------------------------------------------- audio

def wav(info=None, extra_chunks=(), samples=800):
    fmt = struct.pack("<HHIIHH", 1, 1, 8000, 16000, 2, 16)
    data = b"\x00\x00" * samples
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt + b"data" + struct.pack("<I", len(data)) + data
    if info:
        sub = b""
        for k, v in info.items():
            d = v.encode() + b"\x00"
            if len(d) % 2:
                d += b"\x00"
            sub += k.encode() + struct.pack("<I", len(d)) + d
        lst = b"INFO" + sub
        body += b"LIST" + struct.pack("<I", len(lst)) + lst
    for cid, d in extra_chunks:
        body += cid + struct.pack("<I", len(d)) + d + (b"\x00" if len(d) % 2 else b"")
    return b"RIFF" + struct.pack("<I", len(body)) + body


def id3(frames):
    """ID3v2.3 with text frames {id: text}; GEOB as ('GEOB', mime, data)."""
    out = b""
    for f in frames:
        if f[0] == "GEOB":
            d = b"\x00" + f[1].encode() + b"\x00" + b"c2pa.bin\x00" + b"c2pa\x00" + f[2]
            fid = b"GEOB"
        elif f[0] == "COMM":
            d = b"\x03eng\x00" + f[1].encode()
            fid = b"COMM"
        else:
            d = b"\x03" + f[1].encode()
            fid = f[0].encode()
        out += fid + struct.pack(">I", len(d)) + b"\x00\x00" + d
    n = len(out)
    size = bytes([(n >> 21) & 0x7F, (n >> 14) & 0x7F, (n >> 7) & 0x7F, n & 0x7F])
    return b"ID3\x03\x00\x00" + size + out


def mp3(frames):
    return id3(frames) + b"\xff\xfb\x90\x00" + b"\x00" * 400


def m4a(tags):
    ilst = b"".join(box(k.replace("©", "\xa9").encode("latin-1"),
                        box(b"data", struct.pack(">II", 1, 0) + v.encode())) for k, v in tags.items())
    meta = box(b"meta", b"\x00\x00\x00\x00" + box(b"hdlr", b"\x00" * 24) + box(b"ilst", ilst))
    return box(b"ftyp", b"M4A \x00\x00\x00\x00M4A mp42isom") + box(b"moov", box(b"udta", meta)) + box(b"mdat", b"\x00" * 64)
