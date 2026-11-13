"""AI image and voice check, phase A (docs/AI-DETECTION.md).

Reads the markers a file carries about how it was made: Content Credentials (C2PA), XMP/IPTC digital source
type, EXIF, PNG text from local generators, and audio tags (RIFF INFO, ID3, MP4, FLAC). Standard library only;
c2patool and exiftool are used when installed. Files are untrusted: every length is checked, sizes are capped,
and a parser that trips on a damaged part says so instead of failing.

It never says a file is "real". "No AI markers found" is a different statement, and the result says so.
"""
import json
import os
import re
import shutil
import struct
import subprocess
import zlib

import macguard_tools as mtools

MAX_BYTES = 200 * 1024 * 1024
SCAN_BYTES = 8 * 1024 * 1024  # generic marker search: this much from the start and from the end

IPTC = "http://cv.iptc.org/newscodes/digitalsourcetype/"
DST_AI_CREATED = {"trainedAlgorithmicMedia"}
DST_AI_EDITED = {"compositeWithTrainedAlgorithmicMedia"}
DST_SYNTHETIC = {"compositeSynthetic", "algorithmicMedia"}
DST_TEXT = {
    "trainedAlgorithmicMedia": "created with generative AI",
    "compositeWithTrainedAlgorithmicMedia": "edited with generative AI",
    "compositeSynthetic": "combined with synthetic content",
    "algorithmicMedia": "made by an algorithm (not stated as AI)",
    "digitalCapture": "captured by a camera",
    "computationalCapture": "captured by a camera with computational processing",
    "negativeFilm": "scanned from film", "positiveFilm": "scanned from film", "print": "scanned from a print",
    "humanEdits": "edited by a person", "compositeCapture": "combined from camera captures",
    "screenCapture": "a screenshot", "digitalArt": "drawn by a person with software",
    "virtualRecording": "recorded in a virtual environment", "dataDrivenMedia": "generated from data",
}

# Names of AI generators and voice services. Matched as whole words in metadata fields only.
AI_IMAGE_NAMES = ["Adobe Firefly", "Firefly", "DALL-E", "DALL·E", "DALLE", "Midjourney", "Stable Diffusion",
                  "StableDiffusion", "SDXL", "ComfyUI", "Automatic1111", "AUTOMATIC1111", "InvokeAI", "NovelAI",
                  "Imagen", "Google AI", "Gemini", "Ideogram", "Leonardo.Ai", "Leonardo AI", "Flux", "FLUX.1",
                  "Bing Image Creator", "Microsoft Designer", "Designer (Microsoft)", "ChatGPT", "OpenAI", "GPT-4o",
                  "Runway", "Sora", "Kling", "Grok", "Aurora", "Krea", "Playground AI", "DreamStudio", "Fooocus",
                  "Craiyon", "Nano Banana", "Recraft", "Seedream", "Hunyuan", "Qwen-Image", "Meta AI", "Veo"]
AI_VOICE_NAMES = ["ElevenLabs", "Eleven Labs", "Murf", "WellSaid", "Resemble AI", "Resemble.ai", "Play.ht", "PlayHT",
                  "Speechify", "Coqui", "XTTS", "Tortoise TTS", "Kokoro", "F5-TTS", "OpenAI TTS", "Amazon Polly",
                  "Azure TTS", "Azure Neural TTS", "Google Text-to-Speech", "WaveNet", "Overdub", "Suno", "Udio",
                  "mlx-audio", "Cartesia", "Hume AI", "Sesame", "Bark TTS", "Piper TTS", "StyleTTS", "VALL-E",
                  "Voicemod AI", "Lovo", "Synthesia", "HeyGen", "text-to-speech", "Text To Speech", "TTS"]
_ai_re = re.compile(r"(?<![\w.])(" + "|".join(re.escape(n) for n in
                                                 sorted(set(AI_IMAGE_NAMES + AI_VOICE_NAMES), key=len, reverse=True))
                    + r")(?![\w])", re.I)
# encoders and editors that say nothing about AI (an encoder isn't a generator)
NEUTRAL_SOFTWARE = re.compile(r"^(Lavf|Lavc|LAME|FFmpeg|libsndfile|iTunes|Logic|GarageBand|Audacity|QuickTime|"
                              r"Adobe Photoshop(?! Firefly)|Photos|Preview|GIMP|Pixelmator|Lightroom)", re.I)

C2PA_BMFF_UUID = bytes.fromhex("d8fec3d61b0e483c92975828877ec481")
IMAGE_FORMATS = {"jpeg", "png", "webp", "heic", "avif", "gif", "tiff"}
AUDIO_FORMATS = {"wav", "aiff", "mp3", "m4a", "flac", "ogg", "aac"}
VIDEO_FORMATS = {"mp4", "mov"}


class Damaged(ValueError):
    pass


# ---------------------------------------------------------------- small readers

def u16(b, o, le=False):
    if o + 2 > len(b):
        raise Damaged("short read")
    return struct.unpack_from("<H" if le else ">H", b, o)[0]


def u32(b, o, le=False):
    if o + 4 > len(b):
        raise Damaged("short read")
    return struct.unpack_from("<I" if le else ">I", b, o)[0]


def u64(b, o, le=False):
    if o + 8 > len(b):
        raise Damaged("short read")
    return struct.unpack_from("<Q" if le else ">Q", b, o)[0]


def text(raw):
    raw = raw.split(b"\x00", 1)[0]
    for enc in ("utf-8", "latin-1"):
        try:
            return raw.decode(enc).strip()
        except UnicodeDecodeError:
            continue
    return ""


# ---------------------------------------------------------------- CBOR (RFC 8949), enough for C2PA

def cbor_loads(b, max_depth=48, max_items=200000):
    pos, count = 0, [0]

    def need(n):
        if n < 0 or pos + n > len(b):
            raise Damaged("CBOR runs past the end")

    def arg(info):
        nonlocal pos
        if info < 24:
            return info
        size = {24: 1, 25: 2, 26: 4, 27: 8}.get(info)
        if size is None:
            raise Damaged("bad CBOR length")
        need(size)
        v = int.from_bytes(b[pos:pos + size], "big")
        pos += size
        return v

    def item(depth):
        nonlocal pos
        if depth > max_depth:
            raise Damaged("CBOR nested too deep")
        count[0] += 1
        if count[0] > max_items:
            raise Damaged("CBOR too large")
        need(1)
        ib = b[pos]
        pos += 1
        major, info = ib >> 5, ib & 31
        if major == 7:
            if info == 20:
                return False
            if info == 21:
                return True
            if info in (22, 23):
                return None
            if info in (25, 26, 27):
                size = {25: 2, 26: 4, 27: 8}[info]
                need(size)
                v = struct.unpack_from({2: ">e", 4: ">f", 8: ">d"}[size], b, pos)[0]
                pos += size
                return v
            if info < 24:
                return info
            if info == 24:
                need(1)
                pos += 1
                return b[pos - 1]
            raise Damaged("unexpected CBOR break")
        if info == 31:  # indefinite length
            if major in (2, 3):
                parts = []
                while True:
                    need(1)
                    if b[pos] == 0xFF:
                        pos += 1
                        break
                    parts.append(item(depth + 1))
                return (b"" if major == 2 else "").join(parts)
            if major == 4:
                out = []
                while True:
                    need(1)
                    if b[pos] == 0xFF:
                        pos += 1
                        return out
                    out.append(item(depth + 1))
            if major == 5:
                out = {}
                while True:
                    need(1)
                    if b[pos] == 0xFF:
                        pos += 1
                        return out
                    k = item(depth + 1)
                    out[k if isinstance(k, (str, int, float, bool, type(None))) else repr(k)] = item(depth + 1)
            raise Damaged("bad indefinite CBOR item")
        v = arg(info)
        if major == 0:
            return v
        if major == 1:
            return -1 - v
        if major in (2, 3):
            need(v)
            raw = b[pos:pos + v]
            pos += v
            return bytes(raw) if major == 2 else raw.decode("utf-8", "replace")
        if major == 4:
            need(v)  # every item takes at least one byte
            return [item(depth + 1) for _ in range(v)]
        if major == 5:
            need(v)
            out = {}
            for _ in range(v):
                k = item(depth + 1)
                out[k if isinstance(k, (str, int, float, bool, type(None))) else repr(k)] = item(depth + 1)
            return out
        if major == 6:
            return item(depth + 1)  # tags: keep the value
        raise Damaged("bad CBOR")

    return item(0)


# ---------------------------------------------------------------- JUMBF and C2PA

def boxes(b, start, end):
    """ISO-BMFF style boxes in b[start:end]: (type, payload start, payload end). Stops at the first bad one."""
    while start + 8 <= end:
        size, typ, hdr = u32(b, start), bytes(b[start + 4:start + 8]), 8
        if size == 1:
            size, hdr = u64(b, start + 8), 16
        elif size == 0:
            size = end - start
        if size < hdr or start + size > end:
            return
        yield typ, start + hdr, start + size
        start += size


def jumbf(b, s, e, depth=0):
    """A JUMBF superbox's payload -> {"label", "children": [...], "content": [(type, bytes)]}."""
    if depth > 16:
        raise Damaged("JUMBF nested too deep")
    node = {"label": "", "children": [], "content": []}
    for typ, ps, pe in boxes(b, s, e):
        if typ == b"jumd":
            if pe - ps >= 17:
                toggles = b[ps + 16]
                if toggles & 0x02:
                    end = bytes(b[ps + 17:pe]).find(b"\x00")
                    node["label"] = bytes(b[ps + 17:ps + 17 + end if end >= 0 else pe]).decode("utf-8", "replace")
        elif typ == b"jumb":
            node["children"].append(jumbf(b, ps, pe, depth + 1))
        else:
            node["content"].append((typ, bytes(b[ps:pe])))
    return node


def find_c2pa_store(b):
    """A C2PA manifest store stored in one piece anywhere in b (PNG caBX, WebP/WAV C2PA chunk, BMFF uuid, ID3 GEOB)."""
    i = 0
    while True:
        i = b.find(b"jumd", i)
        if i < 0 or i < 12:
            if i < 0:
                return None
            i += 4
            continue
        start = i - 12  # [LBox][jumb][LBox][jumd]...
        if bytes(b[i - 8:i - 4]) == b"jumb":
            label_at = i + 4 + 16 + 1
            if bytes(b[label_at:label_at + 5]) == b"c2pa\x00":
                size = u32(b, start)
                if 16 < size <= len(b) - start:
                    return jumbf(b, start + 8, start + size)
        i += 4


def jpeg_app11_store(segments):
    """JPEG keeps C2PA in APP11 JUMBF segments that may span many; join them per box instance (JPEG XT)."""
    parts = {}
    for seg in segments:
        if len(seg) < 16 or seg[:2] != b"JP":
            continue
        en, z = u16(seg, 2), u32(seg, 4)
        parts.setdefault(en, []).append((z, seg[8:]))
    for en, chunks in parts.items():
        chunks.sort()
        data = chunks[0][1] + b"".join(c[8:] for _, c in chunks[1:])  # later packets repeat LBox+TBox
        if data[4:8] == b"jumb":
            node = jumbf(data, 8, min(len(data), u32(data, 0) or len(data)))
            if node["children"] and node["children"][0]["label"] == "c2pa" or node["label"] == "c2pa":
                return node
    return None


def read_c2pa(store):
    """Manifest store node -> {"generator", "sources": [dst...], "actions": [...], "manifests": n}."""
    manifests = store["children"] if store["label"] == "c2pa" else []
    if not manifests and store["children"] and store["children"][0]["label"] == "c2pa":
        manifests = store["children"][0]["children"]
    out = {"manifests": len(manifests), "generator": "", "sources": [], "actions": [], "ingredients": 0, "damaged": []}
    if not manifests:
        return out
    active = manifests[-1]  # the last manifest in the store is the active one
    for part in active["children"]:
        label = part["label"]
        cbor_boxes = [c for t, c in part["content"] if t == b"cbor"]
        if label.startswith("c2pa.claim") and cbor_boxes:
            try:
                claim = cbor_loads(cbor_boxes[0])
            except Damaged as e:
                out["damaged"].append(f"claim: {e}")
                continue
            gen = claim.get("claim_generator") if isinstance(claim, dict) else None
            info = claim.get("claim_generator_info") if isinstance(claim, dict) else None
            if isinstance(info, dict):
                info = [info]
            if isinstance(info, list) and info and isinstance(info[0], dict):
                gen = " ".join(str(x) for x in (info[0].get("name"), info[0].get("version")) if x)
            out["generator"] = str(gen or "")
        if label == "c2pa.assertions":
            for a in part["children"]:
                body = [c for t, c in a["content"] if t == b"cbor"]
                if a["label"].startswith("c2pa.ingredient"):
                    out["ingredients"] += 1
                if not a["label"].startswith("c2pa.actions") or not body:
                    continue
                try:
                    data = cbor_loads(body[0])
                except Damaged as e:
                    out["damaged"].append(f"actions: {e}")
                    continue
                for act in (data.get("actions") or []) if isinstance(data, dict) else []:
                    if not isinstance(act, dict):
                        continue
                    dst = str(act.get("digitalSourceType") or "")
                    agent = act.get("softwareAgent")
                    agent = agent.get("name") if isinstance(agent, dict) else agent
                    out["actions"].append({"action": str(act.get("action") or ""), "source": dst.rsplit("/", 1)[-1],
                                           "agent": str(agent or "")})
                    if dst:
                        out["sources"].append(dst.rsplit("/", 1)[-1])
    return out


# ---------------------------------------------------------------- EXIF / TIFF

TIFF_TAGS = {0x010F: "make", 0x0110: "model", 0x0131: "software", 0x010E: "description", 0x013B: "artist",
             0x8298: "copyright", 0x0132: "datetime"}
EXIF_TAGS = {0x9003: "taken", 0x9011: "offset", 0x9286: "comment", 0xA434: "lens"}


def parse_tiff(b, base=0, limit=None):
    """EXIF in TIFF form -> {make, model, software, ..., taken, offset, gps: (lat, lon) or None}."""
    end = len(b) if limit is None else min(len(b), limit)
    order = bytes(b[base:base + 2])
    if order not in (b"II", b"MM"):
        raise Damaged("not TIFF")
    le = order == b"II"
    if u16(b, base + 2, le) != 42:
        raise Damaged("not TIFF")
    out, seen = {}, set()

    def ifd(off, names, depth=0):
        if depth > 4 or off in seen or not 0 < off < end - base:
            return {}
        seen.add(off)
        p = base + off
        n = u16(b, p, le)
        if n > 1000:
            raise Damaged("too many TIFF entries")
        found = {}
        for i in range(n):
            e = p + 2 + i * 12
            tag, typ, cnt = u16(b, e, le), u16(b, e + 2, le), u32(b, e + 4, le)
            size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 13: 4}.get(typ, 0) * cnt
            vo = e + 8 if size <= 4 else base + u32(b, e + 8, le)
            if size > 1 << 20 or vo + size > end:
                continue
            raw = bytes(b[vo:vo + size])
            if names is GPS_TAGS and tag in GPS_TAGS:
                if typ == 5 and cnt == 3:
                    vals = struct.unpack_from(("<" if le else ">") + "6I", raw)
                    found[GPS_TAGS[tag]] = sum((vals[2 * k] / vals[2 * k + 1] if vals[2 * k + 1] else 0) / 60 ** k
                                               for k in range(3))
                elif typ == 2:
                    found[GPS_TAGS[tag]] = text(raw)
            elif tag in names:
                if tag == 0x9286:  # UserComment: 8-byte charset id first
                    cs = raw[:8]
                    found[names[tag]] = (raw[8:].decode("utf-16-be" if not le else "utf-16-le", "replace").strip("\x00 ")
                                         if cs.startswith(b"UNICODE") else text(raw[8:]))
                else:
                    found[names[tag]] = text(raw)
            elif tag in (0x8769, 0x8825):
                found[tag] = struct.unpack_from("<I" if le else ">I", raw)[0] if typ in (4, 13) and cnt == 1 else 0
        return found

    first = u32(b, base + 4, le)
    ifd0 = ifd(first, TIFF_TAGS)
    out.update({k: v for k, v in ifd0.items() if isinstance(k, str)})
    if ifd0.get(0x8769):
        out.update({k: v for k, v in ifd(ifd0[0x8769], EXIF_TAGS, 1).items() if isinstance(k, str)})
    out["gps"] = None
    if ifd0.get(0x8825):
        g = ifd(ifd0[0x8825], GPS_TAGS, 1)
        if "lat" in g and "lon" in g:
            lat = -g["lat"] if g.get("latref") == "S" else g["lat"]
            lon = -g["lon"] if g.get("lonref") == "W" else g["lon"]
            if (lat, lon) != (0, 0):
                out["gps"] = (round(lat, 6), round(lon, 6))
    return out


GPS_TAGS = {0x0001: "latref", 0x0002: "lat", 0x0003: "lonref", 0x0004: "lon"}


def find_exif(b):
    """EXIF anywhere (HEIC/AVIF items, unknown containers): 'Exif\\0\\0' followed by a TIFF header."""
    i = 0
    while True:
        i = b.find(b"Exif\x00\x00", i)
        if i < 0:
            return None
        if bytes(b[i + 6:i + 10]) in (b"II*\x00", b"MM\x00*"):
            try:
                return parse_tiff(b, i + 6)
            except (Damaged, struct.error):
                pass
        i += 6


# ---------------------------------------------------------------- XMP

XMP_FIELDS = {
    "source": r"DigitalSourceType", "tool": r"(?:xmp:)?CreatorTool", "software": r"(?:tiff:)?Software",
    "description": r"(?:dc:)?description", "credit": r"(?:photoshop:)?Credit", "creator": r"(?:dc:)?creator",
}


def xmp_packets(b):
    out, i = [], 0
    while len(out) < 4:
        i = b.find(b"<x:xmpmeta", i)
        if i < 0:
            break
        j = b.find(b"</x:xmpmeta>", i)
        if j < 0:
            break
        out.append(bytes(b[i:j + 12]).decode("utf-8", "replace"))
        i = j
    return out


def read_xmp(x):
    found = {}
    for key, name in XMP_FIELDS.items():
        vals = re.findall(r"[\w:]*" + name + r'="([^"]*)"', x)
        for m in re.finditer(r"<[\w:]*" + name + r"\b[^>]*>(.*?)</[\w:]*" + name + ">", x, re.S):
            inner = re.findall(r"<rdf:li[^>]*>(.*?)</rdf:li>", m.group(1), re.S) or [m.group(1)]
            vals += [re.sub(r"<[^>]+>", "", v).strip() for v in inner]
        vals += re.findall(r'rdf:resource="([^"]*' + IPTC + r'[^"]*)"', x) if key == "source" else []
        vals = [v.strip() for v in vals if v.strip()]
        if vals:
            found[key] = vals
    return found


# ---------------------------------------------------------------- formats

def sniff(b, name=""):
    if b[:3] == b"\xff\xd8\xff":
        return "jpeg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    if b[:4] == b"RIFF" and b[8:12] == b"WAVE":
        return "wav"
    if b[:4] == b"FORM" and b[8:12] in (b"AIFF", b"AIFC"):
        return "aiff"
    if b[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:4] == b"fLaC":
        return "flac"
    if b[:4] == b"OggS":
        return "ogg"
    if b[4:8] == b"ftyp":
        brand = bytes(b[8:12])
        if brand in (b"heic", b"heix", b"mif1", b"msf1", b"heim", b"heis", b"hevc"):
            return "heic"
        if brand in (b"avif", b"avis"):
            return "avif"
        if brand in (b"M4A ", b"M4B ", b"M4P "):
            return "m4a"
        if brand == b"qt  ":
            return "mov"
        return "m4a" if name.lower().endswith((".m4a", ".aac")) else "mp4"
    if b[:3] == b"ID3":
        flac_at = b.find(b"fLaC", 10, 10 + 4 + id3_size(b))
        return "flac" if flac_at > 0 else "mp3"
    if len(b) > 2 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0:
        return "aac" if (b[1] & 0x06) == 0 and name.lower().endswith(".aac") else "mp3"
    return None


def id3_size(b):
    if b[:3] != b"ID3" or len(b) < 10:
        return 0
    return (b[6] << 21) | (b[7] << 14) | (b[8] << 7) | b[9]


def jpeg_parts(b):
    """Walk JPEG segments to the image data: APP1 EXIF/XMP, APP11 JUMBF, COM."""
    out = {"exif": None, "app11": [], "comments": []}
    p = 2
    while p + 4 <= len(b):
        if b[p] != 0xFF:
            raise Damaged("JPEG segment missing")
        m = b[p + 1]
        if m == 0xFF:
            p += 1
            continue
        if m in (0xD8, 0x01) or 0xD0 <= m <= 0xD7:
            p += 2
            continue
        if m in (0xDA, 0xD9):  # start of scan: metadata is all before it
            break
        size = u16(b, p + 2)
        seg = bytes(b[p + 4:p + 2 + size])
        if m == 0xE1 and seg.startswith(b"Exif\x00\x00") and out["exif"] is None:
            out["exif"] = parse_tiff(seg, 6)
        elif m == 0xEB:
            out["app11"].append(seg)
        elif m == 0xFE:
            out["comments"].append(text(seg))
        p += 2 + size
    return out


def png_parts(b):
    out = {"text": {}, "exif": None, "crc_bad": 0}
    p = 8
    while p + 12 <= len(b):
        n, typ = u32(b, p), bytes(b[p + 4:p + 8])
        if p + 12 + n > len(b):
            raise Damaged("PNG chunk runs past the end")
        data = bytes(b[p + 8:p + 8 + n])
        if zlib.crc32(typ + data) & 0xFFFFFFFF != u32(b, p + 8 + n):
            out["crc_bad"] += 1
        if typ == b"tEXt" and b"\x00" in data:
            k, v = data.split(b"\x00", 1)
            out["text"][k.decode("latin-1")] = v.decode("latin-1")
        elif typ == b"zTXt" and b"\x00" in data:
            k, v = data.split(b"\x00", 1)
            out["text"][k.decode("latin-1")] = zlib.decompressobj().decompress(v[1:], 4 << 20).decode("latin-1")
        elif typ == b"iTXt" and b"\x00" in data:
            k, rest = data.split(b"\x00", 1)
            comp = rest[0] if rest else 0
            rest = rest[2:]
            parts = rest.split(b"\x00", 2)
            if len(parts) == 3:
                v = parts[2]
                if comp:
                    v = zlib.decompressobj().decompress(v, 4 << 20)
                out["text"][k.decode("latin-1")] = v.decode("utf-8", "replace")
        elif typ == b"eXIf":
            out["exif"] = parse_tiff(data, 0)
        elif typ == b"IEND":
            break
        p += 12 + n
    return out


def riff_parts(b):
    out = {"info": {}, "exif": None, "id3": None}
    end = min(len(b), 8 + u32(b, 4, True))
    p = 12
    while p + 8 <= end:
        cid, n = bytes(b[p:p + 4]), u32(b, p + 4, True)
        if p + 8 + n > len(b):
            break
        data = b[p + 8:p + 8 + n]
        if cid == b"LIST" and bytes(data[:4]) == b"INFO":
            q = 4
            while q + 8 <= len(data):
                sid, sn = bytes(data[q:q + 4]).decode("latin-1"), u32(data, q + 4, True)
                out["info"][sid] = text(bytes(data[q + 8:q + 8 + sn]))
                q += 8 + sn + (sn & 1)
        elif cid == b"EXIF":
            raw = bytes(data)
            out["exif"] = parse_tiff(raw, 6 if raw.startswith(b"Exif") else 0)
        elif cid in (b"id3 ", b"ID3 "):
            out["id3"] = id3_frames(bytes(data))
        p += 8 + n + (n & 1)
    return out


def aiff_parts(b):
    """AIFF/AIFC chunks (big-endian): NAME, AUTH, ANNO, (c), and an ID3 chunk."""
    out = {"info": {}, "id3": None}
    end = min(len(b), 8 + u32(b, 4))
    p = 12
    while p + 8 <= end:
        cid, n = bytes(b[p:p + 4]), u32(b, p + 4)
        if p + 8 + n > len(b):
            break
        if cid in (b"NAME", b"AUTH", b"ANNO", b"(c) "):
            out["info"][cid.decode("latin-1").strip()] = text(bytes(b[p + 8:p + 8 + n]))
        elif cid in (b"ID3 ", b"id3 "):
            out["id3"] = id3_frames(bytes(b[p + 8:p + 8 + n]))
        p += 8 + n + (n & 1)
    return out


def id3_text(raw):
    if not raw:
        return ""
    enc, body = raw[0], raw[1:]
    codec = {0: "latin-1", 1: "utf-16", 2: "utf-16-be", 3: "utf-8"}.get(enc, "latin-1")
    try:
        return body.decode(codec).replace("\x00", " / ").strip(" /")
    except UnicodeDecodeError:
        return body.decode("latin-1", "replace")


def id3_frames(b):
    """ID3v2.2–2.4 frames -> {"TSSE": ..., "COMM": ..., "TXXX:desc": ..., "GEOB": [(mime, data)]}."""
    out = {"GEOB": []}
    if b[:3] != b"ID3" or len(b) < 10:
        return out
    ver, end = b[3], min(len(b), 10 + id3_size(b))
    p = 10
    if b[5] & 0x40 and ver >= 3:  # extended header
        p += (id3_size(b"ID3" + b"\x00" * 3 + b[10:14]) if ver == 4 else u32(b, 10) + 4)
    while p + (6 if ver == 2 else 10) <= end:
        if ver == 2:
            fid, n, hdr = bytes(b[p:p + 3]).decode("latin-1"), int.from_bytes(b[p + 3:p + 6], "big"), 6
        else:
            fid = bytes(b[p:p + 4]).decode("latin-1")
            n = (id3_size(b"ID3" + b"\x00" * 3 + b[p + 4:p + 8]) if ver == 4 else u32(b, p + 4))
            hdr = 10
        if not fid.strip("\x00") or n <= 0 or p + hdr + n > end:
            break
        data = bytes(b[p + hdr:p + hdr + n])
        fid = {"TSS": "TSSE", "TEN": "TENC", "COM": "COMM", "TXX": "TXXX", "GEO": "GEOB", "TT2": "TIT2",
               "TP1": "TPE1"}.get(fid, fid)
        if fid == "GEOB" and data:
            enc = data[0]
            mime_end = data.find(b"\x00", 1)
            mime = data[1:mime_end].decode("latin-1")
            rest = data[mime_end + 1:]
            term = b"\x00\x00" if enc in (1, 2) else b"\x00"
            for _ in range(2):  # file name, description
                k = rest.find(term)
                while term == b"\x00\x00" and k >= 0 and k % 2:
                    k = rest.find(term, k + 1)
                rest = rest[k + len(term):] if k >= 0 else b""
            out["GEOB"].append((mime, rest))
        elif fid == "COMM" and len(data) > 4:
            out["COMM"] = id3_text(data[:1] + data[4:])
        elif fid == "TXXX":
            v = id3_text(data)
            desc, _, val = v.partition(" / ")
            out[f"TXXX:{desc}"] = val
        elif fid.startswith("T"):
            out[fid] = id3_text(data)
        p += hdr + n
    return out


def bmff_parts(b):
    """ISO-BMFF (HEIC, AVIF, MP4, MOV, M4A): top-level C2PA uuid box, and iTunes-style tags in moov/udta/meta/ilst."""
    out = {"tags": {}, "c2pa_uuid": False}

    def walk(s, e, depth):
        if depth > 6:
            return
        for typ, ps, pe in boxes(b, s, e):
            if typ == b"uuid" and bytes(b[ps:ps + 16]) == C2PA_BMFF_UUID:
                out["c2pa_uuid"] = True
            elif typ in (b"moov", b"udta", b"ilst"):
                walk(ps, pe, depth + 1)
            elif typ == b"meta":
                walk(ps + 4 if bytes(b[ps:ps + 4]) == b"\x00\x00\x00\x00" else ps, pe, depth + 1)
            elif depth >= 1 and (typ[:1] == b"\xa9" or typ in (b"desc", b"ldes", b"----")):
                for dt, dps, dpe in boxes(b, ps, pe):
                    if dt == b"data" and dpe - dps > 8:
                        out["tags"][typ.decode("latin-1").replace("\xa9", "©")] = text(bytes(b[dps + 8:dpe]))
                    elif dt == b"name" and typ == b"----":
                        pass

    walk(0, len(b), 0)
    return out


def flac_parts(b):
    out = {}
    p = b.find(b"fLaC")
    if p < 0:
        return out
    p += 4
    while p + 4 <= len(b):
        hdr = b[p]
        n = int.from_bytes(b[p + 1:p + 4], "big")
        if hdr & 0x7F == 4 and p + 4 + n <= len(b):
            d = b[p + 4:p + 4 + n]
            vl = u32(d, 0, True)
            out["vendor"] = text(bytes(d[4:4 + vl]))
            q, cnt = 8 + vl, u32(d, 4 + vl, True)
            for _ in range(min(cnt, 1000)):
                ln = u32(d, q, True)
                k, _, v = bytes(d[q + 4:q + 4 + ln]).decode("utf-8", "replace").partition("=")
                out[k.upper()] = v
                q += 4 + ln
        if hdr & 0x80:
            break
        p += 4 + n
    return out


# ---------------------------------------------------------------- generator fingerprints

def generator_text(png_text):
    """Local image generators that write their settings into PNG text chunks."""
    hits = []
    params = png_text.get("parameters", "")
    if "Steps:" in params and ("Sampler:" in params or "Seed:" in params):
        model = re.search(r"Model: ([^,\n]+)", params)
        hits.append("Automatic1111 / Forge generation settings" + (f" (model {model.group(1).strip()})" if model else ""))
    for key in ("prompt", "workflow"):
        v = png_text.get(key, "")
        if v.lstrip().startswith("{") and ("class_type" in v or '"nodes"' in v):
            hits.append("a ComfyUI workflow")
            break
    if any(k in png_text for k in ("invokeai_metadata", "sd-metadata", "Dream")):
        hits.append("InvokeAI generation settings")
    comment = png_text.get("Comment", "")
    if comment.lstrip().startswith("{") and '"steps"' in comment and ('"sampler"' in comment or '"seed"' in comment):
        hits.append("NovelAI generation settings")
    return hits


def ai_names(value):
    return sorted({m.group(1) for m in _ai_re.finditer(value or "")}, key=str.lower)


# ---------------------------------------------------------------- optional helpers

def c2patool_check(path, run=subprocess.run):
    """Validate Content Credentials with c2patool when installed: {"state", "signer", "failures"} or None."""
    tool = shutil.which("c2patool")
    if not tool:
        return None
    try:
        r = run([tool, path], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or not r.stdout.strip().startswith("{"):
        return {"state": "none", "signer": "", "failures": [], "error": (r.stderr or "").strip()[:200]}
    try:
        d = json.loads(r.stdout)
    except ValueError:
        return None
    active = (d.get("manifests") or {}).get(d.get("active_manifest") or "", {})
    sig = active.get("signature_info") or {}
    failures = [v.get("code", "") for v in d.get("validation_status") or [] if isinstance(v, dict)]
    res = (d.get("validation_results") or {}).get("activeManifest") or {}
    failures += [v.get("code", "") for v in res.get("failure") or [] if isinstance(v, dict)]
    state = d.get("validation_state") or ("Invalid" if failures else "Valid")
    if state == "Valid" and failures:
        state = "Invalid"
    return {"state": state, "signer": str(sig.get("issuer") or sig.get("common_name") or ""), "time": sig.get("time", ""),
            "failures": [f for f in failures if f]}


def exiftool_fields(path, run=subprocess.run):
    tool = shutil.which("exiftool")
    if not tool:
        return None
    try:
        r = run([tool, "-j", "-G", "-n", path], capture_output=True, text=True, timeout=60)
        return (json.loads(r.stdout) or [{}])[0] if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


# ---------------------------------------------------------------- the check

def read_file(path):
    st = os.stat(path)
    if not os.path.isfile(path):
        raise ValueError("not a file")
    if st.st_size > MAX_BYTES:
        raise ValueError(f"the file is over {MAX_BYTES >> 20} MB")
    with open(path, "rb") as fh:
        return fh.read()


def metadata(b, fmt):
    """Every marker we can read: {"fields": [(where, name, value)], "c2pa": store or None, "exif", "damaged": [...]}"""
    fields, damaged, exif, store = [], [], None, None

    def add(where, name, value):
        if value and str(value).strip():
            fields.append((where, name, str(value).strip()[:500]))

    try:
        if fmt == "jpeg":
            j = jpeg_parts(b)
            exif = j["exif"]
            store = jpeg_app11_store(j["app11"]) if j["app11"] else None
            for c in j["comments"]:
                add("JPEG comment", "comment", c)
        elif fmt == "png":
            p = png_parts(b)
            exif = p["exif"]
            for k, v in p["text"].items():
                if k != "XML:com.adobe.xmp":
                    add("PNG text", k, v)
            for hit in generator_text(p["text"]):
                add("PNG text", "generator", hit)
            if p["crc_bad"]:
                damaged.append(f"{p['crc_bad']} PNG chunk(s) fail their checksum")
        elif fmt in ("webp", "wav"):
            r = riff_parts(b)
            exif = r["exif"]
            names = {"ISFT": "software", "ICMT": "comment", "INAM": "title", "IART": "artist", "IENG": "engineer",
                     "ICRD": "date", "ISRC": "source", "IPRD": "product"}
            for k, v in r["info"].items():
                add("RIFF INFO", names.get(k, k), v)
            for k, v in (r["id3"] or {}).items():
                if k != "GEOB":
                    add("ID3", k, v)
        elif fmt == "aiff":
            r = aiff_parts(b)
            for k, v in r["info"].items():
                add("AIFF", {"NAME": "title", "AUTH": "artist", "ANNO": "comment", "(c)": "copyright"}.get(k, k), v)
            for k, v in (r["id3"] or {}).items():
                if k != "GEOB":
                    add("ID3", k, v)
        elif fmt == "mp3" or (fmt == "flac" and b[:3] == b"ID3"):
            for k, v in id3_frames(b).items():
                if k != "GEOB":
                    add("ID3", k, v)
            if fmt == "flac":
                for k, v in flac_parts(b).items():
                    add("FLAC tags", k.lower(), v)
        elif fmt == "flac":
            for k, v in flac_parts(b).items():
                add("FLAC tags", k.lower(), v)
        elif fmt in ("heic", "avif", "mp4", "mov", "m4a"):
            m = bmff_parts(b)
            for k, v in m["tags"].items():
                add("MP4 tags", {"©too": "encoder", "©swr": "software", "©cmt": "comment", "©nam": "title",
                                 "©ART": "artist", "desc": "description"}.get(k, k), v)
        elif fmt == "tiff":
            exif = parse_tiff(b, 0)
    except (Damaged, struct.error, IndexError, zlib.error) as e:
        damaged.append(f"part of the {fmt.upper()} structure couldn't be read ({e})")
    head = b[:SCAN_BYTES] if len(b) <= 2 * SCAN_BYTES else bytes(b[:SCAN_BYTES]) + bytes(b[-SCAN_BYTES:])
    if exif is None:
        exif = find_exif(head)
    for k in ("make", "model", "software", "description", "artist", "comment", "copyright"):
        if exif and exif.get(k):
            add("EXIF", k, exif[k])
    for x in xmp_packets(head):
        for key, vals in read_xmp(x).items():
            for v in vals:
                add("XMP", key, v)
    if store is None:
        try:
            store = find_c2pa_store(b)
        except (Damaged, struct.error, IndexError) as e:
            damaged.append(f"Content Credentials couldn't be read ({e})")
    return {"fields": fields, "c2pa": store, "exif": exif or {}, "damaged": damaged}


def check(path, display_name=None, run=subprocess.run):
    """Check one file. display_name replaces the path in the result (uploads use a temporary file)."""
    shown = display_name or mtools.home_short(path)
    try:
        b = read_file(path)
    except (OSError, ValueError) as e:
        return mtools.result("ai-check", "unsupported", f"Couldn't read the file: {e}", file=shown)
    fmt = sniff(b, display_name or path)
    tool = "ai-voice" if fmt in AUDIO_FORMATS else "ai-video" if fmt in VIDEO_FORMATS else "ai-image"
    if fmt is None:
        return mtools.result("ai-check", "unsupported", "This file type isn't supported", file=shown,
                             limits=["Images: JPEG, PNG, HEIC, AVIF, WebP, TIFF, GIF. Audio: WAV, AIFF, MP3, M4A, AAC, FLAC. "
                                     "Video: MP4, MOV."],
                             next_steps=["Check the original file rather than a converted copy. If you must convert, "
                                         "export to PNG or WAV, which keep metadata; screenshots lose it."])
    meta = metadata(b, fmt)
    evidence, verdict, confidence, headline = [], None, "none", ""
    rank = {"none": 0, "weak": 1, "moderate": 2, "strong": 3, "proven": 4}

    def raise_to(v, c, h):
        nonlocal verdict, confidence, headline
        if verdict is None or rank[c] > rank[confidence] or (rank[c] == rank[confidence] and v == "ai-declared"
                                                              and verdict == "ai-edited"):
            verdict, confidence, headline = v, c, h

    # 1. Content Credentials
    c2 = read_c2pa(meta["c2pa"]) if meta["c2pa"] else None
    tool_check = c2patool_check(path, run) if c2 else None
    if c2:
        sources = set(c2["sources"])
        gen = f" (by {c2['generator']})" if c2["generator"] else ""
        what = ", ".join(sorted({DST_TEXT.get(s, s) for s in sources})) or "no statement about how it was made"
        verified = tool_check and tool_check["state"] in ("Valid", "Trusted")
        failed = tool_check and tool_check["state"] == "Invalid"
        weight = "proven" if verified else "weak" if failed else "strong"
        sig = ("signature checked by c2patool" + (f", signed by {tool_check['signer']}" if tool_check.get("signer") else "")
               + ("; the signer is on the C2PA trust list" if tool_check["state"] == "Trusted" else "")
               if verified else f"signature check FAILED ({', '.join(tool_check['failures'][:3])}): the file may "
               "have been changed after signing" if failed else "signature not checked")
        evidence.append({"kind": "c2pa", "weight": weight,
                         "detail": f"Content Credentials{gen}: {what}. {c2['manifests']} manifest(s); {sig}."})
        for a in c2["actions"][:6]:
            evidence.append({"kind": "c2pa-action", "weight": weight,
                             "detail": f"action {a['action'] or '?'}" + (f": {DST_TEXT.get(a['source'], a['source'])}"
                                                                          if a["source"] else "")
                             + (f" (software: {a['agent']})" if a["agent"] else "")})
        signer = (tool_check or {}).get("signer") or c2["generator"] or "the tool that made it"
        if sources & DST_AI_CREATED:
            if verified:
                raise_to("ai-proven", "proven", f"Made with AI: signed Content Credentials from {signer} say so")
            else:
                raise_to("ai-declared", weight, "Made with AI, says " + ("a Content Credentials record whose "
                         "signature check failed" if failed else "an unverified Content Credentials record"))
        elif sources & DST_AI_EDITED:
            raise_to("ai-edited", weight, "Edited with AI, says " + ("its signed Content Credentials" if verified
                     else "a Content Credentials record (" + ("signature check failed)" if failed else "unverified)")))
        elif sources & DST_SYNTHETIC:
            raise_to("info", "weak", "Content Credentials say it's synthetic or made by an algorithm, not that AI made it")
        elif not sources and _ai_re.search(c2["generator"] or ""):
            raise_to("ai-declared", "moderate", f"Content Credentials were written by an AI tool ({c2['generator']})")
        for d in c2["damaged"]:
            meta["damaged"].append(d)
    # 2. Metadata
    for where, name, value in meta["fields"]:
        low = name.lower()
        if where == "XMP" and low == "source":
            s = value.rsplit("/", 1)[-1]
            evidence.append({"kind": "xmp", "weight": "moderate" if s in DST_AI_CREATED | DST_AI_EDITED else "weak",
                             "detail": f"XMP digital source type: {DST_TEXT.get(s, s)}"})
            if s in DST_AI_CREATED:
                raise_to("ai-declared", "moderate", "Made with AI, says the file's metadata (IPTC digital source type)")
            elif s in DST_AI_EDITED:
                raise_to("ai-edited", "moderate", "Edited with AI, says the file's metadata (IPTC digital source type)")
            continue
        if low == "generator":
            evidence.append({"kind": "png-text", "weight": "moderate", "detail": f"PNG text holds {value}"})
            raise_to("ai-declared", "moderate", f"Made with AI, says the file's metadata: {value}")
            continue
        names = ai_names(value)
        if names and not (low in ("software", "encoder", "tool", "tsse", "tenc") and NEUTRAL_SOFTWARE.match(value)):
            if low in ("title", "tit2", "artist", "tpe1") and not any(n.lower() in ("elevenlabs", "midjourney")
                                                                        for n in names):
                evidence.append({"kind": where.lower().replace(" ", "-"), "weight": "weak",
                                 "detail": f"{where} {name} mentions {', '.join(names)}: {value[:120]}"})
                continue
            evidence.append({"kind": where.lower().replace(" ", "-"), "weight": "moderate",
                             "detail": f"{where} {name} names {', '.join(names)}: {value[:160]}"})
            raise_to("ai-declared", "moderate", f"Made with AI, says the file's metadata ({where} {name}: {names[0]})")
    # 3. exiftool sees fields we don't parse (IPTC IIM, maker notes)
    et = exiftool_fields(path, run) if verdict is None else None
    for k, v in (et or {}).items():
        if not isinstance(v, str):
            continue
        if k.endswith("DigitalSourceType"):
            s = v.rsplit("/", 1)[-1]
            evidence.append({"kind": "exiftool", "weight": "moderate", "detail": f"exiftool {k}: {DST_TEXT.get(s, s)}"})
            if s in DST_AI_CREATED:
                raise_to("ai-declared", "moderate", "Made with AI, says the file's metadata (read by exiftool)")
            elif s in DST_AI_EDITED:
                raise_to("ai-edited", "moderate", "Edited with AI, says the file's metadata (read by exiftool)")
        elif ai_names(v) and k.split(":")[-1] in ("Software", "CreatorTool", "Credit", "Description", "Comment",
                                                  "UserComment", "Encoder", "EncodedBy"):
            evidence.append({"kind": "exiftool", "weight": "moderate", "detail": f"exiftool {k}: {v[:160]}"})
            raise_to("ai-declared", "moderate", f"Made with AI, says the file's metadata ({k})")
    # camera facts: shown, never used to say "real"
    ex = meta["exif"]
    if ex.get("make") or ex.get("model"):
        evidence.append({"kind": "exif", "weight": "none", "detail": f"Camera named in EXIF: {ex.get('make', '')} "
                         f"{ex.get('model', '')}".strip() + ". EXIF is easy to edit, so this proves nothing either way."})
    limits = ["Content Credentials and metadata are easy to remove: screenshots, messaging apps and social networks "
              "strip them. No markers doesn't mean real.",
              "Metadata can also be added or faked: anything not backed by a checked signature is a claim, not proof.",
              "This version reads markers only. It doesn't analyse the " + ("sound" if tool == "ai-voice" else "pixels")
              + " with an AI model."]
    if tool == "ai-voice":
        limits.append("Most AI voice services don't label their files yet, so a voice clip rarely carries markers.")
    limits += meta["damaged"]
    nxt = []
    if c2 and not tool_check:
        nxt.append("Install c2patool (brew install c2patool) to check the Content Credentials signature.")
    if verdict is None:
        verdict, confidence = "no-markers", "none"
        headline = ("No AI markers found. This does NOT mean it's real: most shared files have lost their markers")
        nxt.append("Ask for the original file, not a screenshot, download or re-shared copy.")
        if tool == "ai-voice":
            nxt.append("Online, with your consent: ElevenLabs' AI Speech Classifier checks for ElevenLabs voices "
                       "(it uploads the file).")
        else:
            nxt.append("Online, with your consent: contentcredentials.org/verify, and Google's SynthID Detector for "
                       "Google-made images (both upload the file).")
    return mtools.result(tool, verdict, headline, confidence, evidence, limits, nxt, file=shown, format=fmt,
                         size=len(b), fields=[{"where": w, "name": n, "value": v[:200]} for w, n, v in meta["fields"][:40]])


# ---------------------------------------------------------------- CLI

VERDICT_COLOR = {"ai-proven": "r", "ai-declared": "r", "ai-edited": "y", "likely-ai": "y", "info": "b",
                 "no-markers": "g", "unsupported": "d"}


def cmd_ai_check(args):
    import macguard as mg
    results = []
    for f in args.files:
        results.append(check(os.path.abspath(os.path.expanduser(f))))
    if args.json:
        print(json.dumps(results if len(results) > 1 else results[0], indent=2, default=str))
        return
    C = mg.C
    for r in results:
        col = C.get(VERDICT_COLOR.get(r["verdict"], "x"), "")
        print(f"{C['B']}{r.get('file')}{C['x']} {C['d']}({r.get('format') or '?'}){C['x']}")
        print(f"  {col}{r['headline']}{C['x']} {C['d']}[{r['verdict']}, evidence: {r['confidence']}]{C['x']}")
        for e in r["evidence"]:
            print(f"   • {e['detail']} {C['d']}({e['weight']}){C['x']}")
        for n in r["next"]:
            print(f"  {C['b']}→{C['x']} {n}")
        if args.verbose:
            for f in r.get("fields", []):
                print(f"   {C['d']}{f['where']} {f['name']}: {f['value'][:100]}{C['x']}")
        print(f"  {C['d']}Limits: {' '.join(r['limits'][:3])}{C['x']}\n")
