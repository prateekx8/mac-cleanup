"""Deep recovery of memory cards (docs/RECOVERY.md, phases R2 and R3).

1. Image the card: the only step that needs root, behind the macOS password dialog. The device is opened
   read-only; unreadable sectors are zero-filled and listed in a map. GNU ddrescue is used when installed.
2. Scan the image, never the card, as the normal user:
   - undelete on FAT12/16/32 and exFAT: deleted directory entries still hold the name, start and size,
     so files that weren't fragmented come back with their names;
   - carve by file signature: JPEG, PNG, HEIC/MP4/MOV, TIFF and camera RAW, PDF, ZIP (Office), WAV/AVI/WebP.
     Carved files get generic names, and each is checked ("looks intact").
3. Save the files you pick to a folder that isn't on the card.

Stdlib only. Images and devices are only ever opened read-only.
"""
import datetime as dt
import io
import json
import mmap
import os
import re
import shlex
import shutil
import struct
import subprocess
import zipfile
import zlib

import macguard as mg
import macguard_tools as mtools

SECTOR = 512
MAX_RESULTS = 20000
LAST_SCAN = {}


def recover_dir():
    d = os.path.join(mg.STATE_DIR, "recover")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def u16(b, o):
    return struct.unpack_from("<H", b, o)[0]


def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def u64(b, o):
    return struct.unpack_from("<Q", b, o)[0]


def open_ro(path):
    """Read-only map of an image file (never anything else)."""
    fd = os.open(path, os.O_RDONLY)
    try:
        size = os.fstat(fd).st_size
        if size == 0:
            raise ValueError("the image is empty")
        return mmap.mmap(fd, 0, access=mmap.ACCESS_READ)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- 1. imaging

# Runs as root (inside the admin prompt), passed inline with -c so no file on disk can be swapped in.
WORKER = r'''
import json, os, sys
src, img, mp, size, uid = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
fd = os.open(src, os.O_RDONLY)
out = os.open(img, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
bad, done, CH, S = [], 0, 1 << 20, 512
def prog():
    with open(mp + ".progress", "w") as fh:
        json.dump({"done": done, "total": size, "bad": len(bad)}, fh)
while done < size:
    n = min(CH, size - done)
    try:
        os.lseek(fd, done, 0)
        buf = os.read(fd, n)
        if len(buf) != n:
            raise OSError(5, "short read")
        os.write(out, buf)
    except OSError:
        for s in range(done, done + n, S):
            try:
                os.lseek(fd, s, 0)
                b = os.read(fd, S)
                if len(b) != S:
                    raise OSError(5, "short read")
            except OSError:
                b = bytes(S)
                if bad and bad[-1][1] == s:
                    bad[-1][1] = s + S
                else:
                    bad.append([s, s + S])
            os.write(out, b)
    done += n
    if done % (64 << 20) == 0 or done >= size:
        prog()
os.close(out)
os.close(fd)
with open(mp, "w") as fh:
    json.dump({"source": src, "size": size, "bad": bad}, fh)
for p in (img, mp, mp + ".progress"):
    os.chown(p, uid, -1)
'''


def image_worker(src, img, map_path, size, uid=None):
    """Run the imaging worker in-process (tests, or when already root)."""
    import sys
    argv = sys.argv
    sys.argv = ["worker", src, img, map_path, str(size), str(os.getuid() if uid is None else uid)]
    try:
        exec(compile(WORKER, "macguard-image-worker", "exec"), {"__name__": "__main__"})
    finally:
        sys.argv = argv


def mounts_of(ident, run=subprocess.run):
    import macguard_recover as rec
    return [v.get("MountPoint") for v in rec.volumes_of(ident) if v.get("MountPoint")]


def check_out_dir(out_dir, card_mounts=()):
    real = os.path.realpath(out_dir)
    for m in card_mounts:
        if real == os.path.realpath(m) or real.startswith(os.path.realpath(m).rstrip("/") + "/"):
            raise ValueError("save somewhere that isn't on the card: writing to the card overwrites what you want back")


def image_plan(ident, out_dir=None):
    import macguard_recover as rec
    info = rec.analyze(ident, quick=True)
    if not info:
        raise ValueError(f"no disk {ident}")
    if info["internal"]:
        raise ValueError("That's an internal disk. Its deleted files can't be recovered by scanning (TRIM and "
                         "encryption); use Recover files search: Trash, Time Machine, snapshots, git, editor history.")
    if any(v["encrypted"] for v in info["volumes"]):
        raise ValueError("This disk is encrypted: scanning its raw sectors finds nothing readable.")
    out_dir = os.path.realpath(os.path.expanduser(out_dir or os.path.join(
        mg.HOME, "Downloads", f"Recovered {dt.date.today().isoformat()}")))
    check_out_dir(out_dir, [v["mount"] for v in info["volumes"] if v["mount"]])
    os.makedirs(out_dir, exist_ok=True)
    free = shutil.disk_usage(out_dir).free
    if info["size"] > free:
        raise ValueError(f"not enough space for the image: the card is {mg.human(info['size'])}, "
                         f"{mg.human(free)} free in {mtools.home_short(out_dir)}")
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    img = os.path.join(out_dir, f"card-{info['id']}-{stamp}.img")
    return {"ident": info["id"], "name": info["name"], "size": info["size"], "image": img, "map": img + ".map.json",
            "ddrescue": shutil.which("ddrescue") or ""}


def image_script(p, uid):
    q = shlex.quote
    dev = f"/dev/r{p['ident']}"
    if p["ddrescue"]:
        return (f"{q(p['ddrescue'])} -d -n -b 512 {q(dev)} {q(p['image'])} {q(p['image'] + '.ddrescue.log')}; "
                f"rc=$?; chown {int(uid)} {q(p['image'])} {q(p['image'] + '.ddrescue.log')}; exit $rc")
    return f"/usr/bin/python3 -I -c {q(WORKER)} {q(dev)} {q(p['image'])} {q(p['map'])} {int(p['size'])} {int(uid)}"


def image_device(ident, out_dir=None, run=subprocess.run, run_admin=None):
    """Copy a whole card into an image file. One admin prompt; read-only on the card."""
    p = image_plan(ident, out_dir)
    if run_admin is None:
        import macguard_capture as cap
        run_admin = cap.run_as_admin
    r = run(["diskutil", "unmountDisk", p["ident"]], capture_output=True, text=True)
    if r.returncode != 0:
        raise ValueError(f"couldn't unmount the card (an app is using it?): {(r.stderr or r.stdout).strip()}")
    ok, err = run_admin(image_script(p, os.getuid()),
                        f"Mac Cleanup wants to copy {p['name'] or p['ident']} into an image file (read-only) to "
                        "recover deleted files.")
    run(["diskutil", "mountDisk", p["ident"]], capture_output=True, text=True)
    if not ok:
        raise ValueError(f"imaging didn't run: {err}")
    bad = []
    if os.path.exists(p["map"]):
        with open(p["map"]) as fh:
            bad = json.load(fh).get("bad", [])
    size = os.path.getsize(p["image"]) if os.path.exists(p["image"]) else 0
    return {"image": p["image"], "size": size, "expected": p["size"], "bad_sectors": sum((b - a) // SECTOR for a, b in bad),
            "complete": size == p["size"], "used": "ddrescue" if p["ddrescue"] else "built-in reader"}


def image_progress(image):
    try:
        with open(image + ".map.json.progress") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {"done": os.path.getsize(image) if os.path.exists(image) else 0}


# ---------------------------------------------------------------- 2a. partitions and file systems

def fs_at(m, off):
    if off + SECTOR > len(m) or m[off + 510:off + 512] != b"\x55\xaa":
        return None
    if m[off + 3:off + 11] == b"EXFAT   ":
        return "exfat"
    if m[off + 82:off + 90] == b"FAT32   ":
        return "fat"
    if m[off + 54:off + 62] in (b"FAT12   ", b"FAT16   ", b"FAT     "):
        return "fat"
    return None


def partitions(m):
    """[(byte offset, "fat"|"exfat")] in a whole-card image or a bare volume image."""
    fs = fs_at(m, 0)
    if fs:
        return [(0, fs)]
    out = []
    if len(m) >= SECTOR and m[510:512] == b"\x55\xaa":
        for i in range(4):
            e = 446 + 16 * i
            typ, lba = m[e + 4], u32(m, e + 8)
            if typ == 0xEE and m[512:520] == b"EFI PART":
                at, n, esz = u64(m, 512 + 72), u32(m, 512 + 80), u32(m, 512 + 84)
                for k in range(min(n, 128)):
                    pe = at * SECTOR + k * esz
                    if pe + 48 > len(m) or m[pe:pe + 16] == bytes(16):
                        continue
                    first = u64(m, pe + 32)
                    f = fs_at(m, first * SECTOR)
                    if f:
                        out.append((first * SECTOR, f))
                break
            if typ and lba:
                f = fs_at(m, lba * SECTOR)
                if f:
                    out.append((lba * SECTOR, f))
    return out


def dos_time(date, time_):
    try:
        return dt.datetime(1980 + (date >> 9), (date >> 5) & 15, date & 31, time_ >> 11, (time_ >> 5) & 63,
                           (time_ & 31) * 2).isoformat()
    except ValueError:
        return ""


SIGS = {"jpg": [b"\xff\xd8\xff"], "jpeg": [b"\xff\xd8\xff"], "png": [b"\x89PNG"], "gif": [b"GIF8"], "pdf": [b"%PDF"],
        "zip": [b"PK\x03\x04"], "docx": [b"PK\x03\x04"], "xlsx": [b"PK\x03\x04"], "pptx": [b"PK\x03\x04"],
        "heic": [b"ftyp"], "mp4": [b"ftyp"], "mov": [b"ftyp", b"moov", b"wide", b"mdat"], "m4a": [b"ftyp"],
        "cr2": [b"II*\x00"], "tif": [b"II*\x00", b"MM\x00*"], "tiff": [b"II*\x00", b"MM\x00*"],
        "nef": [b"MM\x00*", b"II*\x00"], "arw": [b"II*\x00"], "dng": [b"II*\x00", b"MM\x00*"],
        "wav": [b"RIFF"], "avi": [b"RIFF"], "webp": [b"RIFF"], "mp3": [b"ID3", b"\xff\xfb", b"\xff\xf3"]}


def looks_right(data, name):
    e = os.path.splitext(name)[1].lower().lstrip(".")
    sigs = SIGS.get(e)
    if not sigs:
        return None
    head = bytes(data[:16])
    return any(head.startswith(s) or (s in (b"ftyp", b"moov", b"wide", b"mdat") and head[4:8] == s) for s in sigs)


class Fat:
    def __init__(self, m, base):
        self.m, self.base = m, base
        b = m
        self.bps, self.spc, self.rsv, self.nfats = u16(b, base + 11), b[base + 13], u16(b, base + 14), b[base + 16]
        if self.bps not in (512, 1024, 2048, 4096) or self.spc == 0 or self.nfats == 0:
            raise ValueError("not a FAT boot sector")
        rootent, tot16, fat16 = u16(b, base + 17), u16(b, base + 19), u16(b, base + 22)
        tot32, fat32 = u32(b, base + 32), u32(b, base + 36)
        self.fatsz = fat16 or fat32
        root_secs = (rootent * 32 + self.bps - 1) // self.bps
        self.root_at = base + (self.rsv + self.nfats * self.fatsz) * self.bps
        self.root_len = rootent * 32
        self.first_data = self.rsv + self.nfats * self.fatsz + root_secs
        total = tot16 or tot32
        self.clusters = (total - self.first_data) // self.spc
        self.kind = "FAT12" if self.clusters < 4085 else "FAT16" if self.clusters < 65525 else "FAT32"
        self.root_cluster = u32(b, base + 44) if self.kind == "FAT32" else None
        self.csize = self.spc * self.bps
        self.fat_at = base + self.rsv * self.bps

    def off(self, c):
        return self.base + (self.first_data + (c - 2) * self.spc) * self.bps

    def entry(self, c):
        if self.kind == "FAT32":
            return u32(self.m, self.fat_at + c * 4) & 0x0FFFFFFF
        if self.kind == "FAT16":
            return u16(self.m, self.fat_at + c * 2)
        v = u16(self.m, self.fat_at + c * 3 // 2)
        return v >> 4 if c & 1 else v & 0xFFF

    def eoc(self, v):
        return v >= {"FAT32": 0x0FFFFFF8, "FAT16": 0xFFF8, "FAT12": 0xFF8}[self.kind]

    def chain(self, c, limit=1 << 20):
        out, seen = [], set()
        while 2 <= c < self.clusters + 2 and c not in seen and len(out) < limit:
            out.append(c)
            seen.add(c)
            n = self.entry(c)
            if self.eoc(n) or n < 2:
                break
            c = n
        return out

    def free(self, c):
        return self.entry(c) == 0

    def used_runs(self):
        """(offset, size) of every run of clusters in use, plus the system area: carving skips live files."""
        n = self.clusters + 2
        if self.kind == "FAT32":
            vals = struct.unpack_from(f"<{n}I", self.m, self.fat_at)
            used = [v & 0x0FFFFFFF != 0 for v in vals]
        elif self.kind == "FAT16":
            used = [v != 0 for v in struct.unpack_from(f"<{n}H", self.m, self.fat_at)]
        else:
            used = [self.entry(c) != 0 for c in range(n)]
        return [(self.base, self.off(2) - self.base)] + runs(used, self.off, self.csize)

    def dir_bytes(self, c):
        if c is None:  # FAT12/16 root
            return self.m[self.root_at:self.root_at + self.root_len]
        return b"".join(self.m[self.off(x):self.off(x) + self.csize] for x in self.chain(c, 4096))

    def deleted_dir_bytes(self, c):
        """A deleted folder's clusters are freed; read the first one (most folders fit) if it's still free."""
        if 2 <= c < self.clusters + 2 and self.free(c):
            return self.m[self.off(c):self.off(c) + self.csize]
        return b""


def name_is_appledouble(lfn):
    return bool(lfn) and "".join(reversed(lfn)).startswith("._")


def runs(used, off, csize):
    out, start = [], None
    for c in range(2, len(used) + 1):
        u = c < len(used) and used[c]
        if u and start is None:
            start = c
        elif not u and start is not None:
            out.append((off(start), (c - start) * csize))
            start = None
    return out


def lfn_checksum(short11):
    s = 0
    for ch in short11:
        s = (((s & 1) << 7) + (s >> 1) + ch) & 0xFF
    return s


def fat_undelete(m, base, limit=MAX_RESULTS):
    """Deleted files on a FAT volume: [{name, path, offset, size, modified, state}]."""
    fs = Fat(m, base)
    found, seen_dirs = [], set()

    def walk(data, path, deleted_parent, depth):
        if depth > 16 or len(found) >= limit:
            return
        lfn, lfn_sum = [], None
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            first, attr = e[0], e[11]
            if first == 0x00:
                break
            if attr == 0x0F:
                part = (e[1:11] + e[14:26] + e[28:32]).decode("utf-16-le", "replace")
                lfn.append(part.split("\x00")[0])
                lfn_sum = e[13]
                continue
            short = bytes(e[0:11])
            deleted = first == 0xE5 or deleted_parent
            if attr & 0x08 or short.startswith((b".       ", b"..      ")) or name_is_appledouble(lfn):
                lfn, lfn_sum = [], None
                continue
            # a deleted short name lost its first letter; the long-name checksum gives it back
            if first == 0xE5:
                guess = "_"
                if lfn_sum is not None:
                    for ch in range(0x21, 0x7F):
                        if lfn_checksum(bytes([ch]) + short[1:]) == lfn_sum:
                            guess = chr(ch)
                            break
                short_name = guess + short[1:8].decode("latin-1").rstrip()
            else:
                short_name = short[:8].decode("latin-1").rstrip()
            ext = short[8:11].decode("latin-1").rstrip()
            if e[12] & 0x08:
                short_name = short_name.lower()
            if e[12] & 0x10:
                ext = ext.lower()
            name = "".join(reversed(lfn)) if lfn else short_name + ("." + ext if ext else "")
            lfn, lfn_sum = [], None
            c = (u16(e, 20) << 16 | u16(e, 26)) if fs.kind == "FAT32" else u16(e, 26)
            size = u32(e, 28)
            if attr & 0x10:
                if c and c not in seen_dirs:
                    seen_dirs.add(c)
                    sub = fs.deleted_dir_bytes(c) if deleted else fs.dir_bytes(c)
                    walk(sub, path + name + "/", deleted, depth + 1)
                continue
            if not deleted:
                continue
            item = {"name": name, "path": path + name, "size": size, "modified": dos_time(u16(e, 24), u16(e, 22)),
                    "fs": fs.kind}
            if not c or c >= fs.clusters + 2 or size == 0:
                item.update(offset=None, state="lost", note="the entry no longer says where the data was")
            else:
                n = (size + fs.csize - 1) // fs.csize
                start = fs.off(c)
                if start + size > len(m):
                    item.update(offset=None, state="lost", note="points past the end of the card")
                else:
                    reused = sum(1 for k in range(c, min(c + n, fs.clusters + 2)) if not fs.free(k))
                    item.update(offset=start, state="intact" if not reused else "overwritten",
                                note="" if not reused else f"{reused} of {n} clusters are used by newer files")
            found.append(item)

    walk(fs.dir_bytes(fs.root_cluster), "/", False, 0)
    return found, fs.kind


class ExFat:
    def __init__(self, m, base):
        self.m, self.base = m, base
        self.bps, self.spc = 1 << m[base + 108], 1 << m[base + 109]
        self.fat_at = base + u32(m, base + 80) * self.bps
        self.heap = base + u32(m, base + 88) * self.bps
        self.clusters = u32(m, base + 92)
        self.root = u32(m, base + 96)
        self.csize = self.bps * self.spc
        self.bitmap = b""

    def off(self, c):
        return self.heap + (c - 2) * self.csize

    def fat(self, c):
        return u32(self.m, self.fat_at + c * 4)

    def chain(self, c, limit=1 << 20):
        out, seen = [], set()
        while 2 <= c < self.clusters + 2 and c not in seen and len(out) < limit:
            out.append(c)
            seen.add(c)
            n = self.fat(c)
            if n >= 0xFFFFFFF7 or n < 2:
                break
            c = n
        return out

    def used(self, c):
        k = c - 2
        return bool(self.bitmap[k // 8] >> (k % 8) & 1) if 0 <= k // 8 < len(self.bitmap) else True

    def used_runs(self):
        used = [False, False] + [self.used(c) for c in range(2, self.clusters + 2)]
        return [(self.base, self.heap - self.base)] + runs(used, self.off, self.csize)

    def read(self, c, length, contiguous):
        if contiguous:
            return self.m[self.off(c):self.off(c) + length]
        return b"".join(self.m[self.off(x):self.off(x) + self.csize] for x in self.chain(c, 4096))[:length]


def exfat_time(ts, off_byte):
    """exFAT timestamps are local time at the offset stored next to them; shown in this Mac's time zone."""
    local = dos_time(ts >> 16, ts & 0xFFFF)
    if not local or not off_byte & 0x80:
        return local
    q = off_byte & 0x7F
    q = q - 128 if q & 0x40 else q
    t = dt.datetime.fromisoformat(local).replace(tzinfo=dt.timezone(dt.timedelta(minutes=15 * q)))
    return t.astimezone().replace(tzinfo=None).isoformat()


def exfat_with_bitmap(m, base):
    fs = ExFat(m, base)
    root = fs.read(fs.root, 1 << 22, False)
    for i in range(0, len(root) - 31, 32):  # allocation bitmap
        if root[i] == 0x81:
            fs.bitmap = fs.read(u32(root, i + 20), u64(root, i + 24), True)
            break
    fs.root_bytes = root
    return fs


def exfat_undelete(m, base, limit=MAX_RESULTS):
    fs = exfat_with_bitmap(m, base)
    root = fs.root_bytes
    found, seen = [], set()

    def walk(data, path, deleted_parent, depth):
        if depth > 16 or len(found) >= limit:
            return
        i = 0
        while i + 32 <= len(data):
            t = data[i]
            if t == 0x00:
                break
            if t not in (0x85, 0x05):
                i += 32
                continue
            deleted = t == 0x05 or deleted_parent
            count = data[i + 1]
            attrs = u16(data, i + 4)
            mtime = u32(data, i + 12)
            if count < 2 or i + 32 * (count + 1) > len(data):
                i += 32
                continue
            st = data[i + 32:i + 64]
            if st[0] & 0x7F != 0x40:
                i += 32
                continue
            nofat, nlen, first, length = bool(st[1] & 2), st[3], u32(st, 20), u64(st, 24)
            name = ""
            for k in range(2, count + 1):
                ne = data[i + 32 * k:i + 32 * (k + 1)]
                if ne[0] & 0x7F == 0x41:
                    name += ne[2:32].decode("utf-16-le", "replace")
            name = name[:nlen]
            off_byte = data[i + 23]
            i += 32 * (count + 1)
            if name.startswith("._"):
                continue
            if attrs & 0x10:
                if first and first not in seen and length < 1 << 26:
                    seen.add(first)
                    walk(fs.read(first, length, nofat or deleted), path + name + "/", deleted, depth + 1)
                continue
            if not deleted:
                continue
            item = {"name": name, "path": path + name, "size": length, "fs": "exFAT",
                    "modified": exfat_time(mtime, off_byte)}
            n = (length + fs.csize - 1) // fs.csize
            if not first or first >= fs.clusters + 2 or not length:
                item.update(offset=None, state="lost", note="the entry no longer says where the data was")
            elif fs.off(first) + length > len(m):
                item.update(offset=None, state="lost", note="points past the end of the card")
            else:
                reused = sum(1 for k in range(first, min(first + n, fs.clusters + 2)) if fs.used(k))
                item.update(offset=fs.off(first), state="intact" if not reused else "overwritten",
                            note="" if not reused else f"{reused} of {n} clusters are used by newer files",
                            fragmented=not nofat)
            found.append(item)

    walk(root, "/", False, 0)
    return found, "exFAT"


# ---------------------------------------------------------------- 2b. carving

HEADER = re.compile(rb"\xff\xd8\xff[\xc0-\xfe]|\x89PNG\r\n\x1a\n|%PDF-|PK\x03\x04|II\*\x00|MM\x00\*|RIFF....(?:WAVE|AVI |WEBP)"
                    rb"|....ftyp", re.S)
JPEG_MARK = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")
MAX_CARVE = 4 << 30


def jpeg_end(m, s):
    p, end = s + 2, min(len(m), s + (64 << 20))
    while p + 4 <= end:
        if m[p] != 0xFF:
            return None
        mk = m[p + 1]
        if mk == 0xFF:
            p += 1
            continue
        if mk == 0xD9:
            return p + 2
        if 0xD0 <= mk <= 0xD7 or mk == 0x01:
            p += 2
            continue
        ln = struct.unpack_from(">H", m, p + 2)[0]
        if ln < 2:
            return None
        p += 2 + ln
        if mk == 0xDA:  # entropy-coded data until the next real marker
            x = JPEG_MARK.search(m, p, end)
            if not x:
                return None
            p = x.start()
    return None


def png_end(m, s):
    p, intact = s + 8, True
    while p + 12 <= len(m):
        n, typ = struct.unpack_from(">I", m, p)[0], bytes(m[p + 4:p + 8])
        if not typ.isalpha() or p + 12 + n > len(m) or n > 1 << 28:
            return None, False
        if n < 1 << 24 and zlib.crc32(m[p + 4:p + 8 + n]) & 0xFFFFFFFF != struct.unpack_from(">I", m, p + 8 + n)[0]:
            intact = False
        p += 12 + n
        if typ == b"IEND":
            return p, intact
    return None, False


def bmff_end(m, s):
    p, seen = s, set()
    brand = bytes(m[s + 8:s + 12])
    while p + 8 <= len(m) and p - s < MAX_CARVE:
        size, typ = struct.unpack_from(">I", m, p)[0], bytes(m[p + 4:p + 8])
        if not re.fullmatch(rb"[a-zA-Z0-9 \xa9_-]{4}", typ):
            break
        if size == 1:
            size = struct.unpack_from(">Q", m, p + 8)[0]
        if size < 8 or p + size > len(m):
            break
        seen.add(typ)
        p += size
    ok = b"mdat" in seen and (b"moov" in seen or b"meta" in seen)
    ext = ("heic" if brand in (b"heic", b"heix", b"mif1", b"msf1") else "avif" if brand == b"avif" else
           "mov" if brand == b"qt  " else "m4a" if brand.startswith(b"M4A") else "mp4")
    return (p if p > s + 8 and len(seen) > 1 else None), ok, ext


def tiff_end(m, s):
    le = m[s:s + 2] == b"II"
    f = "<" if le else ">"
    U16 = lambda o: struct.unpack_from(f + "H", m, s + o)[0]
    U32 = lambda o: struct.unpack_from(f + "I", m, s + o)[0]
    end, todo, seen, make, dng = 8, [U32(4)], set(), b"", False
    try:
        while todo and len(seen) < 64:
            o = todo.pop()
            if o in seen or not 8 <= o < MAX_CARVE or s + o + 2 > len(m):
                continue
            seen.add(o)
            n = U16(o)
            if n == 0 or n > 512:
                return None, "tif"
            end = max(end, o + 2 + n * 12 + 4)
            offs, lens = {}, {}
            for i in range(n):
                e = o + 2 + i * 12
                tag, typ, cnt = U16(e), U16(e + 2), U32(e + 4)
                size = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 13: 4}.get(typ, 1) * cnt
                val = e + 8 if size <= 4 else U32(e + 8)
                if size > 4:
                    end = max(end, val + size)
                vals = ([U16(val + 2 * k) for k in range(min(cnt, 4096))] if typ == 3 else
                        [U32(val + 4 * k) for k in range(min(cnt, 4096))] if typ in (4, 13) else [])
                if tag in (0x111, 0x144, 0x201):
                    offs[tag] = vals
                elif tag in (0x117, 0x145, 0x202):
                    lens[tag] = vals
                elif tag in (0x14A, 0x8769) and vals:
                    todo += vals
                elif tag == 0x10F:
                    make = bytes(m[s + val:s + val + min(size, 32)])
                elif tag == 0xC612:
                    dng = True
            for a, b in ((0x111, 0x117), (0x144, 0x145), (0x201, 0x202)):
                for x, y in zip(offs.get(a, []), lens.get(b, [])):
                    end = max(end, x + y)
            nxt = U32(o + 2 + n * 12)
            if nxt:
                todo.append(nxt)
    except struct.error:
        return None, "tif"
    if end > MAX_CARVE or s + end > len(m):
        return None, "tif"
    ext = ("dng" if dng else "cr2" if m[s + 8:s + 10] == b"CR" else "nef" if make.startswith(b"NIKON")
           else "arw" if make.startswith(b"SONY") else "tif")
    return s + end, ext


def carve(m, start=0, end=None, aligned=SECTOR, skip=()):
    """Find files by signature in m[start:end]. skip: (offset, size) ranges already recovered by undelete."""
    end = len(m) if end is None else end
    found, pos = [], start
    skips = sorted(skip)
    while len(found) < MAX_RESULTS:
        x = HEADER.search(m, pos, end)
        if not x:
            break
        s = x.start()
        if aligned and (s - start) % aligned:
            pos = s + 1
            continue
        hit = next(((a, b) for a, b in skips if a <= s < a + b), None)
        if hit:
            pos = hit[0] + hit[1]
            continue
        sig = bytes(m[s:s + 12])
        e, ext, intact, note = None, "", None, ""
        if sig.startswith(b"\xff\xd8\xff"):
            e, ext = jpeg_end(m, s), "jpg"
            intact = e is not None
        elif sig.startswith(b"\x89PNG"):
            e, intact = png_end(m, s)
            ext = "png"
        elif sig.startswith(b"%PDF-"):
            k = m.find(b"%%EOF", s, min(end, s + (200 << 20)))
            if k >= 0:
                e = k + 5
                while True:  # incremental updates add more %%EOF markers shortly after
                    k2 = m.find(b"%%EOF", e, min(end, e + (1 << 20)))
                    nxt = m.find(b"%PDF-", e, min(end, e + (1 << 20)))
                    if k2 < 0 or (0 <= nxt < k2):
                        break
                    e = k2 + 5
                while e < len(m) and e - k < 7 and m[e] in (0x0A, 0x0D):  # the end-of-line after %%EOF
                    e += 1
                intact = m.find(b"startxref", s, e) >= 0
            ext = "pdf"
        elif sig.startswith(b"PK\x03\x04"):
            k = m.find(b"PK\x05\x06", s, min(end, s + (512 << 20)))
            if k >= 0 and k + 22 <= len(m):
                e = k + 22 + struct.unpack_from("<H", m, k + 20)[0]
                ext, intact = "zip", None
                if e - s < 100 << 20:
                    try:
                        z = zipfile.ZipFile(io.BytesIO(m[s:e]))
                        names = z.namelist()
                        intact = z.testzip() is None
                        ext = ("docx" if any(n.startswith("word/") for n in names) else
                               "xlsx" if any(n.startswith("xl/") for n in names) else
                               "pptx" if any(n.startswith("ppt/") for n in names) else "zip")
                    except (zipfile.BadZipFile, ValueError, OSError, NotImplementedError, RuntimeError, zlib.error,
                            EOFError):
                        intact = False
        elif sig[:4] in (b"II*\x00", b"MM\x00*"):
            e, ext = tiff_end(m, s)
            intact = e is not None
        elif sig.startswith(b"RIFF"):
            n = struct.unpack_from("<I", m, s + 4)[0]
            if 12 < n < MAX_CARVE and s + 8 + n <= len(m):
                e = s + 8 + n
                intact = True
            ext = {b"WAVE": "wav", b"AVI ": "avi", b"WEBP": "webp"}[sig[8:12]]
        elif sig[4:8] == b"ftyp":
            e, intact, ext = bmff_end(m, s)
        if e is None or e - s < 64:
            pos = s + 1
            continue
        found.append({"offset": s, "size": e - s, "ext": ext, "intact": intact, "note": note})
        pos = e + ((-(e - start)) % aligned if aligned else 0)
    return found


# ---------------------------------------------------------------- 2c. scan an image

def scan(image, undelete=True, do_carve=True, everything=False):
    image = os.path.realpath(os.path.expanduser(image))
    if image.startswith("/dev/"):
        raise ValueError("scan an image file, not the card: make one with `macguard recover image diskN`")
    if not os.path.isfile(image):
        raise ValueError(f"no such image: {image}")
    m = open_ro(image)
    items, notes, parts, live = [], [], [], []
    try:
        parts = partitions(m)
        if not everything:
            for off, kind in parts:
                try:
                    live += (Fat(m, off) if kind == "fat" else exfat_with_bitmap(m, off)).used_runs()
                except (ValueError, struct.error, IndexError):
                    pass
        if undelete:
            if not parts:
                notes.append("No FAT or exFAT file system found (formatted, or another kind): using signature carving only.")
            for off, kind in parts:
                try:
                    got, label = (fat_undelete if kind == "fat" else exfat_undelete)(m, off)
                except (ValueError, struct.error, IndexError) as e:
                    notes.append(f"The {kind} file system at {off} couldn't be read: {e}")
                    continue
                for g in got:
                    if g.get("offset") is not None:
                        ok = looks_right(m[g["offset"]:g["offset"] + 16], g["name"])
                        if ok is False and g["state"] == "intact":
                            g["state"], g["note"] = "damaged", "the data doesn't start like a ." + g["name"].rsplit(".", 1)[-1]
                    items.append(dict(g, source="undelete"))
                notes.append(f"{label} at byte {off}: {len(got)} deleted file(s) found in its folders.")
        if do_carve:
            taken = [(i["offset"], i["size"]) for i in items if i.get("offset") is not None and i["state"] == "intact"]
            carved = carve(m, skip=taken + live)
            if live:
                notes.append("Carving looked only at free space; files that weren't deleted are skipped "
                             "(--everything to include them).")
            for k, c in enumerate(carved, 1):
                items.append({"source": "carve", "name": f"recovered-{k:05d}.{c['ext']}", "path": "",
                              "offset": c["offset"], "size": c["size"], "modified": "",
                              "state": "intact" if c["intact"] else "unchecked" if c["intact"] is None else "damaged",
                              "note": c["note"] or ("" if c["intact"] else "may be fragmented or partly overwritten")})
    finally:
        m.close()
    for k, it in enumerate(items):
        it["id"] = str(k)
    LAST_SCAN.clear()
    LAST_SCAN.update({"image": image, "items": {i["id"]: i for i in items}})
    with open(os.path.join(recover_dir(), "scan-last.json"), "w") as fh:
        json.dump({"image": image, "items": items}, fh)
    good = sum(1 for i in items if i["state"] == "intact")
    named = sum(1 for i in items if i["source"] == "undelete")
    head = (f"{len(items)} file(s) found: {good} look intact, {named} with their names"
            if items else "Nothing recoverable found in this image")
    return mtools.result("recover", "found" if items else "nothing-found", head,
                         "strong" if good else "weak" if items else "none",
                         evidence=[{"kind": "scan", "detail": n} for n in notes],
                         limits=["Undelete assumes a file wasn't fragmented; on cards most photos aren't, but "
                                 "large videos can be.", "Carved files lose their names and dates.",
                                 "Only recover cards you own: a second-hand card can hold other people's files."],
                         next_steps=["Save the files you want to a folder on the Mac (never the card)."],
                         image=mtools.home_short(image), items=items, partitions=[{"offset": o, "fs": k} for o, k in parts])


def last_scan():
    if not LAST_SCAN:
        p = os.path.join(recover_dir(), "scan-last.json")
        if os.path.exists(p):
            with open(p) as fh:
                d = json.load(fh)
            LAST_SCAN.update({"image": d["image"], "items": {i["id"]: i for i in d["items"]}})
    return LAST_SCAN


def item_bytes(item, image=None, limit=None):
    m = open_ro(image or last_scan()["image"])
    try:
        n = item["size"] if limit is None else min(item["size"], limit)
        return bytes(m[item["offset"]:item["offset"] + n])
    finally:
        m.close()


def save(ids, dest=None):
    """Write the chosen items from the last scan into dest (default ~/Downloads/Recovered <date>)."""
    s = last_scan()
    if not s:
        raise ValueError("scan an image first")
    dest = os.path.realpath(os.path.expanduser(dest or os.path.join(
        mg.HOME, "Downloads", f"Recovered {dt.date.today().isoformat()}")))
    if os.path.realpath(dest).startswith("/dev/"):
        raise ValueError("bad destination")
    chosen = list(s["items"].values()) if ids == "all" else [s["items"][i] for i in ids if i in s["items"]]
    chosen = [c for c in chosen if c.get("offset") is not None]
    if not chosen:
        raise ValueError("nothing to save: pick files that have data")
    need = sum(c["size"] for c in chosen)
    os.makedirs(dest, exist_ok=True)
    if need > shutil.disk_usage(dest).free:
        raise ValueError(f"not enough space: needs {mg.human(need)}")
    import macguard_photos as ph
    m = open_ro(s["image"])
    saved, failed = [], []
    try:
        for c in chosen:
            sub = os.path.dirname(c["path"]).strip("/") if c["source"] == "undelete" else "carved"
            name = re.sub(r"[/\x00]", "_", c["name"]) or "recovered"
            target = ph.unique(os.path.join(dest, sub, name))
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "xb") as fh:
                    fh.write(m[c["offset"]:c["offset"] + c["size"]])
                if c.get("modified"):
                    t = dt.datetime.fromisoformat(c["modified"]).timestamp()
                    os.utime(target, (t, t))
                saved.append(target)
            except OSError as e:
                failed.append({"name": c["name"], "why": e.strerror or str(e)})
    finally:
        m.close()
    return {"saved": len(saved), "failed": failed, "dest": dest, "bytes": need}


# ---------------------------------------------------------------- CLI

def cmd_image(args):
    C = mg.C
    if not args.target:
        raise SystemExit("give the card: macguard recover image disk4 (see macguard recover analyze)")
    p = image_plan(args.target, args.to)
    print(f"{C['B']}Image {p['name'] or p['ident']}{C['x']} ({mg.human(p['size'])}) → {mtools.home_short(p['image'])}")
    print(f"  {C['d']}read-only; using {'ddrescue' if p['ddrescue'] else 'the built-in reader'}; macOS asks for your "
          f"password once. Only recover cards you own.{C['x']}")
    if not args.apply:
        print(f"{C['y']}Dry run.{C['x']} Add --apply to start.")
        return
    r = image_device(args.target, args.to)
    print(f"{C['g']}✔{C['x']} {mtools.home_short(r['image'])}: {mg.human(r['size'])}"
          + (f", {r['bad_sectors']} unreadable sectors (zero-filled)" if r["bad_sectors"] else "")
          + f"\n  next: macguard recover scan \"{mtools.home_short(r['image'])}\"")


def cmd_scan(args):
    C = mg.C
    if not args.target:
        raise SystemExit("give an image file: macguard recover scan ~/Downloads/card.img")
    if args.save:
        r = save("all" if args.save == "all" else args.save.split(","), args.to)
        print(json.dumps(r, indent=2) if args.json else f"{C['g']}✔{C['x']} saved {r['saved']} file(s) to "
              f"{mtools.home_short(r['dest'])}" + "".join(f"\n  {C['r']}✘{C['x']} {f['name']}: {f['why']}" for f in r["failed"]))
        return
    r = scan(args.target, undelete=not args.no_undelete, do_carve=not args.no_carve, everything=args.everything)
    if args.json:
        print(json.dumps(r, indent=2, default=str))
        return
    print(f"{C['B']}{r['headline']}{C['x']}")
    for e in r["evidence"]:
        print(f"  {C['d']}{e['detail']}{C['x']}")
    col = {"intact": "g", "overwritten": "y", "damaged": "r", "lost": "r", "unchecked": "d"}
    for it in r["items"][:200]:
        print(f"  {it['id']:>5}  {C[col.get(it['state'], 'x')]}{it['state']:<11}{C['x']} {mg.human(it['size']):>8}  "
              f"{it['path'] or it['name']} {C['d']}{it['modified'][:16]} {it['note']}{C['x']}")
    if len(r["items"]) > 200:
        print(f"  … {len(r['items']) - 200} more (use --json)")
    print(f"\n  save: macguard recover scan IMAGE --save all|ID,ID [--to DIR]")
