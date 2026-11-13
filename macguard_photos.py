"""Photo sorter (docs/PHOTO-SORT.md): index a folder of photos first, then sort by event, month or kind.

The index (dates, camera, and what Apple's on-device Vision sees) comes from helpers/photo_sense.swift, compiled
once with swiftc. Without Swift it falls back to EXIF read in Python, file names and file dates: sorting by date
still works, kinds and similar photos don't, and the result says so.

Safety: nothing moves before a plan is shown. Copy is the default; a move is journalled first and can be undone;
tags only add Finder tags. Nothing is deleted. The Photos library is refused. Nothing leaves the Mac.
"""
import base64
import datetime as dt
import hashlib
import json
import math
import os
import plistlib
import re
import shutil
import sqlite3
import struct
import subprocess
import time
import uuid

import macguard as mg
import macguard_tools as mtools

HERE = os.path.dirname(os.path.abspath(__file__))
HELPER_SRC = os.path.join(HERE, "helpers", "photo_sense.swift")
BUNDLED_HELPER = os.path.join(HERE, "helpers", "photo_sense")

IMAGE_EXTS = {"jpg", "jpeg", "heic", "heif", "png", "gif", "webp", "tif", "tiff", "bmp", "avif",
              "dng", "cr2", "cr3", "nef", "nrw", "arw", "raf", "orf", "rw2", "pef", "srw", "raw"}
RAW_EXTS = {"dng", "cr2", "cr3", "nef", "nrw", "arw", "raf", "orf", "rw2", "pef", "srw", "raw"}
VIDEO_EXTS = {"mov", "mp4", "m4v", "3gp", "avi", "mts"}
SIDECAR_EXTS = {"aae", "xmp", "thm"}
SKIP_DIRS = {".git", "node_modules", ".Trash", "Library", ".photoslibrary"}

KIND_FOLDERS = {"photo": "Photos", "screenshot": "Screenshots", "document": "Documents and receipts",
                "saved": "Saved and shared", "video": "Videos", "duplicate": "Duplicates", "undated": "Undated"}
KIND_TAGS = {"photo": "Photo", "screenshot": "Screenshot", "document": "Document or receipt",
             "saved": "Saved image", "video": "Video", "duplicate": "Duplicate"}
GENERIC_LABELS = {"structure", "outdoor", "indoor", "material", "textile", "wood_processed", "liquid", "water_body",
                  "art", "illustrations", "document", "printed_page", "screenshot", "text", "adult", "sky", "land",
                  "consumer_electronics", "machine", "container", "furniture", "conveyance", "vehicle", "wood",
                  "plant", "grass", "people", "clothing", "headwear", "apparel", "animal", "mammal"}
SCREENSHOT_NAME = re.compile(r"^(Screenshot|Screen Shot|Simulator Screen Shot|CleanShot|Capture d.écran|"
                             r"Bildschirmfoto|Schermafbeelding|Captura de pantalla|スクリーンショット|截屏|屏幕截图)", re.I)
SAVED_NAME = re.compile(r"(WhatsApp Image|IMG-\d{8}-WA\d+|telegram|signal-\d{4}|FB_IMG|received_|Messenger|"
                        r"Snapchat|images?\(\d+\)|download(\s*\(\d+\))?$)", re.I)
NAME_DATES = [  # (pattern, has time)
    re.compile(r"(?<!\d)(20\d\d|19\d\d)[-_.]?(0[1-9]|1[0-2])[-_.]?([0-2]\d|3[01])[ T_-]?(?:at )?([01]\d|2[0-3])[.:_-]?([0-5]\d)[.:_-]?([0-5]\d)"),
    re.compile(r"(?<!\d)(20\d\d|19\d\d)[-_.](0[1-9]|1[0-2])[-_.]([0-2]\d|3[01])(?!\d)"),
    re.compile(r"(?<!\d)(20\d\d)(0[1-9]|1[0-2])([0-2]\d|3[01])(?!\d)"),
]
SIMILAR_DISTANCE = 0.45  # Vision feature print distance; measured: a rotated or cropped copy 0.26-0.41, other subjects 0.6+
SIMILAR_SECONDS = 10
BATCH = 150


def photos_dir():
    return os.path.join(mg.STATE_DIR, "photos")


def db_path():
    return os.path.join(photos_dir(), "index.sqlite")


def ensure_dir():
    os.makedirs(photos_dir(), mode=0o700, exist_ok=True)
    os.chmod(photos_dir(), 0o700)


def refuse_library(path):
    real = os.path.realpath(path)
    if ".photoslibrary" in real.split(os.sep)[-1] or any(p.endswith(".photoslibrary") for p in real.split(os.sep)):
        raise ValueError("That's inside a Photos library. Moving files there breaks the library, so the sorter "
                         "won't touch it. Export the photos from Photos first, or sort another folder.")


# ---------------------------------------------------------------- the Swift helper

def helper(compile_if_needed=True, run=subprocess.run):
    """Path to a working photo_sense binary, or None (then metadata comes from Python)."""
    forced = os.environ.get("MACGUARD_PHOTO_SENSE")
    if forced:
        return forced if os.path.exists(forced) else None
    if os.path.exists(BUNDLED_HELPER) and os.access(BUNDLED_HELPER, os.X_OK):
        return BUNDLED_HELPER  # the app bundles a prebuilt one
    if not os.path.exists(HELPER_SRC):
        return None
    with open(HELPER_SRC, "rb") as fh:
        want = hashlib.sha256(fh.read()).hexdigest()[:16]
    target = os.path.join(mg.STATE_DIR, "bin", "photo_sense")
    stamp = target + ".sha"
    if os.path.exists(target) and os.path.exists(stamp) and mg.read_text(stamp).strip() == want:
        return target
    swiftc = shutil.which("swiftc")
    if not (compile_if_needed and swiftc):
        return None
    os.makedirs(os.path.dirname(target), exist_ok=True)
    tmp = f"{target}.{os.getpid()}.tmp"
    r = run([swiftc, "-O", HELPER_SRC, "-o", tmp], capture_output=True, text=True, timeout=600)
    if r.returncode != 0 or not os.path.exists(tmp):
        return None
    os.replace(tmp, target)
    with open(stamp, "w") as fh:
        fh.write(want)
    return target


def sense(paths, binary, vision=True, run=subprocess.run):
    """Run the helper on a batch: {path: info}."""
    args = [binary] + ([] if vision else ["--no-vision"])
    r = run(args, input="\n".join(paths) + "\n", capture_output=True, text=True, timeout=60 + 20 * len(paths))
    out = {}
    for line in (r.stdout or "").splitlines():
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict) and d.get("path"):
            out[d["path"]] = d
    return out


def python_sense(path):
    """Fallback without the helper: EXIF from the start of the file (Python), no Vision."""
    import macguard_aicheck as ai
    out = {"path": path, "kind": "video" if ext_of(path) in VIDEO_EXTS else "image"}
    try:
        with open(path, "rb") as fh:
            head = fh.read(2 << 20)
        ex = None
        if head[:3] == b"\xff\xd8\xff":
            ex = ai.jpeg_parts(head)["exif"]
        elif head[:4] in (b"II*\x00", b"MM\x00*"):
            ex = ai.parse_tiff(head, 0)
        ex = ex or ai.find_exif(head) or {}
        for k in ("taken", "offset", "make", "model", "software"):
            if ex.get(k):
                out[k] = ex[k]
        if ex.get("gps"):
            out["gps"] = list(ex["gps"])
    except (OSError, ValueError, struct.error, IndexError):
        pass
    return out


# ---------------------------------------------------------------- index

SCHEMA = """CREATE TABLE IF NOT EXISTS photos (
  path TEXT PRIMARY KEY, root TEXT, size INTEGER, mtime REAL, qhash TEXT, sha TEXT, ext TEXT,
  taken TEXT, date_src TEXT, make TEXT, model TEXT, lat REAL, lon REAL, w INTEGER, h INTEGER, duration REAL,
  labels TEXT, faces INTEGER, textlines INTEGER, quality REAL, utility INTEGER, fp BLOB, vision INTEGER,
  error TEXT, indexed REAL)"""


def connect():
    ensure_dir()
    con = sqlite3.connect(db_path(), timeout=30)
    con.row_factory = sqlite3.Row
    con.execute(SCHEMA)
    con.execute("CREATE INDEX IF NOT EXISTS by_root ON photos(root)")
    os.chmod(db_path(), 0o600)
    return con


def ext_of(path):
    return os.path.splitext(path)[1].lower().lstrip(".")


def walk(root):
    """Media files under root (and sidecars, returned separately)."""
    media, sidecars = [], []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS and not d.endswith(
            (".photoslibrary", ".app", ".photolibrary", ".aplibrary"))]
        for f in files:
            if f.startswith("."):
                continue
            e = ext_of(f)
            p = os.path.join(dirpath, f)
            if e in IMAGE_EXTS or e in VIDEO_EXTS:
                media.append(p)
            elif e in SIDECAR_EXTS:
                sidecars.append(p)
    return sorted(media), sorted(sidecars)


def quick_hash(path, size):
    h = hashlib.sha256(str(size).encode())
    with open(path, "rb") as fh:
        h.update(fh.read(65536))
        if size > 131072:
            fh.seek(-65536, os.SEEK_END)
            h.update(fh.read(65536))
    return h.hexdigest()[:24]


def full_hash(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def name_date(name):
    for i, rx in enumerate(NAME_DATES):
        m = rx.search(name)
        if not m:
            continue
        g = [int(x) for x in m.groups()]
        try:
            return dt.datetime(*g[:3], *(g[3:6] if i == 0 else (12, 0, 0))).isoformat()
        except ValueError:
            continue
    return None


def resolve_date(info, path, mtime):
    """(ISO date, source): EXIF → video metadata → file name → file date (guessed)."""
    t = info.get("taken")
    if t:
        try:
            return dt.datetime.strptime(t[:19], "%Y:%m:%d %H:%M:%S").isoformat(), "exif"
        except ValueError:
            pass
    c = info.get("created")
    if c:
        try:
            utc = dt.datetime.strptime(c[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc)
            return utc.astimezone().replace(tzinfo=None).isoformat(), "video"
        except ValueError:
            pass
    n = name_date(os.path.basename(path))
    if n:
        return n, "name"
    return dt.datetime.fromtimestamp(mtime).replace(microsecond=0).isoformat(), "file"


def iso6709(s):
    m = re.match(r"([+-]\d+(?:\.\d+)?)([+-]\d+(?:\.\d+)?)", s or "")
    return (float(m.group(1)), float(m.group(2))) if m else None


def index(root, vision=True, stop=None, report=None, run=subprocess.run):
    """Build or update the index for root. Returns counts. Unchanged files (path, size, mtime) are skipped."""
    root = os.path.realpath(os.path.expanduser(root))
    if not os.path.isdir(root):
        raise ValueError(f"no such folder: {root}")
    refuse_library(root)
    media, _ = walk(root)
    con = connect()
    known = {r["path"]: (r["size"], r["mtime"], r["vision"]) for r in
             con.execute("SELECT path, size, mtime, vision FROM photos WHERE root = ?", (root,))}
    gone = set(known) - set(media)
    con.executemany("DELETE FROM photos WHERE path = ?", [(p,) for p in gone])
    todo, stats = [], {}
    for p in media:
        try:
            st = os.stat(p)
        except OSError:
            continue
        k = known.get(p)
        if k and k[0] == st.st_size and abs(k[1] - st.st_mtime) < 1 and (k[2] or not vision):
            continue
        stats[p] = st
    todo = list(stats)
    binary = helper(run=run)
    unreadable = 0
    for i in range(0, len(todo), BATCH):
        if stop and stop():
            break
        batch = todo[i:i + BATCH]
        infos = sense(batch, binary, vision, run) if binary else {}
        rows = []
        for p in batch:
            st = stats[p]
            info = infos.get(p) or python_sense(p)
            if ext_of(p) not in VIDEO_EXTS and not (info.get("taken") and info.get("make")):
                for k, v in python_sense(p).items():  # fill gaps ImageIO left (or a stub helper)
                    info.setdefault(k, v)
            if info.get("error"):
                unreadable += 1
            taken, src = resolve_date(info, p, st.st_mtime)
            gps = info.get("gps") or iso6709(info.get("iso6709"))
            fp = base64.b64decode(info["fp"]) if info.get("fp") else None
            try:
                qh = quick_hash(p, st.st_size)
            except OSError as e:
                info["error"] = str(e)
                qh = ""
            rows.append((p, root, st.st_size, st.st_mtime, qh, None, ext_of(p), taken, src, info.get("make") or "",
                         info.get("model") or "", gps[0] if gps else None, gps[1] if gps else None, info.get("w") or 0,
                         info.get("h") or 0, info.get("duration"), json.dumps(info.get("labels") or []),
                         info.get("faces"), info.get("text"), info.get("quality"),
                         None if info.get("utility") is None else int(bool(info["utility"])), fp,
                         int(bool(binary and vision and ("labels" in info or info.get("kind") == "video" or info.get("error")))), info.get("error") or "", time.time()))
        con.executemany(f"INSERT OR REPLACE INTO photos VALUES ({','.join('?' * 25)})", rows)
        con.commit()
        if report:
            report(done=min(i + BATCH, len(todo)), total=len(todo))
    con.commit()
    con.close()
    return {"root": root, "files": len(media), "updated": len(todo), "removed": len(gone), "unreadable": unreadable,
            "vision": bool(binary and vision), "helper": mtools.home_short(binary) if binary else ""}


def rows(root=None):
    """Indexed files under root (None = everything indexed)."""
    con = connect()
    if root is None:
        out = [dict(r) for r in con.execute("SELECT * FROM photos ORDER BY taken, path")]
    else:
        root = os.path.realpath(os.path.expanduser(root))
        out = [dict(r) for r in con.execute("SELECT * FROM photos WHERE root = ? ORDER BY taken, path", (root,))]
    con.close()
    for r in out:
        r["labels"] = json.loads(r["labels"] or "[]")
    return out


# ---------------------------------------------------------------- make sense of it

def fp_distance(a, b):
    if not a or not b or len(a) != len(b):
        return 9.0
    n = len(a) // 4
    x, y = struct.unpack(f"{n}f", a), struct.unpack(f"{n}f", b)
    return math.sqrt(sum((p - q) ** 2 for p, q in zip(x, y)))


def label_names(r, min_conf=0.3):
    return [l[0] for l in r["labels"] if l[1] >= min_conf]


def kind_of(r):
    name = os.path.basename(r["path"])
    labels = set(label_names(r))
    if r["ext"] in VIDEO_EXTS:
        return "video"
    if SCREENSHOT_NAME.match(name) or "screenshot" in labels:
        return "screenshot"
    if r["utility"] and (labels & {"document", "receipt", "printed_page", "whiteboard", "text"} or (r["textlines"] or 0) >= 5):
        return "document"
    if not r["make"] and r["ext"] == "png" and r["utility"]:
        return "screenshot"
    if r["make"] or r["ext"] in RAW_EXTS:
        return "photo"
    if SAVED_NAME.search(name) or (r["date_src"] in ("file", "name") and not r["make"]):
        return "saved"
    return "photo"


def km(a, b):
    lat1, lon1, lat2, lon2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371 * 2 * math.asin(math.sqrt(min(1, h)))


def analyse(items, gap_hours=3.0, trust_file_dates=False):
    """Adds kind, dup_of, similar group and event to every row. Returns (items, events)."""
    by_key = {}
    for r in items:
        r["kind"] = kind_of(r)
        r["dup_of"] = None
        if r["qhash"]:
            by_key.setdefault((r["size"], r["qhash"]), []).append(r)
    for group in by_key.values():
        if len(group) < 2:
            continue
        shas = {}
        for r in group:
            try:
                r["sha"] = r["sha"] or full_hash(r["path"])
            except OSError:
                continue
            shas.setdefault(r["sha"], []).append(r)
        for same in shas.values():
            # keep the oldest date, then the shortest name (no "copy", "(2)")
            same.sort(key=lambda r: (r["taken"] or "", len(os.path.basename(r["path"])), r["path"]))
            for r in same[1:]:
                r["dup_of"] = same[0]["path"]
                r["kind"] = "duplicate"
    # similar photos: bursts and retakes, close in time and in Vision's fingerprint
    photos = [r for r in items if r["kind"] == "photo" and r["fp"] and r["date_src"] == "exif"]
    photos.sort(key=lambda r: r["taken"])
    gid = 0
    for a, b in zip(photos, photos[1:]):
        ta, tb = dt.datetime.fromisoformat(a["taken"]), dt.datetime.fromisoformat(b["taken"])
        if (tb - ta).total_seconds() <= SIMILAR_SECONDS and fp_distance(a["fp"], b["fp"]) < SIMILAR_DISTANCE:
            if not a.get("similar"):
                gid += 1
                a["similar"] = gid
            b["similar"] = a["similar"]
    # events
    dated = [r for r in items if r["kind"] not in ("duplicate",) and (r["date_src"] != "file" or trust_file_dates)]
    dated.sort(key=lambda r: r["taken"])
    events, cur, last_gps = [], None, None
    for r in dated:
        t = dt.datetime.fromisoformat(r["taken"])
        gps = (r["lat"], r["lon"]) if r["lat"] is not None else None
        new = (cur is None or (t - cur["end"]).total_seconds() > gap_hours * 3600
               or (gps and last_gps and km(gps, last_gps) > 50))
        if new:
            cur = {"start": t, "end": t, "items": []}
            events.append(cur)
        cur["end"] = t
        cur["items"].append(r)
        last_gps = gps or last_gps
    for i, e in enumerate(events, 1):
        counts = {}
        for r in e["items"]:
            for l in label_names(r, 0.5):
                if l not in GENERIC_LABELS:
                    counts[l] = counts.get(l, 0) + 1
            if (r["faces"] or 0) > 0:
                counts["people"] = counts.get("people", 0) + 1
        top = [l.replace("_", " ") for l, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:2]
               if n >= max(1, len(e["items"]) // 5)]
        days = e["start"].strftime("%Y-%m-%d") + ("" if e["end"].date() == e["start"].date()
                                                  else e["end"].strftime(" to %d %b") if e["end"].year == e["start"].year
                                                  else e["end"].strftime(" to %Y-%m-%d"))
        e["id"] = i
        e["name"] = days + (" " + ", ".join(top).capitalize() if top else "")
        e["count"] = len(e["items"])
        for r in e["items"]:
            r["event"] = i
    return items, events


def safe_name(s):
    s = re.sub(r"[/:\x00-\x1f]", "-", s).strip(" .")
    return s[:120] or "Untitled"


def summary(root, gap_hours=3.0, trust_file_dates=False):
    items = rows(root)
    if not items:
        return mtools.result("photo-sort", "nothing-found", "Nothing indexed in this folder yet: index it first",
                             next_steps=[f"macguard photos index {mtools.home_short(root)}"])
    items, events = analyse(items, gap_hours, trust_file_dates)
    kinds, years, srcs = {}, {}, {}
    for r in items:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
        srcs[r["date_src"]] = srcs.get(r["date_src"], 0) + 1
        if r["date_src"] != "file" or trust_file_dates:
            years[r["taken"][:4]] = years.get(r["taken"][:4], 0) + 1
    dups = [r for r in items if r["kind"] == "duplicate"]
    similar = len({r["similar"] for r in items if r.get("similar")})
    follow = companions(*walk(os.path.realpath(os.path.expanduser(root))))  # Live Photo videos go with their photo
    undated = sum(1 for r in items if r["date_src"] == "file" and not trust_file_dates and r["kind"] != "duplicate"
                  and r["path"] not in follow)
    vision = sum(1 for r in items if r["vision"] and r["ext"] not in VIDEO_EXTS)
    images = sum(1 for r in items if r["ext"] not in VIDEO_EXTS)
    errors = [r for r in items if r["error"]]
    head = (f"{len(items)} files: {kinds.get('photo', 0)} photos, {kinds.get('screenshot', 0)} screenshots, "
            f"{kinds.get('document', 0)} documents, {kinds.get('video', 0)} videos, {len(events)} events"
            + (f", {len(dups)} duplicates ({mg.human(sum(r['size'] for r in dups))})" if dups else ""))
    limits = ["Dates come from the photo itself when it has one; otherwise from the file name, and then the file's "
              "own date, which only shows when it was copied. Those go to Undated unless you trust file dates."]
    if vision < images:
        limits.append(f"Apple Vision looked at {vision} of {images} pictures"
                      + ("" if vision else ": without Swift (Command Line Tools) kinds and similar photos aren't "
                         "available, sorting by date still works") + ".")
    return mtools.result(
        "photo-sort", "info", head, evidence=[], limits=limits,
        next_steps=["Make a plan: macguard photos plan FOLDER --by event (or month, kind)"],
        root=mtools.home_short(os.path.realpath(os.path.expanduser(root))), files=len(items), kinds=kinds,
        years=dict(sorted(years.items())), date_sources=srcs, duplicates=len(dups),
        duplicate_bytes=sum(r["size"] for r in dups), similar_groups=similar, undated=undated, vision=vision,
        unreadable=[{"path": mtools.home_short(r["path"]), "why": r["error"]} for r in errors[:50]],
        events=[{"id": e["id"], "name": e["name"], "count": e["count"],
                 "samples": [r["path"] for r in e["items"] if r["kind"] == "photo"][:4]} for e in events][-200:])


# ---------------------------------------------------------------- plan

def plans_dir():
    return os.path.join(photos_dir(), "plans")


def default_dest():
    return os.path.join(mg.HOME, "Pictures", f"Sorted Photos {dt.date.today().isoformat()}")


def companions(media, sidecars):
    """Live Photo videos, RAW+JPEG twins and edit sidecars: {follower path: leader path}."""
    stems = {}
    for p in media + sidecars:
        stems.setdefault(os.path.splitext(p)[0].lower(), []).append(p)
    follow = {}
    for group in stems.values():
        if len(group) < 2:
            continue
        rank = lambda p: (0 if ext_of(p) in ("heic", "jpg", "jpeg") else 1 if ext_of(p) in IMAGE_EXTS - RAW_EXTS
                          else 2 if ext_of(p) in RAW_EXTS else 3 if ext_of(p) in VIDEO_EXTS else 4)
        group.sort(key=rank)
        leader = group[0]
        if ext_of(leader) in VIDEO_EXTS or ext_of(leader) in SIDECAR_EXTS:
            continue
        for p in group[1:]:
            follow[p] = leader
    return follow


def plan(root, layout="event", dest=None, gap_hours=3.0, trust_file_dates=False):
    if layout not in ("event", "month", "kind"):
        raise ValueError("layout must be event, month or kind")
    root = os.path.realpath(os.path.expanduser(root))
    refuse_library(root)
    dest = os.path.realpath(os.path.expanduser(dest or default_dest()))
    refuse_library(dest)
    items = rows(root)
    if not items:
        raise ValueError("index this folder first (macguard photos index FOLDER)")
    items, events = analyse(items, gap_hours, trust_file_dates)
    ev = {e["id"]: e for e in events}
    media, sidecars = walk(root)
    follow = companions(media, sidecars)
    moves, by_path = [], {}
    for r in items:
        if r["path"] in follow:
            continue
        k = r["kind"]
        t = dt.datetime.fromisoformat(r["taken"])
        undated = r["date_src"] == "file" and not trust_file_dates
        month = t.strftime("%Y-%m %B")
        if k == "duplicate":
            rel = KIND_FOLDERS["duplicate"]
        elif undated:
            rel = KIND_FOLDERS["undated"] if layout != "kind" else os.path.join(KIND_FOLDERS[k], "Undated")
        elif layout == "kind":
            rel = os.path.join(KIND_FOLDERS[k], t.strftime("%Y"), month)
        elif layout == "month":
            rel = os.path.join(t.strftime("%Y"), month)
        elif k in ("photo", "video") and r.get("event"):
            rel = os.path.join(t.strftime("%Y"), month, safe_name(ev[r["event"]]["name"]))
        elif k in ("screenshot",):
            rel = os.path.join(KIND_FOLDERS[k], t.strftime("%Y-%m"))
        else:
            rel = os.path.join(KIND_FOLDERS[k], t.strftime("%Y"))
        m = {"src": r["path"], "dir": rel, "kind": k, "date": r["taken"], "date_src": r["date_src"],
             "event": ev[r["event"]]["name"] if r.get("event") in ev else "", "size": r["size"]}
        moves.append(m)
        by_path[r["path"]] = m
    for f, leader in follow.items():
        if leader in by_path:
            lm = by_path[leader]
            moves.append(dict(lm, src=f, size=os.path.getsize(f) if os.path.exists(f) else 0, companion=leader))
    counts = {}
    for m in moves:
        counts[m["dir"]] = counts.get(m["dir"], 0) + 1
    p = {"id": dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:4], "root": root, "dest": dest,
         "layout": layout, "created": time.time(), "moves": moves, "folders": dict(sorted(counts.items())),
         "bytes": sum(m["size"] for m in moves), "events": len(events),
         "skipped": [{"path": s, "why": "edit sidecar without its photo"} for s in sidecars if s not in follow]}
    os.makedirs(plans_dir(), mode=0o700, exist_ok=True)
    with open(os.path.join(plans_dir(), p["id"] + ".json"), "w") as fh:
        json.dump(p, fh)
    with open(os.path.join(plans_dir(), "last"), "w") as fh:
        fh.write(p["id"])
    return p


def load_plan(plan_id="last"):
    if plan_id in (None, "", "last"):
        last = os.path.join(plans_dir(), "last")
        if not os.path.exists(last):
            raise ValueError("no plan yet: make one with `macguard photos plan FOLDER`")
        plan_id = mg.read_text(last).strip()
    if not re.fullmatch(r"[\w-]+", plan_id or ""):
        raise ValueError("bad plan id")
    path = os.path.join(plans_dir(), plan_id + ".json")
    if not os.path.exists(path):
        raise ValueError(f"no plan {plan_id}")
    with open(path) as fh:
        return json.load(fh)


# ---------------------------------------------------------------- apply / undo

def unique(path):
    if not os.path.lexists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 2
    while os.path.lexists(f"{stem} ({i}){ext}"):
        i += 1
    return f"{stem} ({i}){ext}"


def existing_parent(path):
    while not os.path.exists(path):
        path = os.path.dirname(path)
    return path


def read_tags(path, run=subprocess.run):
    r = run(["xattr", "-px", "com.apple.metadata:_kMDItemUserTags", path], capture_output=True, text=True)
    if r.returncode != 0:
        return []
    try:
        return list(plistlib.loads(bytes.fromhex(re.sub(r"\s", "", r.stdout))))
    except (ValueError, plistlib.InvalidFileException):
        return []


def write_tags(path, tags, run=subprocess.run):
    now = read_tags(path, run)
    names = {t.split("\n")[0] for t in now}
    merged = now + [t for t in tags if t not in names]
    if merged == now:
        return True
    hexdata = plistlib.dumps(merged, fmt=plistlib.FMT_BINARY).hex()
    r = run(["xattr", "-wx", "com.apple.metadata:_kMDItemUserTags", hexdata, path], capture_output=True, text=True)
    return r.returncode == 0


def apply(plan_id="last", mode="copy", report=None, run=subprocess.run):
    """Carry out a plan. copy (default) | move (journalled, undoable) | tag (Finder tags, nothing moves)."""
    if mode not in ("copy", "move", "tag"):
        raise ValueError("mode must be copy, move or tag")
    p = load_plan(plan_id)
    refuse_library(p["root"])
    refuse_library(p["dest"])
    moves = [m for m in p["moves"] if os.path.exists(m["src"])]
    done, failed, journal = 0, [], None
    if mode == "tag":
        for i, m in enumerate(moves):
            tags = [KIND_TAGS.get(m["kind"], m["kind"])] + ([m["event"]] if m.get("event") else [])
            if write_tags(m["src"], tags, run):
                done += 1
            else:
                failed.append({"path": m["src"], "why": "couldn't write Finder tags (read-only disk?)"})
            if report and i % 50 == 0:
                report(done=i, total=len(moves))
        return {"mode": mode, "done": done, "failed": failed, "plan": p["id"], "dest": ""}
    os.makedirs(p["dest"], exist_ok=True)
    if mode == "move":
        if os.stat(existing_parent(p["dest"])).st_dev != os.stat(p["root"]).st_dev:
            raise ValueError("move only works on the same disk: choose copy (the default) to sort onto another disk")
        if not os.access(p["root"], os.W_OK):
            raise ValueError("this folder is read-only (a locked card?): choose copy")
        journal = os.path.join(photos_dir(), f"undo-{dt.datetime.now():%Y%m%d-%H%M%S}.jsonl")
    else:
        need = sum(os.path.getsize(m["src"]) for m in moves)
        free = shutil.disk_usage(existing_parent(p["dest"])).free
        if need > free * 0.98:
            raise ValueError(f"not enough free space: needs {mg.human(need)}, {mg.human(free)} free")
    jfh = open(journal, "a") if journal else None
    try:
        for i, m in enumerate(moves):
            target = unique(os.path.join(p["dest"], m["dir"], os.path.basename(m["src"])))
            try:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                if mode == "copy":
                    shutil.copy2(m["src"], target)
                else:
                    jfh.write(json.dumps({"from": m["src"], "to": target}) + "\n")
                    jfh.flush()
                    os.fsync(jfh.fileno())
                    os.rename(m["src"], target)
                done += 1
            except OSError as e:
                failed.append({"path": m["src"], "why": e.strerror or str(e)})
                if e.errno == 28:  # disk full: stop cleanly
                    break
            if report and i % 25 == 0:
                report(done=i, total=len(moves))
    finally:
        if jfh:
            jfh.close()
    return {"mode": mode, "done": done, "failed": failed, "plan": p["id"], "dest": p["dest"],
            "undo": mtools.home_short(journal) if journal else ""}


def journals():
    if not os.path.isdir(photos_dir()):
        return []
    return sorted(os.path.join(photos_dir(), f) for f in os.listdir(photos_dir())
                  if f.startswith("undo-") and f.endswith(".jsonl"))


def undo(journal=None):
    """Put every moved file back, newest first. Files whose old name is taken again are left and listed."""
    js = journals()
    journal = journal or (js[-1] if js else None)
    if not journal or not os.path.exists(journal):
        raise ValueError("nothing to undo: no moves were made")
    with open(journal) as fh:
        entries = [json.loads(l) for l in fh if l.strip()]
    back, left, dirs = 0, [], set()
    for e in reversed(entries):
        if os.path.exists(e["to"]) and not os.path.lexists(e["from"]):
            os.makedirs(os.path.dirname(e["from"]), exist_ok=True)
            os.rename(e["to"], e["from"])
            dirs.add(os.path.dirname(e["to"]))
            back += 1
        elif not os.path.exists(e["to"]):
            left.append({"path": e["to"], "why": "no longer there"})
        else:
            left.append({"path": e["to"], "why": f"{e['from']} exists again"})
    for d in sorted(dirs, key=len, reverse=True):  # tidy now-empty folders the sorter made
        while d and os.path.isdir(d) and not os.listdir(d):
            os.rmdir(d)
            d = os.path.dirname(d)
    os.replace(journal, journal + ".undone")
    return {"restored": back, "left": left, "journal": mtools.home_short(journal)}


def find(query, root=None, limit=200):
    items, events = analyse(rows(root))
    ev = {e["id"]: e["name"] for e in events}
    terms = [t.lower() for t in query.split() if t]
    out = []
    for r in items:
        hay = " ".join([os.path.basename(r["path"]), r["kind"], r["make"] or "", r["model"] or "", r["taken"] or "",
                        dt.datetime.fromisoformat(r["taken"]).strftime("%B %Y"), ev.get(r.get("event"), "")]
                       + [l.replace("_", " ") for l in label_names(r)]).lower()
        if all(t in hay for t in terms):
            out.append({"path": r["path"], "taken": r["taken"], "kind": r["kind"], "labels": label_names(r)[:4]})
    return out[:limit]


def thumbnail(path, run=subprocess.run):
    """A small JPEG of an indexed photo, made in memory (sips into a temp file that's removed at once)."""
    con = connect()
    ok = con.execute("SELECT 1 FROM photos WHERE path = ?", (path,)).fetchone()
    con.close()
    if not ok or ext_of(path) in VIDEO_EXTS:
        raise ValueError("not an indexed photo")
    tmp = os.path.join(photos_dir(), f"thumb-{uuid.uuid4().hex}.jpg")
    try:
        r = run(["sips", "-s", "format", "jpeg", "-Z", "320", path, "--out", tmp], capture_output=True, timeout=30)
        if r.returncode != 0 or not os.path.exists(tmp):
            raise ValueError("couldn't make a thumbnail")
        with open(tmp, "rb") as fh:
            return fh.read()
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


# ---------------------------------------------------------------- CLI

def cmd_photos(args):
    C = mg.C
    a = args.action
    if a == "index":
        def rep(done, total):
            print(f"\r  {done}/{total} files", end="", flush=True)
        root = args.target or "."
        print(f"Indexing {root} …" + ("" if args.no_vision else " (Apple Vision)"))
        r = index(root, vision=not args.no_vision, report=None if args.json else rep)
        if args.json:
            print(json.dumps(r, indent=2))
            return
        print(f"\r{C['g']}✔{C['x']} {r['files']} files ({r['updated']} new or changed, {r['removed']} gone)"
              + ("" if r["vision"] else f" {C['y']}without Vision{C['x']}: no Swift helper, dates only"))
        print(f"  {C['d']}next: macguard photos summary {root}{C['x']}")
        return
    if a == "summary":
        r = summary(args.target or ".", args.gap, args.trust_file_dates)
        if args.json:
            print(json.dumps(r, indent=2, default=str))
            return
        print(f"{C['B']}{r['headline']}{C['x']}")
        if r.get("years"):
            print("  by year: " + ", ".join(f"{y} {n}" for y, n in r["years"].items()))
            print(f"  date from: " + ", ".join(f"{k} {n}" for k, n in r["date_sources"].items())
                  + f" · undated {r['undated']} · similar groups {r['similar_groups']}")
            for e in r["events"][-15:]:
                print(f"  {C['d']}·{C['x']} {e['name']} {C['d']}({e['count']}){C['x']}")
        for l in r["limits"]:
            print(f"  {C['d']}{l}{C['x']}")
        return
    if a == "plan":
        p = plan(args.target or ".", args.by, args.to, args.gap, args.trust_file_dates)
        if args.json:
            print(json.dumps({k: v for k, v in p.items() if k != "moves"} | {"sample": p["moves"][:20]}, indent=2))
            return
        print(f"{C['B']}Plan {p['id']}{C['x']}: {len(p['moves'])} files ({mg.human(p['bytes'])}) into "
              f"{mtools.home_short(p['dest'])}, by {p['layout']}")
        for d, n in list(p["folders"].items())[:40]:
            print(f"  {n:>6}  {d}/")
        if len(p["folders"]) > 40:
            print(f"  … and {len(p['folders']) - 40} more folders")
        print(f"\n{C['y']}Nothing has moved.{C['x']} Copy: macguard photos apply · move (undoable): --move · tags only: --tag")
        return
    if a == "apply":
        mode = "move" if args.move else "tag" if args.tag else "copy"
        r = apply(args.plan or "last", mode)
        if args.json:
            print(json.dumps(r, indent=2))
            return
        print(f"{C['g']}✔{C['x']} {mode}: {r['done']} files" + (f" → {mtools.home_short(r['dest'])}" if r["dest"] else ""))
        for f in r["failed"][:10]:
            print(f"  {C['r']}✘{C['x']} {f['path']}: {f['why']}")
        if r.get("undo"):
            print(f"  {C['d']}undo: macguard photos undo{C['x']}")
        return
    if a == "undo":
        r = undo()
        print(json.dumps(r, indent=2) if args.json else f"{C['g']}✔{C['x']} put back {r['restored']} files"
              + (f", {len(r['left'])} left where they are" if r["left"] else ""))
        return
    if a == "find":
        hits = find(args.target or "", args.within)
        if args.json:
            print(json.dumps(hits, indent=2))
            return
        for h in hits[:50]:
            print(f"  {h['taken'][:16]}  {h['kind']:<10} {mtools.home_short(h['path'])} {C['d']}{', '.join(h['labels'])}{C['x']}")
        print(f"{len(hits)} match(es)")
