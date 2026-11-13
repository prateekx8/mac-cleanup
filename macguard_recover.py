"""Recover files, phase R1: light recovery and disk analysis (docs/RECOVERY.md). No root, never writes to a source.

Sources searched:
  trash      ~/.Trash and external volumes' .Trashes (directly, or through Finder when macOS blocks direct access)
  history    editor local history: VS Code, Cursor, Windsurf, Antigravity, VSCodium (older versions of files)
  git        lost commits and staged-then-lost files in a repo (git fsck --unreachable --no-reflogs)
  timemachine older versions of a file in Time Machine backups (when Time Machine is set up)
Also: local APFS snapshots (listed, with how to browse them) and where iCloud Drive and Photos keep deleted items.

Restoring always COPIES into a folder you pick (default ~/Downloads/Recovered <date>), never moves, never overwrites.
Analyze reads `diskutil` and says honestly what the chances are; deep recovery of cards comes in phase R2.
"""
import datetime as dt
import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys

import macguard as mg
import macguard_tools as tools

EDITORS = ("Code", "Code - Insiders", "Cursor", "Windsurf", "Antigravity", "VSCodium")
MAX_ITEMS = 500
FINDER_COUNT = 'with timeout of 15 seconds\ntell application "Finder" to count items of trash\nend timeout'
FINDER_TRASH = '''
with timeout of 90 seconds
  tell application "Finder" to set L to (items of trash) as alias list
end timeout
set out to ""
set n to 0
repeat with a in L
  set n to n + 1
  if n > 500 then exit repeat
  set out to out & POSIX path of a & linefeed
end repeat
return out
'''
FINDER_LIMIT = 2000  # more items than this and Finder takes minutes; open the Trash in Finder instead
GUIDANCE = [
    {"source": "iCloud Drive", "where": "icloud.com › Drive › Recently Deleted",
     "detail": "Files deleted from iCloud Drive stay there for 30 days."},
    {"source": "Photos", "where": "Photos app › Recently Deleted (in the sidebar)",
     "detail": "Deleted photos and videos stay there for 30 days, on every device using iCloud Photos."},
    {"source": "Notes", "where": "Notes app › Recently Deleted folder", "detail": "Deleted notes stay there for 30 days."},
]


def item_id(source, path, extra=""):
    return hashlib.sha1(f"{source}|{path}|{extra}".encode()).hexdigest()[:12]


def iso(ts):
    try:
        return dt.datetime.fromtimestamp(float(ts)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def matches(query, *texts):
    if not query:
        return True
    q = query.lower().strip()
    if "*" in q or "?" in q:
        import fnmatch
        return any(fnmatch.fnmatch((t or "").lower(), q) or fnmatch.fnmatch(os.path.basename(t or "").lower(), q)
                   for t in texts)
    return any(q in (t or "").lower() for t in texts)


def size_of(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            total = 0
            for d, _, files in os.walk(path):
                for f in files:
                    try:
                        total += os.lstat(os.path.join(d, f)).st_size
                    except OSError:
                        pass
            return total
        return os.lstat(path).st_size
    except OSError:
        return 0


# ---------------------------------------------------------------- Trash

def trash_dirs():
    dirs = [os.path.join(mg.HOME, ".Trash")]
    uid = str(os.getuid())
    try:
        for v in os.listdir("/Volumes"):
            d = os.path.join("/Volumes", v, ".Trashes", uid)
            if os.path.isdir(d):
                dirs.append(d)
    except OSError:
        pass
    return dirs


def finder_error(err):
    if "-1743" in err or "Not authorized" in err:
        return ("macOS didn't allow Finder access. Allow it in System Settings › Privacy & Security › Automation "
                "(your terminal or Mac Cleanup › Finder), or give Full Disk Access.")
    if "-1712" in err or "timed out" in err:
        return ("Finder didn't answer in time: macOS may be showing a permission prompt (answer it, then try again), "
                "or the Trash is very large (open it in Finder instead).")
    return f"Finder couldn't list the Trash: {err.strip()[:160]}"


def finder_trash():
    """([(path, mtime, size)], error). Asks Finder, which may show a one-time macOS permission prompt."""
    rc, out, err = mg.run(["osascript", "-e", FINDER_COUNT], timeout=20)
    if rc != 0:
        return None, finder_error(err or "timed out")
    try:
        count = int(out.strip())
    except ValueError:
        count = 0
    if count > FINDER_LIMIT:
        return None, (f"The Trash holds {count} items, too many to list through Finder quickly. Open the Trash in "
                      "Finder (search there), or give Full Disk Access so Mac Cleanup can read it directly.")
    rc, out, err = mg.run(["osascript", "-e", FINDER_TRASH], timeout=100)
    if rc != 0:
        return None, finder_error(err or "timed out")
    rows = []
    for p in out.splitlines():
        if not p.strip():
            continue
        try:
            st = os.lstat(p.rstrip("/"))
            rows.append((p, st.st_mtime, st.st_size if not p.endswith("/") else 0))
        except OSError:
            rows.append((p, 0.0, 0))
    return rows, None


def search_trash(query, finder=False):
    """(items, notes). Direct listing first; through Finder only when asked (finder=True), since macOS may prompt."""
    items, notes, blocked = [], [], False
    for d in trash_dirs():
        try:
            names = os.listdir(d)
        except PermissionError:
            blocked = True
            continue
        except OSError:
            continue
        for n in names:
            if n in (".DS_Store", ".localized"):
                continue
            p = os.path.join(d, n)
            if not matches(query, n):
                continue
            try:
                mtime = os.lstat(p).st_mtime
            except OSError:
                mtime = 0
            items.append({"id": item_id("trash", p), "source": "trash", "name": n, "path": p, "original": "",
                          "modified": iso(mtime), "size": size_of(p), "kind": "folder" if os.path.isdir(p) else "file",
                          "via": "direct"})
    if blocked and not finder:
        notes.append("macOS protects the Trash, so it wasn't searched. Read it through Finder (--finder, or the button "
                     "in the app; macOS may ask once to allow it), or give Full Disk Access to your terminal or Mac "
                     "Cleanup. You can also open the Trash in Finder and use File › Put Back.")
    elif blocked:
        rows, err = finder_trash()
        if rows is None:
            notes.append(err)
        else:
            notes.append("Read the Trash through Finder.")
            seen = {i["path"] for i in items}
            for p, mtime, size in rows:
                n = os.path.basename(p.rstrip("/"))
                if p in seen or not matches(query, n):
                    continue
                items.append({"id": item_id("trash", p.rstrip("/")), "source": "trash", "name": n, "path": p.rstrip("/"),
                              "original": "", "modified": iso(mtime) if mtime else "", "size": size,
                              "kind": "folder" if p.endswith("/") else "file", "via": "finder"})
    return items, notes


# ---------------------------------------------------------------- editor local history

def history_roots():
    base = os.path.join(mg.HOME, "Library/Application Support")
    return [(app, os.path.join(base, app, "User/History")) for app in EDITORS
            if os.path.isdir(os.path.join(base, app, "User/History"))]


def file_path_of(resource):
    if resource.startswith("file://"):
        from urllib.parse import unquote, urlparse
        return unquote(urlparse(resource).path)
    return resource


def search_history(query, keep=5):
    """Older versions of files that VS Code-style editors saved (newest `keep` per file)."""
    items = []
    for app, root in history_roots():
        try:
            folders = os.listdir(root)
        except OSError:
            continue
        for f in folders:
            meta = os.path.join(root, f, "entries.json")
            try:
                with open(meta) as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                continue
            original = file_path_of(data.get("resource") or "")
            if not original or not matches(query, original):
                continue
            entries = sorted(data.get("entries") or [], key=lambda e: -(e.get("timestamp") or 0))[:keep]
            for e in entries:
                p = os.path.join(root, f, e.get("id") or "")
                if not os.path.isfile(p):
                    continue
                items.append({"id": item_id("history", p), "source": "history", "app": app,
                              "name": os.path.basename(original), "path": p, "original": original,
                              "modified": iso((e.get("timestamp") or 0) / 1000), "size": size_of(p), "kind": "version",
                              "via": e.get("source") or ""})
    return items


# ---------------------------------------------------------------- git

def git(repo, *args, timeout=60):
    try:
        p = subprocess.run(["git", "-C", repo, *args], capture_output=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired) as e:
        return 1, b"", str(e)


def repo_root(path):
    rc, out, _ = git(path, "rev-parse", "--show-toplevel", timeout=10)
    return out.decode().strip() if rc == 0 else None


def search_git(repo, query=None, blob_limit=50):
    """Lost commits (reset away, deleted branches) and staged-then-lost file contents."""
    root = repo_root(repo)
    if not root:
        return [], [f"{tools.home_short(repo)} isn't inside a git repository."]
    rc, out, err = git(root, "fsck", "--unreachable", "--no-reflogs", "--no-progress", timeout=300)
    if rc != 0:
        return [], [f"git fsck failed: {err.strip()[:200]}"]
    items, blobs = [], 0
    for line in out.decode("utf-8", "replace").splitlines():
        m = re.match(r"unreachable (commit|blob) ([0-9a-f]{40})", line)
        if not m:
            continue
        kind, sha = m.groups()
        if kind == "commit":
            _, info, _ = git(root, "log", "-1", "--format=%ct%x09%an%x09%s", sha, timeout=10)
            ts, author, subject = (info.decode("utf-8", "replace").strip().split("\t") + ["", "", ""])[:3]
            if not matches(query, subject, sha):
                continue
            _, stat, _ = git(root, "show", "--stat", "--format=", sha, timeout=20)
            items.append({"id": item_id("git", root, sha), "source": "git", "kind": "commit", "name": subject or sha[:12],
                          "sha": sha, "repo": root, "path": root, "original": "", "modified": iso(ts), "author": author,
                          "size": 0, "detail": stat.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]})
        else:
            if blobs >= blob_limit:
                continue
            _, content, _ = git(root, "cat-file", "-p", sha, timeout=10)
            head = content[:2000].decode("utf-8", "replace")
            if b"\0" in content[:2000] and query:
                continue
            first = next((l.strip() for l in head.splitlines() if l.strip()), "")[:120]
            if not matches(query, head, sha):
                continue
            blobs += 1
            items.append({"id": item_id("git", root, sha), "source": "git", "kind": "blob", "sha": sha, "repo": root,
                          "name": first or f"blob {sha[:12]}", "path": root, "original": "", "modified": "",
                          "size": len(content), "detail": [first]})
    items.sort(key=lambda i: (i["kind"] != "commit", i["modified"]), reverse=False)
    return items, []


# ---------------------------------------------------------------- Time Machine and snapshots

def timemachine_state():
    """{configured, backups: [paths], error}."""
    rc, out, err = mg.run(["tmutil", "destinationinfo"], timeout=20)
    configured = rc == 0 and "No destinations configured" not in (out + err)
    backups, error = [], ""
    if configured:
        rc, out, err = mg.run(["tmutil", "listbackups"], timeout=60)
        if rc == 0:
            backups = [l.strip() for l in out.splitlines() if l.strip().startswith("/")]
        else:
            error = (err or out).strip()[:200] or "Time Machine backups aren't reachable right now"
    return {"configured": configured, "backups": backups, "error": error}


def timemachine_versions(path, backups):
    """Copies of `path` inside each backup (backup/<volume>/<path as seen from that volume>)."""
    path = os.path.abspath(os.path.expanduser(path))
    rels = [path.lstrip("/")]
    if path.startswith("/Users/"):
        rels.append(os.path.join("System/Volumes/Data", path.lstrip("/")))
    out = []
    for b in backups:
        try:
            vols = os.listdir(b)
        except OSError:
            continue
        for v in vols:
            for rel in rels:
                cand = os.path.join(b, v, rel)
                if os.path.exists(cand):
                    out.append({"id": item_id("timemachine", cand), "source": "timemachine",
                                "name": os.path.basename(path), "path": cand, "original": path,
                                "modified": os.path.basename(b.rstrip("/")).replace(".backup", ""),
                                "size": size_of(cand), "kind": "folder" if os.path.isdir(cand) else "file", "via": b})
                    break
    return out


def local_snapshots():
    rc, out, _ = mg.run(["tmutil", "listlocalsnapshots", "/"], timeout=20)
    names = re.findall(r"(com\.apple\.TimeMachine\.\S+)", out) if rc == 0 else []
    return [{"name": n, "date": (re.search(r"(\d{4}-\d{2}-\d{2}-\d{6})", n) or [None, ""])[1]} for n in names]


# ---------------------------------------------------------------- search and restore

SOURCES = ("trash", "history", "git", "timemachine")


def search(query=None, sources=SOURCES, repo=None, path=None, finder=False):
    """Everything recoverable that matches, newest first, plus notes, snapshot and guidance info."""
    items, notes = [], []
    if "trash" in sources:
        found, n = search_trash(query, finder)
        items += found
        notes += n
    if "history" in sources:
        items += search_history(query)
    if "git" in sources and repo:
        found, n = search_git(repo, query)
        items += found
        notes += n
    tm = timemachine_state() if "timemachine" in sources else {"configured": None, "backups": [], "error": ""}
    if tm["configured"] and path:
        items += timemachine_versions(path, tm["backups"])
    snaps = local_snapshots()
    items.sort(key=lambda i: i.get("modified") or "", reverse=True)
    tm_note = ("Time Machine isn't set up, so there are no backups to restore from. Turn it on in System Settings › "
               "General › Time Machine for next time." if tm["configured"] is False else
               tm["error"] or (f"{len(tm['backups'])} Time Machine backup(s). Give a file path (--path) to find its "
                               "older versions." if tm["configured"] else ""))
    if tm_note:
        notes.append(tm_note)
    found = len(items)
    r = tools.result("recover", "found" if found else "nothing-found",
                     f"Found {found} recoverable item(s)" if found else "Nothing matching was found in the places searched",
                     "strong" if found else "none",
                     evidence=[{"kind": s, "detail": f"{sum(1 for i in items if i['source'] == s)} item(s)"} for s in sources],
                     limits=["Files deleted from this Mac's internal SSD after the Trash was emptied can't be brought back "
                             "by scanning (encrypted storage and TRIM). Backups and snapshots are the way."],
                     next_steps=["Restore copies a file into a folder you pick; nothing is moved or overwritten."],
                     query=query or "", items=items[:MAX_ITEMS], truncated=len(items) > MAX_ITEMS, notes=notes,
                     snapshots=snaps, guidance=GUIDANCE, timemachine=tm)
    if snaps:
        r["next"].append(f"{len(snaps)} local Time Machine snapshot(s): open the folder in Finder, then Time Machine › "
                         "Browse Time Machine Backups to step back in time.")
    return r


def default_dest():
    return os.path.join(mg.HOME, "Downloads", f"Recovered {dt.date.today().isoformat()}")


def unique(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    n = 2
    while os.path.exists(f"{stem} ({n}){ext}"):
        n += 1
    return f"{stem} ({n}){ext}"


def check_dest(dest):
    dest = os.path.abspath(os.path.expanduser(dest))
    trash = os.path.join(mg.HOME, ".Trash")
    if dest == trash or dest.startswith(trash + os.sep) or "/.Trashes/" in dest + "/":
        raise ValueError("pick a folder outside the Trash")
    if dest.startswith(("/System/", "/usr/", "/bin/", "/sbin/")):
        raise ValueError("pick a folder in your home folder or on another disk")
    return dest


def restore(item, dest=None):
    """Copy one item into dest (created if needed). Returns {ok, path, detail}. Never moves, never overwrites."""
    dest = check_dest(dest or default_dest())
    os.makedirs(dest, exist_ok=True)
    src, name = item["path"], item["name"]
    if item["source"] == "git":
        root = item["repo"]
        if item["kind"] == "commit":
            branch = f"recovered/{item['sha'][:10]}"
            rc, _, err = git(root, "branch", branch, item["sha"], timeout=20)
            if rc != 0:
                return {"ok": False, "detail": err.strip()[:200]}
            return {"ok": True, "path": root, "detail": f"Created branch {branch} in {tools.home_short(root)}: "
                                                         f"git switch {branch} to look at it."}
        rc, content, err = git(root, "cat-file", "-p", item["sha"], timeout=20)
        if rc != 0:
            return {"ok": False, "detail": err.strip()[:200]}
        out = unique(os.path.join(dest, f"git-blob-{item['sha'][:10]}.txt"))
        with open(out, "wb") as fh:
            fh.write(content)
        return {"ok": True, "path": out, "detail": f"Saved to {tools.home_short(out)}"}
    if item["source"] == "history":
        stem, ext = os.path.splitext(name)
        out = unique(os.path.join(dest, f"{stem} ({item['modified'].replace(':', '.')}){ext}"))
    else:
        out = unique(os.path.join(dest, name))
    if item.get("via") == "finder":  # only Finder can read the Trash here: let it make the copy
        q = lambda p: p.replace("\\", "\\\\").replace('"', '\\"')
        script = (f'tell application "Finder" to duplicate (POSIX file "{q(src)}" as alias) '
                  f'to (POSIX file "{q(dest)}" as alias)')
        rc, _, err = mg.run(["osascript", "-e", script], timeout=600)
        copied = os.path.join(dest, os.path.basename(src.rstrip("/")))
        return {"ok": rc == 0, "path": copied, "detail": f"Copied to {tools.home_short(dest)}" if rc == 0 else
                f"Finder couldn't copy it: {err.strip()[:200]}"}
    try:
        if os.path.isdir(src) and not os.path.islink(src):
            shutil.copytree(src, out, symlinks=True)
        else:
            shutil.copy2(src, out, follow_symlinks=False)
    except PermissionError:
        return {"ok": False, "detail": "macOS blocked reading it. Give Full Disk Access, or copy it in Finder."}
    except OSError as e:
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
    return {"ok": True, "path": out, "detail": f"Copied to {tools.home_short(out)}"}


# ---------------------------------------------------------------- analyze disks and cards

def disk_info(ident):
    rc, out, _ = mg.run(["diskutil", "info", "-plist", ident], timeout=20)
    if rc != 0:
        return None
    try:
        return plistlib.loads(out.encode())
    except Exception:
        return None


def devices():
    """External disks and cards, each with its volumes and a quick verdict."""
    rc, out, _ = mg.run(["diskutil", "list", "-plist", "external", "physical"], timeout=20)
    if rc != 0:
        return []
    try:
        data = plistlib.loads(out.encode())
    except Exception:
        return []
    found = []
    for d in data.get("AllDisksAndPartitions", []):
        ident = d.get("DeviceIdentifier")
        if not ident:
            continue
        found.append(analyze(ident, quick=True))
    return [f for f in found if f]


def list_plist(ident):
    rc, out, _ = mg.run(["diskutil", "list", "-plist", ident], timeout=20)
    if rc != 0:
        return {}
    try:
        disks = plistlib.loads(out.encode()).get("AllDisksAndPartitions") or [{}]
        return disks[0]
    except Exception:
        return {}


def volumes_of(ident, depth=0):
    """diskutil info for every volume on a disk: partitions, APFS volumes, and APFS containers on physical stores."""
    entry, vols = list_plist(ident), []
    ids = [p.get("DeviceIdentifier") for p in entry.get("Partitions", [])] + \
          [v.get("DeviceIdentifier") for v in entry.get("APFSVolumes", [])]
    for vid in filter(None, ids):
        vi = disk_info(vid)
        if not vi:
            continue
        if vi.get("FilesystemType"):
            if vi.get("Content") != "EFI" and vi.get("VolumeName") != "EFI":
                vols.append(vi)
        elif vi.get("APFSContainerReference") and depth < 2:
            vols += volumes_of(vi["APFSContainerReference"], depth + 1)
    return vols


FS_NAMES = {"msdos": "FAT32", "exfat": "exFAT", "apfs": "APFS", "hfs": "Mac OS Extended (HFS+)", "ntfs": "NTFS"}


def verdict_for(info):
    """(chance, why, steps) for one volume or disk."""
    fs = (info.get("FilesystemType") or "").lower()
    internal, ssd = info.get("Internal"), info.get("SolidState")
    encrypted = info.get("Encryption") or info.get("FileVault")
    if internal and (ssd or fs == "apfs"):
        return ("none", "This is the Mac's internal SSD: its storage is encrypted and macOS erases freed space "
                        "(TRIM), so deleted files can't be found by scanning.",
                ["Use the Trash, Time Machine, local snapshots or iCloud's Recently Deleted (macguard recover)."])
    if fs == "apfs" and encrypted:
        return ("very low", "Encrypted APFS: deleted blocks are unreadable ciphertext, and SSDs usually erase them.",
                ["Check Time Machine and snapshots on this disk instead."])
    if fs == "apfs" and ssd:
        return ("low", "APFS on an SSD: freed space is usually erased (TRIM) soon after deletion.",
                ["Stop writing to it now. Deep recovery (phase R2/R3) may still find recent files."])
    if fs in ("msdos", "exfat", "") or info.get("RemovableMedia") or info.get("Removable"):
        return ("good", "Memory cards and USB sticks (FAT32/exFAT) keep deleted data until it's written over.",
                ["Stop using the card now: don't take photos or copy files to it.",
                 "Recover to a different disk, never to the card itself."])
    return ("possible", "Deleted data may still be on the disk until it's written over.",
            ["Stop writing to it now. Recover to a different disk."])


def analyze(ident, quick=False):
    """What's on this disk or card, and the honest chances of getting deleted files back."""
    ident = ident.replace("/dev/", "").replace("rdisk", "disk")
    if not re.match(r"^disk\d+(s\d+)*$", ident):
        raise ValueError("give a disk identifier like disk4 or disk4s1 (see `diskutil list external`)")
    whole = disk_info(ident)
    if not whole:
        return None
    vols = volumes_of(ident)
    if not vols and whole.get("FilesystemType"):
        vols = [whole]
    per_volume = []
    for v in vols:
        chance, why, steps = verdict_for({**whole, **v})
        free = v.get("FreeSpace") or v.get("APFSContainerFree") or 0
        per_volume.append({"id": v.get("DeviceIdentifier"), "name": v.get("VolumeName") or "",
                           "fs": FS_NAMES.get((v.get("FilesystemType") or "").lower(), v.get("FilesystemName") or "?"),
                           "mounted": bool(v.get("MountPoint")), "mount": v.get("MountPoint") or "",
                           "size": v.get("TotalSize") or v.get("Size") or 0, "free": free, "encrypted": bool(v.get("Encryption")),
                           "chance": chance, "why": why, "steps": steps})
    chance, why, steps = verdict_for(whole) if not per_volume else \
        min(((p["chance"], p["why"], p["steps"]) for p in per_volume),
            key=lambda c: ["good", "possible", "low", "very low", "none"].index(c[0]))
    rec = {"id": ident, "name": whole.get("MediaName") or whole.get("IORegistryEntryName") or "",
           "size": whole.get("TotalSize") or whole.get("Size") or 0, "internal": bool(whole.get("Internal")),
           "removable": bool(whole.get("RemovableMedia") or whole.get("Removable") or whole.get("Ejectable")),
           "protocol": whole.get("BusProtocol") or "", "ssd": bool(whole.get("SolidState")),
           "smart": whole.get("SMARTStatus") or "Not reported", "volumes": per_volume,
           "chance": chance, "why": why}
    if quick:
        return rec
    deep = [h for h in tools.helpers() if h["name"] == "photorec"][0]
    if chance in ("good", "possible", "low"):
        steps = steps + [f"Deep recovery: image the card first (macguard recover image {ident} --apply, or Image this "
                         "card in Tools; one password prompt, read-only), then scan the image for deleted files.",
                         "Optional, for more formats: PhotoRec " + ("is installed" if deep["path"] else
                         "(brew install testdisk)") + ", run on the image file, not the card."]
    if rec["smart"] not in ("Verified", "Not reported", "Not Supported"):
        steps.insert(0, f"SMART status is {rec['smart']}: the device may be failing. Copy what you can first.")
    return tools.result("recover", "info", f"{rec['name'] or ident}: chance of recovery {chance}",
                        {"good": "strong", "possible": "moderate", "low": "weak", "very low": "weak", "none": "none"}[chance],
                        evidence=[{"kind": "diskutil", "detail": f"{rec['protocol']} · {'internal' if rec['internal'] else 'external'}"
                                   f" · {'SSD' if rec['ssd'] else 'disk/card'} · SMART {rec['smart']}"}] +
                        [{"kind": "volume", "detail": f"{v['name'] or v['id']}: {v['fs']}, {mg.human(v['size'])}"
                                                      f"{', encrypted' if v['encrypted'] else ''}"} for v in per_volume],
                        limits=["This is an estimate from the disk type. Every write since the deletion lowers the chances."],
                        next_steps=steps, disk=rec)


# ---------------------------------------------------------------- CLI

def print_items(items):
    by = {}
    for i in items:
        by.setdefault(i["source"], []).append(i)
    labels = {"trash": "Trash", "history": "Editor history (older versions)", "git": "Git (lost commits and files)",
              "timemachine": "Time Machine"}
    for src, rows in by.items():
        print(f"\n{mg.C['B']}{labels.get(src, src)}{mg.C['x']} ({len(rows)})")
        for i in rows[:40]:
            where = tools.home_short(i.get("original") or i.get("repo") or "")
            print(f"  {mg.C['d']}{i['id']}{mg.C['x']}  {i['name'][:60]:<60} {mg.C['d']}{i['modified'][:16]:<16} "
                  f"{mg.human(i['size']) if i['size'] else '':>7}  {where[:60]}{mg.C['x']}")
        if len(rows) > 40:
            print(f"  {mg.C['d']}… {len(rows) - 40} more (--json for all){mg.C['x']}")


def cmd_recover(args):
    if args.action in ("image", "scan"):
        import macguard_carve as cv
        try:
            (cv.cmd_image if args.action == "image" else cv.cmd_scan)(args)
        except ValueError as e:
            sys.exit(str(e))
        return
    if args.action == "analyze":
        if not args.target:
            devs = devices()
            if args.json:
                print(json.dumps(devs, indent=1, default=str))
                return
            if not devs:
                print("No external disks or memory cards connected. Plug in the card (in a reader), then try again.")
                return
            print(f"{mg.C['B']}Connected disks and cards{mg.C['x']}")
            for d in devs:
                print(f"  {d['id']:<8} {d['name'][:28]:<28} {mg.human(d['size']):>7}  {d['protocol']:<6} "
                      f"chance: {d['chance']:<9} {mg.C['d']}{', '.join(v['name'] or v['id'] for v in d['volumes'])}{mg.C['x']}")
            print(f"\n{mg.C['d']}Details: macguard recover analyze <disk>{mg.C['x']}")
            return
        try:
            r = analyze(args.target)
        except ValueError as e:
            sys.exit(str(e))
        if not r:
            sys.exit(f"No disk {args.target}. See: diskutil list external")
        if args.json:
            print(json.dumps(r, indent=1, default=str))
            return
        print(f"{mg.C['B']}{r['headline']}{mg.C['x']}\n  {r['disk']['why']}")
        for e in r["evidence"]:
            print(f"  {mg.C['d']}· {e['detail']}{mg.C['x']}")
        print(f"\n{mg.C['B']}What to do{mg.C['x']}")
        for s in r["next"]:
            print(f"  - {s}")
        return
    sources = tuple(s.strip() for s in (args.source or ",".join(SOURCES)).split(",") if s.strip())
    bad = set(sources) - set(SOURCES)
    if bad:
        sys.exit(f"unknown source(s): {', '.join(sorted(bad))}. Known: {', '.join(SOURCES)}")
    repo = args.repo or (os.getcwd() if "git" in sources and repo_root(os.getcwd()) else None)
    r = search(args.search, sources, repo=repo, path=args.path, finder=args.finder)
    if args.restore:
        item = next((i for i in r["items"] if i["id"] == args.restore), None)
        if not item:
            sys.exit(f"No item {args.restore} in this search. Run the same search again and copy its id.")
        dest = check_dest(args.to or default_dest())
        print(f"Restore a COPY of {item['name']}\n  from {tools.home_short(item['path'])}\n  to   {tools.home_short(dest)}")
        if not args.apply:
            print(f"\n{mg.C['d']}Dry run. Add --apply to copy it (nothing is moved or overwritten).{mg.C['x']}")
            return
        out = restore(item, dest)
        print(("✔ " if out["ok"] else "✘ ") + out["detail"])
        return
    if args.json:
        print(json.dumps(r, indent=1, default=str))
        return
    print(f"{mg.C['B']}{r['headline']}{mg.C['x']}" + (f" for '{args.search}'" if args.search else ""))
    print_items(r["items"])
    if r["notes"]:
        print(f"\n{mg.C['B']}Notes{mg.C['x']}")
        for n in r["notes"]:
            print(f"  - {n}")
    print(f"\n{mg.C['B']}Also look here{mg.C['x']}")
    for g in r["guidance"]:
        print(f"  - {g['source']}: {g['where']} {mg.C['d']}({g['detail']}){mg.C['x']}")
    for n in r["next"]:
        print(f"  - {n}")
    if r["items"]:
        print(f"\n{mg.C['d']}Restore a copy: macguard recover --search '{args.search or ''}'{' --finder' if args.finder else ''} --restore <id> [--to DIR] --apply"
              f"{mg.C['x']}")
