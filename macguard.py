#!/usr/bin/python3
"""mac-cleanup (macguard) - clean, monitor and secure a macOS development machine.

Commands:
  scan                 Disk junk analysis (read-only)
  clean                Clean junk (dry-run unless --apply)
  net                  Network snapshot: listeners, connections, ARP/DNS, threats
  security             Security posture audit (firewall, SIP, launch agents, ...)
  apps                 Installed apps: broken/missing signatures, outdated, risky, EOL
  traffic              Sample live traffic: heavy uploads, scanning, odd ports
  uninstall APP        Remove an app and all its ~/Library data (to the Trash); --leftovers-only resets it
  watch                Continuously monitor network, alert on anomalies
  report               Full HTML report (scan + net + security), opens in browser
  ui                   Small local web UI: scan, pick categories, clean, run checks
  doctor               Check prerequisites; --bundle writes a support file
  settings             Show/change settings; `settings background_watcher on` runs
                       `watch` in the background at login (off by default)

Stdlib only. Nothing is deleted without `clean --apply` and a confirmation.
"""
__version__ = "1.0.0"

import argparse
import datetime as dt
import glob
import html
import ipaddress
import json
import os
import plistlib
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".macguard")
BASELINE = os.path.join(STATE_DIR, "baseline.json")
EVENTS_LOG = os.path.join(STATE_DIR, "events.log")
SETTINGS = os.path.join(STATE_DIR, "settings.json")
AGENT_LABEL = "ai.macguard.watch"
AGENT_PLIST = os.path.join(HOME, "Library/LaunchAgents", AGENT_LABEL + ".plist")

C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m", "d": "\033[2m", "B": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str))
        return p.returncode, p.stdout, p.stderr
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 1, "", str(e)


def human(n):
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit in ("B", "K") else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def du(path):
    """Size in bytes via du (fast, handles permissions quietly)."""
    if not os.path.exists(path):
        return 0
    _, out, _ = run(["du", "-sk", path], timeout=600)
    try:
        return int(out.split()[0]) * 1024
    except (IndexError, ValueError):
        return 0


def ensure_state():
    os.makedirs(STATE_DIR, exist_ok=True)


# ---------------------------------------------------------------- disk / cleanup

H = HOME
# risk: "safe" = pure cache, regenerated automatically; "review" = you should decide.
JUNK = [
    dict(id="xcode-derived", name="Xcode DerivedData", risk="safe", paths=[f"{H}/Library/Developer/Xcode/DerivedData/*"]),
    dict(id="xcode-devicesupport", name="Xcode iOS DeviceSupport", risk="safe",
         paths=[f"{H}/Library/Developer/Xcode/*DeviceSupport/*"], note="re-created when a device is connected"),
    dict(id="sim-unavailable", name="Unavailable iOS simulators", risk="safe", special="simctl"),
    dict(id="sim-caches", name="CoreSimulator caches", risk="safe", paths=[f"{H}/Library/Developer/CoreSimulator/Caches/*"]),
    dict(id="npm", name="npm cache", risk="safe", paths=[f"{H}/.npm/_cacache"], cmd="npm cache clean --force"),
    dict(id="pip-uv", name="pip / uv / pkg caches", risk="safe",
         paths=[f"{H}/.cache/pip", f"{H}/.cache/uv", f"{H}/.cache/pkg", f"{H}/Library/Caches/pip"]),
    dict(id="gradle", name="Gradle caches", risk="safe", paths=[f"{H}/.gradle/caches", f"{H}/.gradle/daemon"],
         note="re-downloaded on next build"),
    dict(id="maven", name="Maven repository", risk="review", paths=[f"{H}/.m2/repository"]),
    dict(id="cargo", name="Cargo registry cache", risk="safe", paths=[f"{H}/.cargo/registry/cache", f"{H}/.cargo/registry/src"]),
    dict(id="brew", name="Homebrew cache & old versions", risk="safe", paths=[f"{H}/Library/Caches/Homebrew"], cmd="brew cleanup -s --prune=all"),
    dict(id="docker-build-cache", name="Docker build cache", risk="safe", special="docker-build-cache",
         note="next build is slower once"),
    dict(id="docker-dangling", name="Docker dangling images (untagged)", risk="safe", special="docker-dangling"),
    dict(id="docker-stopped", name="Docker stopped containers", risk="review", special="docker-stopped",
         note="compose recreates one-shot jobs; check none hold data you need"),
    dict(id="docker-unused-images", name="Docker images no container uses", risk="review", special="docker-unused-images"),
    dict(id="docker-unused-volumes", name="Docker volumes no container uses", risk="review", special="docker-unused-volumes",
         note="volumes hold data - deleting is permanent"),
    dict(id="user-logs", name="User logs", risk="safe", paths=[f"{H}/Library/Logs/*"]),
    dict(id="selenium-prisma", name="Selenium / Prisma / Puppeteer caches", risk="safe",
         paths=[f"{H}/.cache/selenium", f"{H}/.cache/prisma", f"{H}/.cache/puppeteer", f"{H}/.cache/ms-playwright"]),
    dict(id="jetbrains-old", name="Old JetBrains IDE versions", risk="safe", special="jetbrains"),
    dict(id="docker-install-tmp", name="Stuck Docker installer download", risk="review",
         paths=[f"{H}/Library/Application Support/com.docker.install/in_progress"], note="quit Docker Desktop first"),
    dict(id="hf-models", name="Hugging Face model downloads", risk="review", paths=[f"{H}/.cache/huggingface/hub/models--*"],
         note="re-downloaded when a model is next used"),
    dict(id="android-avd", name="Android emulator images (AVDs)", risk="review", paths=[f"{H}/.android/avd/*"]),
    dict(id="android-ndk-old", name="Old Android NDK versions", risk="review", special="ndk"),
    dict(id="project-artifacts", name="Stale project folders (node_modules/target/build, untouched 30+ days)", risk="review",
         special="projects"),
    dict(id="build-outputs", name="Build output in active projects (target, build, dist, .next, caches)", risk="review",
         special="builds", note="optional - rebuilt on the next build; stop dev servers first"),
    dict(id="trash", name="Trash", risk="review", paths=[f"{H}/.Trash/*"]),
    dict(id="downloads-old", name="Downloads older than 90 days", risk="review", special="downloads"),
    dict(id="app-leftovers", name="Leftovers from uninstalled apps", risk="review", special="orphans",
         note="moved to the Trash, not deleted"),
]

DEPENDENCY_DIRS = {"node_modules", ".venv", "venv"}  # slow to reinstall: only ever offered when the project is stale
BUILD_DIRS = {"target", ".next", ".nuxt", ".turbo", ".parcel-cache", ".svelte-kit", ".angular", "DerivedData", "__pycache__",
              ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle"}
ARTIFACT_DIRS = DEPENDENCY_DIRS | BUILD_DIRS
# "build"/"dist" only count when next to a known build file, to avoid deleting real folders named build
GUARDED_ARTIFACTS = {"build": ("build.gradle", "build.gradle.kts", "package.json", "CMakeLists.txt", "setup.py", "pyproject.toml"),
                     "dist": ("package.json", "setup.py", "pyproject.toml")}


def project_roots():
    roots = [os.path.join(HOME, d) for d in ("DEV", "Projects", "Developer", "code", "src", "workspace", "repos")]
    return [r for r in roots if os.path.isdir(r)]


def newest_mtime(project, skip):
    """Most recent mtime of source files in a project (ignores artifact dirs), shallow-ish."""
    newest = 0
    for root, dirs, files in os.walk(project):
        dirs[:] = [d for d in dirs if d not in ARTIFACT_DIRS and d not in GUARDED_ARTIFACTS and not d.startswith(".") and d != skip]
        if root.count(os.sep) - project.count(os.sep) > 3:
            dirs[:] = []
        for f in files:
            try:
                newest = max(newest, os.lstat(os.path.join(root, f)).st_mtime)
            except OSError:
                pass
    return newest


def is_artifact(d, files):
    """Is folder `d` (inside a dir containing `files`) a build/dependency output?"""
    if d == "target":
        return "Cargo.toml" in files or "pom.xml" in files
    if d.startswith("cmake-build-"):
        return "CMakeLists.txt" in files
    return d in ARTIFACT_DIRS or (d in GUARDED_ARTIFACTS and any(f in files for f in GUARDED_ARTIFACTS[d]))


_tracked_cache = {}


def git_tracked_dirs(path):
    """(repo top, set of folders holding git-tracked files) for the repo containing `path`; (None, set()) outside git."""
    rc, top, _ = run(["git", "-C", path, "rev-parse", "--show-toplevel"], timeout=10)
    top = top.strip() if rc == 0 else None
    if not top:
        return None, set()
    if top not in _tracked_cache:
        _, out, _ = run(["git", "-C", top, "ls-files", "-z"], timeout=60)
        dirs = set()
        for f in out.split("\0"):
            parts = f.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                dirs.add("/".join(parts[:i]))
        _tracked_cache[top] = dirs
    return top, _tracked_cache[top]


def is_git_tracked(full):
    """True when any file under `full` is committed - then it's source, not build output (e.g. a committed dist/)."""
    top, dirs = git_tracked_dirs(os.path.dirname(full))
    return bool(top) and os.path.relpath(os.path.realpath(full), os.path.realpath(top)) in dirs


_artifact_cache = {}


def find_project_artifacts(stale_days=30):
    """Build and dependency folders in project roots; cached for a minute so one scan walks the disk once."""
    hit = _artifact_cache.get(stale_days)
    if hit and time.time() - hit[0] < 60:
        return [dict(a) for a in hit[1]]
    _tracked_cache.clear()
    found = []
    cutoff = time.time() - stale_days * 86400
    for base in project_roots():
        for root, dirs, files in os.walk(base):
            if root.count(os.sep) - base.count(os.sep) > 6:
                dirs[:] = []
                continue
            keep = []
            for d in dirs:
                full = os.path.join(root, d)
                if is_artifact(d, files) and not os.path.islink(full):
                    if is_git_tracked(full):
                        continue  # committed output (e.g. a published dist/) is source - never offered
                    last = newest_mtime(root, d)
                    found.append({"path": full, "project": root, "stale": last < cutoff,
                                  "kind": "deps" if d in DEPENDENCY_DIRS else "build",
                                  "last_touched": dt.datetime.fromtimestamp(last).strftime("%Y-%m-%d") if last else "?"})
                elif not d.startswith(".") or d in (".github",):
                    keep.append(d)
            dirs[:] = keep
    for f in found:
        f["size"] = du(f["path"])
    found.sort(key=lambda x: -x["size"])
    _artifact_cache[stale_days] = (time.time(), found)
    return [dict(a) for a in found]


def simctl_unavailable():
    rc, out, _ = run(["xcrun", "simctl", "list", "devices", "unavailable", "-j"])
    if rc:
        return []
    items = []
    for runtime, devs in json.loads(out).get("devices", {}).items():
        for d in devs:
            p = d.get("dataPath") or os.path.join(HOME, "Library/Developer/CoreSimulator/Devices", d["udid"])
            items.append(os.path.dirname(p) if p.endswith("/data") else p)
    return items


def docker_size(text):
    """'1.01GB' / '552MB' / '4.1kB (virtual 3.59GB)' -> bytes (docker reports decimal units)."""
    m = re.match(r"\s*([\d.]+)\s*([kKMGT]?B)", text or "")
    if not m:
        return 0
    return int(float(m.group(1)) * {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(2)])


def docker_lines(*args, timeout=30):
    """JSON lines from a docker CLI call, [] when docker is missing or its engine isn't running."""
    if not shutil.which("docker"):
        return []
    rc, out, _ = run(["docker", *args, "--format", "{{json .}}"], timeout=timeout)
    rows = []
    for line in out.splitlines() if rc == 0 else []:
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    return rows


def docker_entries(kind):
    """(display 'name (id)', bytes, label) per removable docker object of one kind."""
    if kind == "docker-build-cache":
        for row in docker_lines("system", "df"):
            if row.get("Type") == "Build Cache":
                n = docker_size(row.get("Reclaimable"))
                return [("build cache", n, f"{row.get('TotalCount', '?')} entries")] if n else []
        return []
    if kind == "docker-stopped":
        return [(f"{c['Names']} ({c['ID'][:12]})", docker_size(c.get("Size")), f"{c['Image']} - {c['Status']}")
                for c in docker_lines("ps", "-a", "--filter", "status=exited", "--filter", "status=created", "--size")]
    if kind == "docker-unused-volumes":
        used = {m for c in docker_lines("ps", "-a") for m in (c.get("Mounts") or "").split(",") if m}
        sizes = {}
        for row in docker_lines("system", "df", "-v", timeout=60):
            for v in row.get("Volumes") or []:
                sizes[v.get("Name")] = docker_size(v.get("Size"))
        return [(f"{v['Name']} (volume)", sizes.get(v["Name"], 0), v.get("Driver", ""))
                for v in docker_lines("volume", "ls", "--filter", "dangling=true") if v["Name"][:20] not in {u[:20] for u in used}]
    images = docker_lines("images", "--no-trunc")
    in_use = {c.get("Image") for c in docker_lines("ps", "-a")} | {c.get("ImageID", "")[:19] for c in docker_lines("ps", "-a")}
    out = []
    for im in images:
        iid = im["ID"].replace("sha256:", "")[:12]
        name = f"{im['Repository']}:{im['Tag']}"
        dangling = im["Repository"] == "<none>"
        if kind == "docker-dangling" and dangling:
            out.append((f"<none> ({iid})", docker_size(im.get("Size")), im.get("CreatedSince", "")))
        elif kind == "docker-unused-images" and not dangling and name not in in_use and im["Repository"] not in in_use \
                and not any(iid in (x or "") for x in in_use):
            out.append((f"{name} ({iid})", docker_size(im.get("Size")), f"created {im.get('CreatedSince', '?')}"))
    return out


def docker_clean(kind, entries):
    """Remove exactly the listed docker objects; returns bytes freed (as reported at scan time)."""
    ids = [m.group(1) for d, _, _ in entries for m in [re.search(r"\(([0-9a-f]{12})\)$", d)] if m]
    freed = 0
    if kind == "docker-build-cache":
        rc, _, _ = run(["docker", "builder", "prune", "-a", "-f"], timeout=900)
        return sum(e[1] for e in entries) if rc == 0 else 0
    if kind == "docker-unused-volumes":
        for d, size, _ in entries:
            name = d.rsplit(" (volume)", 1)[0]
            if run(["docker", "volume", "rm", name], timeout=120)[0] == 0:
                freed += size
        return freed
    cmd = ["docker", "rm"] if kind == "docker-stopped" else ["docker", "rmi"]
    for (d, size, _), iid in zip([e for e in entries if re.search(r"\(([0-9a-f]{12})\)$", e[0])], ids):
        rc, _, err = run(cmd + [iid], timeout=300)  # never --force: in-use objects stay
        if rc == 0:
            freed += size
        else:
            print(f"   {C['y']}kept{C['x']} {d}: {err.strip()[:120]}")
    return freed


def version_key(name):
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", name)]


def old_versions(pattern, group_re):
    """For dirs like IntelliJIdea2025.3 / IntelliJIdea2026.2, return all but the newest per product."""
    groups = {}
    for p in glob.glob(pattern):
        m = re.match(group_re, os.path.basename(p))
        if m and os.path.isdir(p):
            groups.setdefault(m.group(1), []).append(p)
    old = []
    for paths in groups.values():
        paths.sort(key=lambda p: version_key(os.path.basename(p)))
        old += paths[:-1]
    return old


def resolve(item, stale_days=30):
    """Return list of (path, size, label) for a junk category."""
    sp = item.get("special")
    if sp == "simctl":
        paths = simctl_unavailable()
    elif sp and sp.startswith("docker-"):
        return docker_entries(sp)
    elif sp == "jetbrains":
        paths = old_versions(f"{HOME}/Library/Application Support/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+") + \
            old_versions(f"{HOME}/Library/Caches/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+") + \
            old_versions(f"{HOME}/Library/Logs/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+")
    elif sp == "ndk":
        paths = old_versions(f"{HOME}/Library/Android/sdk/ndk/*", r"(\d+)\.")  # keep newest per major
    elif sp == "projects":
        return [(a["path"], a["size"], f"last edited {a['last_touched']}")
                for a in find_project_artifacts(stale_days) if a["stale"] and a["size"] > 1 << 20]
    elif sp == "orphans":
        return orphan_leftovers()
    elif sp == "builds":  # active projects only (stale ones are in "projects"), and never dependencies
        return [(a["path"], a["size"], f"project edited {a['last_touched']}")
                for a in find_project_artifacts(stale_days) if not a["stale"] and a["kind"] == "build" and a["size"] > 1 << 20]
    elif sp == "downloads":
        cutoff = time.time() - 90 * 86400
        out = []
        for p in glob.glob(f"{HOME}/Downloads/*"):
            try:
                if os.lstat(p).st_mtime < cutoff:
                    out.append((p, du(p), ""))
            except OSError:
                pass
        return out
    else:
        paths = [p for pat in item["paths"] for p in glob.glob(pat)]
    return [(p, du(p), "") for p in paths if os.path.exists(p)]


def cmd_scan(args):
    print("Scanning (disk, caches, Docker, folder growth)...", flush=True)
    rep = space_report(args.stale_days)
    d = rep["disk"]
    col = C["r"] if d["critical"] else (C["y"] if d["low"] else "")
    print(f"\n{C['B']}Disk{C['x']}  {human(d['used'])} used / {human(d['total'])}  {col}({human(d['free'])} free){C['x']}")
    if d["low"]:
        print(f"  {col}{'CRITICAL' if d['critical'] else 'LOW'}: builds, updates and apps can start failing. Clean below.{C['x']}")
    print()
    for r in rep["results"]:
        print_junk(r)
    safe = sum(r["size"] for r in rep["results"] if r["risk"] == "safe")
    review = sum(r["size"] for r in rep["results"] if r["risk"] == "review")
    print(f"\n{C['g']}Safe to clean: {human(safe)}{C['x']}   {C['y']}Needs review: {human(review)}{C['x']}")
    if rep["since"] is not None:
        print(f"\n{C['B']}Grew since {dt.datetime.fromtimestamp(rep['since']):%b %d %H:%M}{C['x']}")
        for p, before, now in rep["grew"][:10]:
            print(f"  {C['y']}+{human(now - before):>7}{C['x']}  {p}  {C['d']}({human(before)} -> {human(now)}){C['x']}")
        if not rep["grew"]:
            print(f"  {C['d']}nothing grew by more than 512M{C['x']}")
    else:
        print(f"\n{C['d']}Folder sizes saved; the next scan (an hour or more from now) shows what grew.{C['x']}")
    if rep["managed"]:
        print(f"\n{C['B']}Managed by apps (remove from the app itself){C['x']}")
        for m in rep["managed"]:
            print(f"  {human(m['size']):>7}  {m['name']}  {C['d']}- {m['how']}{C['x']}")
    print(f"\n{C['B']}Largest folders{C['x']}")
    for p, n in rep["big"]:
        print(f"  {human(n):>7}  {p}")
    print(f"\nNext: {C['B']}macguard clean{C['x']} (dry-run)  ->  {C['B']}macguard clean --apply{C['x']}")


def print_junk(r):
    if r["size"] <= 0:
        return
    col = C["g"] if r["risk"] == "safe" else C["y"]
    print(f"  {human(r['size']):>7}  {col}{r['risk']:<6}{C['x']} {r['id']:<22} {r['name']}"
          + (f" {C['d']}({r['note']}){C['x']}" if r.get("note") else ""))
    if r["risk"] == "review" or (r.get("special") or "").startswith(("docker-", "jetbrains", "ndk")):
        for p, size, label in sorted(r["entries"], key=lambda e: -e[1])[:8]:
            print(f"           {C['d']}{human(size):>7}  {p.replace(HOME, '~')}  {label}{C['x']}")


def scan_junk(stale_days=30, verbose=False):
    results = []
    for item in JUNK:
        entries = resolve(item, stale_days)
        r = {**item, "entries": entries, "size": sum(e[1] for e in entries)}
        results.append(r)
        if verbose:
            print_junk(r)
    return results


LOW_DISK_BYTES = 10 * 1024 ** 3


def disk_health(d=None):
    """Free-space status: low under 10 GB or 10%, critical under 5 GB or 5%."""
    d = dict(d or disk_info())
    d["low"] = d["free"] < LOW_DISK_BYTES or d["free"] < d["total"] * 0.10
    d["critical"] = d["free"] < LOW_DISK_BYTES / 2 or d["free"] < d["total"] * 0.05
    return d


def measure_dirs():
    """Sizes of the folders that usually hide big growth: app data, containers, dot-dirs, projects."""
    pats = [f"{HOME}/Library/Application Support/*", f"{HOME}/Library/Containers/*", f"{HOME}/Library/Group Containers/*",
            f"{HOME}/.[!.]*", f"{HOME}/Downloads", f"{HOME}/Movies", f"{HOME}/Documents", f"{HOME}/Desktop"]
    pats += [f"{r}/*" for r in project_roots()] + [f"{r}/*/*" for r in project_roots()]
    sizes = {}
    for pat in pats:
        for p in glob.glob(pat):
            if os.path.isdir(p) and not os.path.islink(p) and p.replace(HOME, "~") not in sizes:
                n = du(p)
                if n >= 50 * 1024 ** 2:
                    sizes[p.replace(HOME, "~")] = n
    return sizes


def big_dirs(sizes=None, n=10):
    sizes = sizes if sizes is not None else measure_dirs()
    # parents and children both appear for project roots; keep the list readable
    return sorted(sizes.items(), key=lambda x: -x[1])[:n]


def sizes_file():
    return os.path.join(STATE_DIR, "sizes.json")


def record_sizes(sizes, keep=30):
    ensure_state()
    try:
        hist = json.loads(read_text(sizes_file()))
    except (OSError, ValueError):
        hist = []
    hist.append({"t": time.time(), "sizes": sizes})
    write_json(sizes_file(), hist[-keep:])
    return hist[:-1]


def growth(sizes, history, min_delta=512 * 1024 ** 2, min_age=3600):
    """Folders that grew by min_delta+ since the newest snapshot at least min_age old."""
    older = [h for h in history if time.time() - h["t"] >= min_age]
    if not older:
        return None, []
    base = older[-1]
    rows = [(p, base["sizes"].get(p, 0), now) for p, now in sizes.items() if now - base["sizes"].get(p, 0) >= min_delta]
    # drop a parent when one of its children explains the growth (DEV vs DEV/project)
    rows = [r for r in rows if not any(o[0].startswith(r[0] + "/") for o in rows)]
    return base["t"], sorted(rows, key=lambda r: -(r[2] - r[1]))


def managed_storage():
    """Big data that its own app must remove - reported, never deleted by macguard."""
    items = [
        ("Claude Cowork workspace image", f"{HOME}/Library/Application Support/Claude/vm_bundles",
         "Claude app > Settings > Storage > Remove (downloads again when Cowork is next used)"),
        ("Docker Desktop virtual disk", f"{HOME}/Library/Containers/com.docker.docker/Data/vms/0/data/Docker.raw",
         "Clean the Docker items above; space returns to macOS gradually. Cap it in Docker Desktop > Settings > Resources"),
        ("Ollama models", f"{HOME}/.ollama/models", "ollama list, then ollama rm <model>"),
        ("iPhone / iPad backups", f"{HOME}/Library/Application Support/MobileSync/Backup", "Finder > your device > Manage Backups"),
        ("Xcode archives", f"{HOME}/Library/Developer/Xcode/Archives", "Xcode > Window > Organizer > Archives"),
        ("Simulator runtimes", "/Library/Developer/CoreSimulator/Volumes", "xcrun simctl runtime list, then xcrun simctl runtime delete <id>"),
    ]
    out = []
    for name, path, how in items:
        n = du(path) if os.path.exists(path) else 0
        if n >= 100 * 1024 ** 2:
            out.append(dict(name=name, path=path.replace(HOME, "~"), size=n, how=how))
    _, snaps, _ = run(["tmutil", "listlocalsnapshots", "/"], timeout=20)
    count = sum(1 for l in snaps.splitlines() if "com.apple" in l)
    if count:
        out.append(dict(name=f"{count} Time Machine local snapshot{'s' if count > 1 else ''}", path="/", size=0,
                        how="macOS frees these when space runs low; tmutil thinlocalsnapshots / forces it"))
    return sorted(out, key=lambda x: -x["size"])


def space_report(stale_days=30):
    """Everything a cleanup decision needs, in one pass."""
    results = scan_junk(stale_days)
    sizes = measure_dirs()
    since, grew = growth(sizes, record_sizes(sizes))
    return dict(disk=disk_health(), results=results, big=big_dirs(sizes), since=since, grew=grew, managed=managed_storage())


def cmd_clean(args):
    results = scan_junk(args.stale_days)
    wanted = set(args.only.split(",")) if args.only else None
    if getattr(args, "builds", False):
        wanted = (wanted or set()) | {"build-outputs"}
    plan = [r for r in results if r["size"] > 0 and ((wanted and r["id"] in wanted) or (not wanted and r["risk"] == "safe"))]
    if not plan:
        print("Nothing to clean." + ("" if wanted else " (review-level items need --only <id>)"))
        return
    total = sum(r["size"] for r in plan)
    for r in plan:
        print(f"  {human(r['size']):>7}  {r['id']:<20} {r['name']}")
        if r["risk"] == "review":
            for p, s, label in r["entries"]:
                print(f"           {C['d']}{human(s):>7}  {p.replace(HOME, '~')}  {label}{C['x']}")
    print(f"  {C['B']}{human(total):>7}  total{C['x']}")
    if not args.apply:
        print(f"\n{C['y']}Dry run.{C['x']} Re-run with --apply to delete. Review items: --only " +
              ",".join(r["id"] for r in results if r["risk"] == "review" and r["size"]))
        return
    if not args.yes:
        if input(f"\nDelete the above ({human(total)})? Type 'yes': ").strip() != "yes":
            print("Aborted.")
            return
    ensure_state()
    freed = 0
    for r in plan:
        freed += clean_item(r)
    log_event("clean", f"freed ~{human(freed)} ({', '.join(r['id'] for r in plan)})")
    print(f"\n{C['g']}Done. Freed ~{human(freed)}.{C['x']}")


def clean_item(r):
    sp = r.get("special")
    print(f"{C['b']}-> {r['name']}{C['x']}")
    if sp == "simctl":
        run(["xcrun", "simctl", "delete", "unavailable"], timeout=600)
        return r["size"]
    if sp and sp.startswith("docker-"):
        return docker_clean(sp, r["entries"])
    if sp == "orphans":  # app data is recoverable from the Trash, unlike caches
        freed = 0
        for p, size, _ in r["entries"]:
            if p.startswith(HOME + "/Library/") and os.path.lexists(p):
                ok, err = trash(p)
                freed += size if ok else 0
                if not ok:
                    print(f"   {C['r']}failed{C['x']} {p}: {err}")
        return freed
    if r.get("cmd") and shutil.which(r["cmd"].split()[0]):
        run(r["cmd"], timeout=900)
    freed = 0
    for p, size, _ in r["entries"]:
        if not os.path.exists(p):
            freed += size
            continue
        if not p.startswith(HOME + "/") or p.count("/") < 4:  # guard rail
            print(f"   skip (unsafe path) {p}")
            continue
        try:
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.remove(p)
            freed += size
        except OSError as e:
            print(f"   {C['r']}failed{C['x']} {p}: {e.strerror}")
    return freed


# ---------------------------------------------------------------- network

SUSPICIOUS_PORTS = {23: "telnet", 4444: "metasploit default", 1337: "common backdoor", 31337: "back orifice",
                    6666: "IRC (botnet C2)", 6667: "IRC (botnet C2)", 6697: "IRC (botnet C2)",
                    5555: "adb / backdoor", 12345: "netbus", 9001: "Tor", 9050: "Tor SOCKS", 3333: "crypto-mining pool",
                    14444: "crypto-mining pool", 45700: "crypto-mining pool"}
RISKY_LISTEN = {22: "SSH", 5900: "Screen Sharing (VNC)", 3283: "Apple Remote Desktop", 445: "SMB file sharing",
                548: "AFP file sharing", 5000: "AirPlay Receiver", 7000: "AirPlay Receiver",
                3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                11434: "Ollama", 2375: "Docker API (unauthenticated!)", 8080: "dev server", 3000: "dev server"}
SUSPICIOUS_EXE_DIRS = ("/tmp/", "/private/tmp/", "/private/var/folders/", "/Users/Shared/", HOME + "/Downloads/", "/var/tmp/")

_exe_cache, _sig_cache = {}, {}


def exe_path(pid):
    if pid not in _exe_cache:
        _, out, _ = run(["ps", "-o", "comm=", "-p", str(pid)])
        _exe_cache[pid] = out.strip()
    return _exe_cache[pid]


def signature(path):
    """('apple'|'developer:<Team>'|'adhoc'|'unsigned'|'unknown')."""
    if not path or not path.startswith("/"):
        return "unknown"
    if path in _sig_cache:
        return _sig_cache[path]
    if not os.path.exists(path):
        _sig_cache[path] = "missing"
        return "missing"
    _, _, err = run(["codesign", "-dv", "--verbose=2", path], timeout=15)
    if "not signed" in err:
        s = "unsigned"
    elif "Signature=adhoc" in err:
        s = "adhoc"
    elif "Authority=Software Signing" in err or "Platform identifier" in err or path.startswith(("/System/", "/usr/", "/bin/", "/sbin/")):
        s = "apple"
    else:
        m = re.search(r"Authority=Developer ID Application: (.+)", err) or re.search(r"Authority=Apple Development: (.+)", err) \
            or re.search(r"TeamIdentifier=(\w+)", err)
        s = f"developer:{m.group(1).strip()}" if m else "unknown"
    _sig_cache[path] = s
    return s


def split_addr(a):
    """'192.168.1.5.443' / '2001:db8::6.54386' / '*.5000' -> (host, port)."""
    if "." not in a:
        return a, None
    host, _, port = a.rpartition(".")
    return host, (int(port) if port.isdigit() else None)


def is_private(host):
    if host in ("*", "127.0.0.1", "::1", "localhost"):
        return True
    # netstat truncates long IPv6 addresses, so classify link-local/ULA/multicast by prefix
    if host.lower().startswith(("fe80:", "fc", "fd", "ff0")) and ":" in host:
        return True
    try:
        ip = ipaddress.ip_address(host.split("%")[0])
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except ValueError:
        return False


def sockets():
    """All TCP/UDP sockets system-wide (netstat -anv shows every process, no sudo needed)."""
    rows = []
    for proto in ("tcp", "udp"):
        _, out, _ = run(["netstat", "-anv", "-p", proto])
        for line in out.splitlines():
            parts = line.split()
            if not parts or not parts[0].startswith(proto):
                continue
            # process:pid column sits right before the 5-hex-digit "state" column
            m = re.search(r"(\S+):(\d+)\s+[0-9a-f]{5}\s", line)
            proc, pid = (m.group(1), int(m.group(2))) if m else (None, None)
            local, remote = parts[3], parts[4]
            state = parts[5] if proto == "tcp" else ("LISTEN" if remote == "*.*" else "UDP")
            lh, lp = split_addr(local)
            rh, rp = split_addr(remote)
            # byte counters follow the (state) column for tcp; udp has no state column
            b = parts[6:8] if proto == "tcp" else parts[5:7]
            rx, tx = (int(b[0]), int(b[1])) if len(b) == 2 and b[0].isdigit() and b[1].isdigit() else (0, 0)
            rows.append(dict(proto=parts[0], lhost=lh, lport=lp, rhost=rh, rport=rp, state=state, proc=proc, pid=pid,
                             rx=rx, tx=tx))
    return rows


def arp_table():
    _, out, _ = run(["arp", "-an"])
    rows = []
    for line in out.splitlines():
        m = re.match(r"\? \((\S+)\) at (\S+) on (\S+)", line)
        if m and m.group(2) not in ("(incomplete)", "ff:ff:ff:ff:ff:ff") and not m.group(2).startswith("1:0:5e"):
            mac = ":".join(x.zfill(2) for x in m.group(2).split(":"))
            rows.append({"ip": m.group(1), "mac": mac, "iface": m.group(3), "permanent": "permanent" in line})
    return rows


def gateway():
    _, out, _ = run(["route", "-n", "get", "default"])
    gw = re.search(r"gateway: (\S+)", out)
    iface = re.search(r"interface: (\S+)", out)
    return (gw.group(1) if gw else None), (iface.group(1) if iface else None)


def dns_servers():
    _, out, _ = run(["scutil", "--dns"])
    return sorted(set(re.findall(r"nameserver\[\d+\] : (\S+)", out)))


def hosts_overrides():
    try:
        lines = read_text("/etc/hosts").splitlines()
    except OSError:
        return []
    default = {"localhost", "broadcasthost", "ip6-localhost", "ip6-loopback"}
    out = []
    for l in lines:
        l = l.split("#")[0].strip()
        if l:
            names = l.split()[1:]
            if not set(names) <= default:
                out.append(l)
    return out


def net_snapshot():
    socks = sockets()
    listeners, conns = [], []
    for s in socks:
        if s["state"] == "LISTEN" and s["proto"].startswith("tcp"):
            listeners.append(s)
        elif s["state"] in ("ESTABLISHED", "SYN_SENT", "SYN_RCVD", "CLOSE_WAIT") and s["rhost"] not in ("*",):
            conns.append(s)
    for s in listeners + conns:
        s["exe"] = exe_path(s["pid"]) if s["pid"] else ""
        if s["exe"]:  # netstat truncates names to 16 chars
            s["proc"] = os.path.basename(s["exe"])
    gw, iface = gateway()
    arp = arp_table()
    return dict(listeners=listeners, conns=conns, arp=arp, gateway=gw, iface=iface,
                gateway_mac=next((a["mac"] for a in arp if a["ip"] == gw), None),
                dns=dns_servers(), hosts=hosts_overrides(), time=time.time())


def analyze_net(snap):
    """Return list of findings: (severity, title, detail). severity: high|medium|low|info."""
    f = []
    listen_ports = set()
    seen = set()
    for s in snap["listeners"]:
        key = (s["proc"], s["lport"], s["lhost"] in ("*", "0.0.0.0", "::"))
        if key in seen:
            continue
        seen.add(key)
        listen_ports.add(s["lport"])
        exposed = not (s["lhost"].startswith("127.") or s["lhost"] in ("::1", "localhost"))
        sig = signature(s["exe"])
        where = f"{s['proc']} (pid {s['pid']}) on {s['lhost']}:{s['lport']}"
        if sig in ("unsigned", "adhoc", "missing") and exposed:
            f.append(("high", "Unsigned program accepting network connections", f"{where} -> {s['exe']} [{sig}]"))
        if s["exe"].startswith(SUSPICIOUS_EXE_DIRS):
            f.append(("high", "Listener running from a temp/download folder", f"{where} -> {s['exe']}"))
        if exposed and s["lport"] in RISKY_LISTEN:
            sev = "high" if s["lport"] in (2375, 6379, 27017, 9200) else "medium"
            f.append((sev, f"{RISKY_LISTEN[s['lport']]} exposed to the network", where))
        elif exposed and s["lport"] and s["lport"] < 49152 and s["proc"] not in ("rapportd", "kdc", "launchd", "sharingd", "identityservice"):
            f.append(("low", "Service listening on all interfaces", where))
    # outbound / inbound connections
    per_remote_inbound = {}
    for c in snap["conns"]:
        sig = signature(c["exe"])
        where = f"{c['proc']} (pid {c['pid']}) -> {c['rhost']}:{c['rport']}"
        if c["rport"] in SUSPICIOUS_PORTS:
            f.append(("high", f"Connection to suspicious port ({SUSPICIOUS_PORTS[c['rport']]})", where))
        if c["exe"].startswith(SUSPICIOUS_EXE_DIRS) and not is_private(c["rhost"]):
            f.append(("high", "Program in temp/download folder talking to the internet", f"{where} [{c['exe']}]"))
        elif sig in ("unsigned",) and not is_private(c["rhost"]):
            f.append(("medium", "Unsigned program talking to the internet", f"{where} [{c['exe']}]"))
        if c["lport"] in listen_ports and not is_private(c["rhost"]):
            per_remote_inbound.setdefault(c["rhost"], []).append(c)
        if c["state"] == "SYN_RCVD":
            per_remote_inbound.setdefault(c["rhost"], []).append(c)
    for rhost, cs in per_remote_inbound.items():
        ports = sorted({c["lport"] for c in cs})
        if len(cs) >= 10 or len(ports) >= 5:
            f.append(("high", "Possible port scan / flood from remote host", f"{rhost}: {len(cs)} connections to ports {ports[:10]}"))
        else:
            f.append(("medium", "Inbound connection from the internet", f"{rhost} -> local ports {ports} ({cs[0]['proc']})"))
    # ARP spoofing: one MAC claiming several IPs (incl. gateway)
    by_mac = {}
    for a in snap["arp"]:
        by_mac.setdefault(a["mac"], []).append(a["ip"])
    for mac, ips in by_mac.items():
        if len(ips) > 1 and snap["gateway"] in ips:
            f.append(("high", "Possible ARP spoofing (gateway MAC shared with another IP)", f"{mac} claims {ips}"))
    if snap["hosts"]:
        f.append(("info", "/etc/hosts has custom entries", "; ".join(snap["hosts"][:5])))
    return f


def print_findings(findings):
    col = {"high": C["r"], "medium": C["y"], "low": C["b"], "info": C["d"], "ok": C["g"]}
    order = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
    if not findings:
        print(f"  {C['g']}No issues found.{C['x']}")
    for sev, title, detail in sorted(findings, key=lambda x: order[x[0]]):
        print(f"  {col[sev]}{sev.upper():<6}{C['x']} {title}\n         {C['d']}{detail}{C['x']}")


def cmd_net(args):
    snap = net_snapshot()
    print(f"{C['B']}Gateway{C['x']} {snap['gateway']} ({snap['gateway_mac']}) via {snap['iface']}   "
          f"{C['B']}DNS{C['x']} {', '.join(snap['dns'])}")
    print(f"\n{C['B']}Listening services{C['x']}")
    seen = set()
    for s in sorted(snap["listeners"], key=lambda s: (s["lport"] or 0)):
        k = (s["proc"], s["lport"])
        if k in seen:
            continue
        seen.add(k)
        exposed = not (s["lhost"].startswith("127.") or s["lhost"] == "::1")
        tag = f"{C['y']}network{C['x']}" if exposed else f"{C['d']}local{C['x']}  "
        print(f"  {s['lport']:>6}  {tag}  {s['proc']:<18} {C['d']}{s['exe']}  [{signature(s['exe'])}]{C['x']}")
    print(f"\n{C['B']}Active connections by process{C['x']}")
    by = {}
    for c in snap["conns"]:
        by.setdefault((c["proc"], c["exe"]), []).append(c)
    for (proc, exe), cs in sorted(by.items(), key=lambda kv: -len(kv[1]))[:20]:
        remotes = sorted({c["rhost"] for c in cs if not is_private(c["rhost"])})
        print(f"  {len(cs):>4}  {proc:<18} {C['d']}{len(remotes)} external hosts  {', '.join(remotes[:3])}{C['x']}")
    print(f"\n{C['B']}Findings{C['x']}")
    print_findings(analyze_net(snap))


# ---------------------------------------------------------------- security posture

def plist_program(path):
    rc, out, _ = run(["plutil", "-convert", "json", "-o", "-", path])
    if rc:
        return None
    try:
        d = json.loads(out)
    except ValueError:
        return None
    return d.get("Program") or (d.get("ProgramArguments") or [None])[0]


def cmd_security(args, quiet=False):
    f = []
    _, out, _ = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if "disabled" in out:
        f.append(("high", "macOS firewall is OFF", "System Settings > Network > Firewall > turn on"))
    else:
        f.append(("ok", "Firewall enabled", ""))
    _, out, _ = run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getstealthmode"])
    if "off" in out.lower():
        f.append(("low", "Firewall stealth mode is off", "Turn on 'Stealth mode' so the Mac ignores probes/pings"))
    _, out, _ = run(["csrutil", "status"])
    f.append(("ok", "System Integrity Protection on", "") if "enabled" in out else ("high", "SIP is disabled", out.strip()))
    _, out, err = run(["spctl", "--status"])
    f.append(("ok", "Gatekeeper on", "") if "enabled" in out + err else ("high", "Gatekeeper is disabled", "sudo spctl --master-enable"))
    _, out, _ = run(["fdesetup", "status"])
    f.append(("ok", "FileVault on", "") if "On" in out else ("high", "FileVault disk encryption is off", ""))
    _, out, _ = run(["launchctl", "print-disabled", "system"])
    if re.search(r'"com\.apple\.screensharing" => enabled', out):
        f.append(("medium", "Screen Sharing is enabled", "System Settings > General > Sharing > Screen Sharing off if unused"))
    if re.search(r'"com\.openssh\.sshd" => enabled', out):
        f.append(("medium", "Remote Login (SSH) is enabled", "System Settings > General > Sharing > Remote Login"))
    _, out, _ = run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticallyInstallMacOSUpdates"])
    if out.strip() == "0":
        f.append(("low", "Automatic macOS updates are off", ""))
    # launch agents / daemons
    for d in (f"{HOME}/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"):
        for p in sorted(glob.glob(d + "/*.plist")):
            prog = plist_program(p)
            name = os.path.basename(p)
            if not prog:
                continue
            sig = signature(prog)
            if sig == "missing":
                f.append(("low", "Orphaned launch item (program no longer exists)", f"{p} -> {prog}"))
            elif sig in ("unsigned", "adhoc") and not prog.startswith("/opt/homebrew/"):
                f.append(("medium", "Unsigned program starts automatically", f"{p} -> {prog}"))
            elif prog.startswith(SUSPICIOUS_EXE_DIRS):
                f.append(("high", "Auto-start program in temp/download folder", f"{p} -> {prog}"))
            if "ccleaner" in name.lower() or "mackeeper" in name.lower():
                f.append(("info", "Third-party 'cleaner' with background daemons", f"{name} - consider uninstalling; macguard replaces it"))
    # secrets left in easily-synced/shared folders
    for d in ("Downloads", "Desktop", "Documents"):
        for p in glob.glob(f"{HOME}/{d}/*") + glob.glob(f"{HOME}/{d}/*/*"):
            name = os.path.basename(p).lower()
            if not os.path.isfile(p) or not (name.endswith((".key", ".pem", ".p12", ".pfx", ".ppk")) or name in ("id_rsa", "id_ed25519", ".env")):
                continue
            try:
                with open(p, "rb") as fh:
                    head = fh.read(4096)
            except OSError:
                continue
            if b"PRIVATE KEY" in head or name.endswith((".p12", ".pfx", ".ppk")) or name == ".env":
                f.append(("medium", f"Private key / secret file in ~/{d}", f"{p.replace(HOME, '~')} - move to ~/.ssh or a password manager"))
    # dedupe
    seen, uniq = set(), []
    for x in f:
        if x[:2] not in seen:
            seen.add(x[:2])
            uniq.append(x)
    if not quiet:
        print(f"{C['B']}Security posture{C['x']}")
        print_findings(uniq)
    return uniq


# ---------------------------------------------------------------- installed applications

# Matched case-insensitively against app name / bundle id. Not "malware": software that
# widens your attack surface or is end-of-life, so you should know it is there.
RISKY_APPS = [
    (("teamviewer", "anydesk", "logmein", "splashtop", "rustdesk", "screenconnect", "connectwise", "gotomypc", "ammyy",
      "chrome remote desktop"), "medium", "Remote-access tool - a common attack vector; remove it if you don't use it"),
    (("mackeeper", "cleanmymac x", "ccleaner", "advanced mac cleaner", "mac auto fixer"), "low",
     "System 'cleaner' with privileged background helpers"),
    (("flash player", "shockwave", "silverlight", "java 6", "quicktime player 7"), "high",
     "End-of-life software - no security updates any more"),
    (("utorrent", "bittorrent", "vuze"), "low", "Torrent client - often bundled with adware; exposes ports"),
]


def read_plist(path):
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:
        return {}


def app_dirs():
    return ["/Applications", "/Applications/Utilities", f"{HOME}/Applications"]


def app_inventory():
    """Third-party and Apple apps in the usual folders (one level of sub-folders too)."""
    seen, apps = set(), []
    for d in app_dirs():
        for path in glob.glob(f"{d}/*.app") + glob.glob(f"{d}/*/*.app"):
            real = os.path.realpath(path)
            if real in seen:
                continue
            seen.add(real)
            info = read_plist(os.path.join(path, "Contents", "Info.plist"))
            exe = os.path.join(path, "Contents", "MacOS", info.get("CFBundleExecutable", ""))
            try:
                mtime = os.stat(os.path.join(path, "Contents", "Info.plist")).st_mtime
            except OSError:
                mtime = 0
            apps.append(dict(name=info.get("CFBundleDisplayName") or info.get("CFBundleName") or os.path.basename(path)[:-4],
                             path=path, bundle_id=info.get("CFBundleIdentifier", ""),
                             version=str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "?"),
                             exe=exe, updated=mtime))
    return sorted(apps, key=lambda a: a["name"].lower())


def app_trust(app):
    """Signature identity + whether the bundle seal still verifies (tampering) + architectures."""
    sig = signature(app["exe"]) if os.path.exists(app["exe"]) else "missing"
    verify = None
    if sig not in ("apple", "missing", "unsigned"):
        rc, _, err = run(["codesign", "--verify", app["path"]], timeout=45)  # --strict also rejects harmless Finder xattrs
        verify = rc == 0 or "timed out" in err
    _, out, _ = run(["lipo", "-archs", app["exe"]], timeout=10)
    return dict(app, sig=sig, seal_ok=verify, archs=out.split())


def brew_outdated():
    if not shutil.which("brew"):
        return [], []
    env = dict(os.environ, HOMEBREW_NO_AUTO_UPDATE="1", HOMEBREW_NO_ANALYTICS="1")
    try:
        p = subprocess.run(["brew", "outdated", "--json=v2"], capture_output=True, text=True, timeout=90, env=env)
        d = json.loads(p.stdout or "{}")
    except (subprocess.TimeoutExpired, ValueError, OSError):
        return [], []
    fmt = lambda x: (x["name"], ", ".join(x.get("installed_versions") or [])[:30], x.get("current_version", "?"))  # noqa: E731
    return [fmt(c) for c in d.get("casks", [])], [fmt(f) for f in d.get("formulae", [])]


def orphan_root_helpers():
    """Root helpers in /Library/PrivilegedHelperTools that no LaunchDaemon references any more."""
    referenced = set()
    for p in glob.glob("/Library/LaunchDaemons/*.plist"):
        d = read_plist(p)
        prog = d.get("Program") or (d.get("ProgramArguments") or [None])[0]
        if prog:
            referenced.add(os.path.basename(prog))
        referenced.add(d.get("Label", ""))
    return [h for h in glob.glob("/Library/PrivilegedHelperTools/*") if os.path.basename(h) not in referenced]


def system_extensions():
    _, out, _ = run(["systemextensionsctl", "list"], timeout=15)
    exts, kind = [], ""
    for line in out.splitlines():
        if line.startswith("---"):
            kind = "network" if "network_extension" in line else ("driver" if "driver" in line else "system")
            continue
        m = re.search(r"\t(\w{10})\t(\S+) \(([^)]*)\)\t(.+?)\t\[(.+)\]", line)
        if m:
            exts.append(dict(kind=kind, team=m.group(1), bundle=m.group(2), version=m.group(3), name=m.group(4), state=m.group(5)))
    return exts


def analyze_apps(apps, casks, formulae, helpers, exts, macos_updates=None, machine=None):
    f = []
    arm = (machine or os.uname().machine) == "arm64"
    stale = time.time() - 3 * 365 * 86400
    for a in apps:
        # Chrome/Edge "install as app" shortcuts are ad-hoc signed stubs generated by the browser
        if "Chrome Apps.localized" in a["path"] or "Edge Apps.localized" in a["path"] or \
                re.match(r"com\.(google\.Chrome|microsoft\.edgemac)\.app\.", a["bundle_id"]):
            continue
        label = f"{a['name']} {a['version']}"
        key = f"{a['name']} {a['bundle_id']}".lower()
        if a.get("seal_ok") is False:
            f.append(("high", "App signature broken (modified after signing)", f"{label} - {a['path']}"))
        if a["sig"] == "unsigned":
            f.append(("medium", "Unsigned app", f"{label} - {a['path']}"))
        elif a["sig"] == "adhoc":
            f.append(("low", "Ad-hoc signed app (no developer identity)", f"{label} - {a['path']}"))
        for words, sev, why in RISKY_APPS:
            if any(w in key for w in words):
                f.append((sev, why, label))
        if arm and a["archs"] and not any(x.startswith("arm64") for x in a["archs"]):
            f.append(("low", "Intel-only app (likely unmaintained; needs Rosetta)", label))
        if a["updated"] and a["updated"] < stale and a["sig"] != "apple":
            f.append(("info", "Not updated in 3+ years", f"{label} (bundle dated {dt.datetime.fromtimestamp(a['updated']):%Y-%m-%d})"))
    for name, have, latest in casks:
        f.append(("medium", "Outdated app (Homebrew cask)", f"{name} {have} -> {latest}  (brew upgrade --cask {name})"))
    if formulae:
        names = ", ".join(n for n, _, _ in formulae[:12]) + (" ..." if len(formulae) > 12 else "")
        f.append(("low", f"{len(formulae)} outdated Homebrew packages", f"{names}  (brew upgrade)"))
    for h in helpers:
        f.append(("medium", "Orphaned root helper (its app is gone, it still runs as root if loaded)", h))
    for e in exts:
        if e["kind"] == "network":
            f.append(("info", "Network extension can see all traffic", f"{e['name']} ({e['team']}) {e['version']}"))
        elif e["kind"] == "driver":
            f.append(("info", "Third-party driver extension", f"{e['name']} ({e['team']}) {e['version']}"))
    if macos_updates:
        for u in macos_updates:
            f.append(("high" if "security" in u.lower() or "macos" in u.lower() else "medium", "macOS update available", u))
    return f


def macos_pending_updates():
    """Asks Apple's update server (network, slow) - only with --online."""
    _, out, err = run(["softwareupdate", "--list"], timeout=120)
    return [l.split("Label:")[1].strip() for l in (out + err).splitlines() if "Label:" in l]


def apps_report(online=False):
    apps = app_inventory()
    with ThreadPoolExecutor(max_workers=8) as ex:
        apps = list(ex.map(app_trust, apps))
    casks, formulae = brew_outdated()
    findings = analyze_apps(apps, casks, formulae, orphan_root_helpers(), system_extensions(),
                            macos_pending_updates() if online else None)
    return apps, findings


def cmd_apps(args):
    print(f"{C['B']}Installed applications{C['x']}  {C['d']}(checking signatures, architectures, updates...){C['x']}")
    apps, findings = apps_report(args.online)
    if args.list:
        for a in apps:
            print(f"  {a['name'][:30]:<30} {a['version'][:14]:<14} {C['d']}{a['sig'][:40]:<40} {'/'.join(a['archs'])}{C['x']}")
        print()
    print(f"  {len(apps)} apps scanned\n")
    print_findings(findings)
    if not args.online:
        print(f"\n{C['d']}Tip: --online also asks Apple for pending macOS security updates.{C['x']}")


# ---------------------------------------------------------------- uninstall / app leftovers

# ~/Library folders where apps keep per-app data, and how entries there are named
LEFTOVER_PLACES = [
    ("Application Support", "{id}"), ("Application Support", "{name}"),
    ("Caches", "{id}"), ("Caches", "{name}"),
    ("Preferences", "{id}.plist"), ("Preferences/ByHost", "{id}.*.plist"),
    ("Containers", "{id}"), ("Application Scripts", "{id}"),
    ("Saved Application State", "{id}.savedState"),
    ("HTTPStorages", "{id}"), ("HTTPStorages", "{id}.binarycookies"), ("Cookies", "{id}.binarycookies"),
    ("WebKit", "{id}"), ("Logs", "{id}"), ("Logs", "{name}"),
    ("LaunchAgents", "{id}*.plist"),
]
LEFTOVER_ROOTS = ["Application Support", "Caches", "Containers", "Preferences", "Saved Application State", "HTTPStorages",
                  "WebKit", "Logs", "Application Scripts", "Cookies"]
GENERIC_NAMES = {"app", "data", "cache", "caches", "logs", "helper", "update", "updater", "google", "microsoft", "adobe",
                 "apple", "mozilla", "chrome", "electron", "node", "python", "java", "default"}


def trash(path):
    """Move to the user's Trash (recoverable). Falls back to Finder, which asks for a password when needed."""
    os.makedirs(os.path.join(HOME, ".Trash"), exist_ok=True)
    dest = os.path.join(HOME, ".Trash", os.path.basename(path.rstrip("/")))
    if os.path.lexists(dest):
        stem, ext = os.path.splitext(dest)
        dest = f"{stem} {dt.datetime.now():%H.%M.%S}{ext}"
    try:
        os.rename(path, dest)
        return True, ""
    except PermissionError as e:  # root-owned (App Store apps, /Library items): Finder asks for a password
        rc, _, err = run(["osascript", "-e", f'tell application "Finder" to delete (POSIX file "{path}" as alias)'], timeout=120)
        return rc == 0, (err.strip() or e.strerror)
    except OSError as e:
        return False, e.strerror


def protected_app(app):
    """Apps macguard refuses to uninstall."""
    bid = app.get("bundle_id", "")
    if not bid or bid.startswith("com.apple.") or app["path"].startswith(("/System/", "/Applications/Utilities/")):
        return "Apple/system app"
    if not app["path"].startswith(("/Applications/", f"{HOME}/Applications/")):
        return "not in an Applications folder"
    return None


def app_running(app):
    rc, out, _ = run(["pgrep", "-f", os.path.join(app["path"], "Contents", "MacOS") + "/"], timeout=10)
    return rc == 0 and bool(out.strip())


def app_leftovers(app):
    """(path, bytes) of this app's data in ~/Library, matched by exact bundle id or exact app name."""
    bid, name = app.get("bundle_id", ""), app.get("name", "")
    use_name = len(name) >= 4 and name.lower() not in GENERIC_NAMES
    lib = os.path.join(HOME, "Library")
    found = {}
    for folder, pat in LEFTOVER_PLACES:
        if "{name}" in pat and not use_name:
            continue
        if "{id}" in pat and not bid:
            continue
        for p in glob.glob(os.path.join(lib, folder, pat.format(id=glob.escape(bid), name=glob.escape(name)))):
            found[p] = du(p)
    if bid:  # system-wide pieces (launch daemons, root helpers): Finder asks for a password to trash these
        for folder in ("/Library/LaunchDaemons", "/Library/LaunchAgents", "/Library/PrivilegedHelperTools"):
            for p in glob.glob(os.path.join(folder, glob.escape(bid) + "*")):
                found[p] = du(p)
        if use_name:
            for p in glob.glob(os.path.join("/Library/Application Support", glob.escape(name))):
                found[p] = du(p)
    if bid:  # group containers are named <TEAMID>.<group id>; match the app's id inside
        for p in glob.glob(os.path.join(lib, "Group Containers", "*")):
            if os.path.basename(p).endswith("." + bid) or os.path.basename(p) == f"group.{bid}":
                found[p] = du(p)
    return sorted(found.items(), key=lambda x: -x[1])


def find_app(query):
    q = query.lower().removesuffix(".app")
    apps = app_inventory()
    exact = [a for a in apps if a["name"].lower() == q or a["bundle_id"].lower() == q or os.path.basename(a["path"]).lower() == q + ".app"]
    return exact or [a for a in apps if q in a["name"].lower()]


def uninstall_plan(app, leftovers_only=False):
    items = ([] if leftovers_only else [(app["path"], du(app["path"]))]) + app_leftovers(app)
    return dict(app=app, items=items, size=sum(n for _, n in items), blocked=protected_app(app),
                running=app_running(app))


def do_uninstall(plan):
    """Move every planned item to the Trash; returns (moved, failed)."""
    if plan["blocked"]:
        raise ValueError(f"refusing: {plan['blocked']}")
    if plan["running"]:
        raise ValueError(f"quit {plan['app']['name']} first")
    moved, failed = [], []
    for path, size in plan["items"]:
        system = path.startswith(("/Library/LaunchDaemons/", "/Library/LaunchAgents/", "/Library/PrivilegedHelperTools/",
                                  "/Library/Application Support/"))
        if not (system or path.startswith(("/Applications/", HOME + "/"))) or path.count("/") < 3:
            failed.append((path, "unsafe path"))
            continue
        ok, err = trash(path)
        (moved if ok else failed).append((path, size) if ok else (path, err))
    log_event("uninstall", f"{plan['app']['name']}: moved {len(moved)} item(s) to Trash, {len(failed)} failed")
    return moved, failed


def cmd_uninstall(args):
    matches = find_app(args.app)
    if not matches:
        sys.exit(f"No installed app matches '{args.app}'.")
    if len(matches) > 1:
        print("Several apps match - be more specific:")
        for a in matches:
            print(f"  {a['name']}  ({a['bundle_id']})  {a['path']}")
        sys.exit(1)
    plan = uninstall_plan(matches[0], args.leftovers_only)
    a = plan["app"]
    print(f"{C['B']}{a['name']} {a['version']}{C['x']}  {C['d']}{a['bundle_id']}{C['x']}")
    for path, size in plan["items"]:
        print(f"  {human(size):>7}  {path.replace(HOME, '~')}")
    print(f"  {C['B']}{human(plan['size']):>7}  total -> Trash{C['x']}")
    if any(p.startswith("/Library/") for p, _ in plan["items"]):
        print(f"  {C['d']}/Library items are system-wide: Finder will ask for your password. Restart afterwards to stop their daemons.{C['x']}")
    if plan["blocked"]:
        sys.exit(f"{C['r']}Refusing: {plan['blocked']}.{C['x']}")
    if plan["running"]:
        sys.exit(f"{C['y']}{a['name']} is running - quit it first.{C['x']}")
    if not args.apply:
        print(f"\n{C['y']}Dry run.{C['x']} Re-run with --apply to move these to the Trash (recoverable until you empty it).")
        return
    if not args.yes and input(f"\nMove {len(plan['items'])} item(s) ({human(plan['size'])}) to the Trash? Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    moved, failed = do_uninstall(plan)
    for path, err in failed:
        print(f"  {C['r']}failed{C['x']} {path.replace(HOME, '~')}: {err}")
    print(f"{C['g']}Moved {len(moved)} item(s), {human(sum(n for _, n in moved))}, to the Trash.{C['x']}")


def running_commands():
    _, out, _ = run(["ps", "-axo", "comm="], timeout=10)
    return out.lower()


def orphan_leftovers(min_bytes=1024 ** 2):
    """Data in ~/Library named after a bundle id that no installed app (or running process / launch item) has."""
    ids = {a["bundle_id"].lower() for a in app_inventory() if a["bundle_id"]}
    for d in ("/System/Applications", "/System/Applications/Utilities", "/System/Library/CoreServices"):
        for p in glob.glob(f"{d}/*.app"):
            bid = read_plist(os.path.join(p, "Contents", "Info.plist")).get("CFBundleIdentifier")
            if bid:
                ids.add(bid.lower())
    running = running_commands()
    for pl in glob.glob(f"{HOME}/Library/LaunchAgents/*.plist") + glob.glob("/Library/Launch*/*.plist"):
        ids.add(os.path.basename(pl)[:-6].lower())

    def owned(bid):
        b = bid.lower()
        # an installed app owns its own id and its helpers' ids (com.vendor.app.helper); vendor-wide prefixes too
        return any(b == i or b.startswith(i + ".") or i.startswith(b + ".") for i in ids) or b in running

    out = []
    lib = os.path.join(HOME, "Library")
    for folder in LEFTOVER_ROOTS:
        for p in glob.glob(os.path.join(lib, folder, "*")):
            base = os.path.basename(p)
            bid = re.sub(r"(\.binarycookies|\.savedState|\.plist)$", "", base)
            if bid.count(".") < 2 or not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9_-]+){2,}", bid):
                continue  # only reverse-DNS names can be attributed to an app
            if bid.lower().startswith(("com.apple.", "group.com.apple.", "systemgroup.")) or owned(bid):
                continue
            n = du(p)
            if n >= min_bytes:
                vendor = ".".join(bid.lower().split(".")[:2])
                hint = " (same vendor still installed - check first)" if any(i.startswith(vendor + ".") for i in ids) else ""
                out.append((p, n, f"{folder} - no installed app '{bid}'{hint}"))
    return sorted(out, key=lambda x: -x[1])


# ---------------------------------------------------------------- traffic

KNOWN_UPLOADERS = ("backupd", "bird", "cloudd", "Dropbox", "Google Drive", "OneDrive", "Backblaze", "bztransmit", "rsync",
                   "ssh", "scp", "git", "git-remote-http", "docker", "com.docker", "photolibraryd", "nsurlsessiond",
                   "Zoom", "zoom.us", "Teams", "Slack", "FaceTime", "avconferenced", "Google Chrome", "Safari", "firefox",
                   "Arc", "Brave", "Microsoft Edge", "Chrome Helper", "WebKit", "OBS", "ffmpeg")
BROWSERS = ("Google Chrome", "Chrome Helper", "Safari", "WebKit", "firefox", "Arc", "Brave", "Microsoft Edge", "com.apple.WebKit")
COMMON_PORTS = {53, 80, 123, 443, 853, 993, 995, 465, 587, 5223, 5228, 3478, 3479, 19302, 8443, 4070, 2197, 22, 9418}
SCAN_PORTS = {21, 22, 23, 25, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 9200, 27017}


def traffic_sample(seconds=6):
    """Two netstat snapshots `seconds` apart -> per-process bytes in/out and destinations."""
    def snap():
        return {(r["proto"], r["lhost"], r["lport"], r["rhost"], r["rport"], r["pid"]): r
                for r in sockets() if r["rhost"] not in ("*",) and r["state"] != "LISTEN"}
    a = snap()
    time.sleep(seconds)
    b = snap()
    procs = {}
    for k, r in b.items():
        old = a.get(k)
        drx = r["rx"] - (old["rx"] if old else 0)
        dtx = r["tx"] - (old["tx"] if old else 0)
        p = procs.setdefault(r["pid"], dict(pid=r["pid"], proc=r["proc"], rx=0, tx=0, hosts=set(), ports=set(), syn=0,
                                             port_hosts={}, new=0))
        p["rx"] += max(drx, 0)
        p["tx"] += max(dtx, 0)
        if not old:
            p["new"] += 1
        if r["state"] == "SYN_SENT":
            p["syn"] += 1
        if not is_private(r["rhost"]):
            p["hosts"].add(r["rhost"])
            if r["rport"]:
                p["ports"].add(r["rport"])
                p["port_hosts"].setdefault(r["rport"], set()).add(r["rhost"])
    for p in procs.values():
        p["exe"] = exe_path(p["pid"]) if p["pid"] else ""
        if p["exe"]:
            p["proc"] = os.path.basename(p["exe"])
        p["rx_rate"], p["tx_rate"] = p["rx"] / seconds, p["tx"] / seconds
    return sorted(procs.values(), key=lambda p: -(p["rx"] + p["tx"]))


def analyze_traffic(procs, seconds):
    f = []
    for p in procs:
        name, exe = p["proc"] or "?", p["exe"]
        who = f"{name} (pid {p['pid']})"
        known = any(k.lower() in (name + exe).lower() for k in KNOWN_UPLOADERS)
        browser = any(k.lower() in (name + exe).lower() for k in BROWSERS)
        sig = signature(exe) if exe else "unknown"
        public = bool(p["hosts"])
        if exe.startswith(SUSPICIOUS_EXE_DIRS) and public:
            f.append(("high", "Program in a temp/download folder is using the internet", f"{who} {exe}"))
        elif sig in ("unsigned", "adhoc") and public and (p["rx"] + p["tx"]) > 0:
            f.append(("medium", f"{'Unsigned' if sig == 'unsigned' else 'Ad-hoc signed'} program is using the internet",
                      f"{who} {exe} - {human(p['tx'])} up / {human(p['rx'])} down"))
        if p["tx_rate"] > 1.5 * 1024 ** 2 and p["tx"] > 3 * p["rx"] and not known:
            f.append(("high" if sig in ("unsigned", "adhoc", "unknown") else "medium", "Heavy upload (possible data exfiltration)",
                      f"{who} sent {human(p['tx'])} in {seconds}s ({human(p['tx_rate'])}/s) to {', '.join(sorted(p['hosts'])[:3])}"))
        for port, hosts in p["port_hosts"].items():
            if port in SCAN_PORTS and len(hosts) >= 10:
                f.append(("high", f"Outbound scanning: port {port} on {len(hosts)} hosts", f"{who}"))
        if len(p["hosts"]) >= 40 and not browser:
            f.append(("medium", "Talking to an unusual number of hosts", f"{who} - {len(p['hosts'])} public hosts in {seconds}s"))
        if p["syn"] >= 10:
            f.append(("medium", "Many connection attempts not answered (scanner or C2 retry)", f"{who} - {p['syn']} pending"))
        odd = sorted(x for x in p["ports"] if x not in COMMON_PORTS and x < 49152)
        if odd and public and not browser:
            bad = [x for x in odd if x in SUSPICIOUS_PORTS]
            if bad:
                f.append(("high", f"Traffic to suspicious port {bad[0]} ({SUSPICIOUS_PORTS[bad[0]]})", who))
            else:
                f.append(("low", "Traffic on uncommon ports", f"{who} -> ports {', '.join(map(str, odd[:6]))}"))
    return f


def traffic_json(procs):
    return [dict(proc=p["proc"], pid=p["pid"], exe=p["exe"], rx_rate=p["rx_rate"], tx_rate=p["tx_rate"],
                 hosts=len(p["hosts"]), ports=sorted(p["ports"])[:8]) for p in procs if p["rx"] + p["tx"] > 0][:12]


def cmd_traffic(args):
    print(f"{C['B']}Sampling network traffic for {args.seconds}s...{C['x']}", flush=True)
    procs = traffic_sample(args.seconds)
    print(f"\n  {'process':<26} {'down/s':>9} {'up/s':>9}  hosts")
    for p in [p for p in procs if p["rx"] + p["tx"] > 0][:15]:
        print(f"  {p['proc'][:26]:<26} {human(p['rx_rate']):>9} {human(p['tx_rate']):>9}  {len(p['hosts'])}")
    print(f"\n{C['B']}Findings{C['x']}")
    print_findings(analyze_traffic(procs, args.seconds))


# ---------------------------------------------------------------- watch mode

def read_text(path):
    with open(path) as fh:
        return fh.read()


def write_json(path, data):
    with open(path, "w") as fh:
        json.dump(data, fh, indent=1)


def log_event(kind, msg):
    ensure_state()
    with open(EVENTS_LOG, "a") as fh:
        fh.write(f"{dt.datetime.now().isoformat(timespec='seconds')} [{kind}] {msg}\n")


def notify(title, msg):
    msg = msg.replace('"', "'")[:200]
    run(["osascript", "-e", f'display notification "{msg}" with title "macguard" subtitle "{title}"'])


def fingerprint(snap):
    return dict(
        # ephemeral ports (rapportd etc. rotate them) are collapsed to "dyn" to avoid noise
        listeners=sorted({f"{s['exe'] or s['proc']}|{'dyn' if (s['lport'] or 0) >= 49152 else s['lport']}|{'net' if not s['lhost'].startswith('127.') and s['lhost'] != '::1' else 'lo'}"
                          for s in snap["listeners"]}),
        talkers=sorted({c["exe"] or c["proc"] for c in snap["conns"] if not is_private(c["rhost"])}),
        gateways={snap["gateway"]: snap["gateway_mac"]} if snap["gateway"] else {},
        dns=snap["dns"], hosts=snap["hosts"])


def cmd_watch(args):
    if args.agent and not load_settings()["background_watcher"]:
        remove_agent()  # stale agent from before the setting was turned off
        return
    ensure_state()
    base = json.loads(read_text(BASELINE)) if os.path.exists(BASELINE) else None
    if base is None or args.reset:
        base = fingerprint(net_snapshot())
        write_json(BASELINE, base)
        print(f"Baseline learned: {len(base['listeners'])} listeners, {len(base['talkers'])} programs using the internet.")
    reported = set()
    print(f"Watching every {args.interval}s. Events -> {EVENTS_LOG}  (Ctrl-C to stop)")
    while True:
        try:
            snap = net_snapshot()
            fp = fingerprint(snap)
            events = []
            for l in set(fp["listeners"]) - set(base["listeners"]):
                exe, port, scope = l.split("|")
                if scope == "net":
                    events.append(("high" if signature(exe) in ("unsigned", "adhoc") else "medium",
                                   "New network listener", f"{exe} on port {port}"))
                base["listeners"].append(l)
            for t in set(fp["talkers"]) - set(base["talkers"]):
                events.append(("low", "New program connecting to internet", t))
                base["talkers"].append(t)
            for gw, mac in fp["gateways"].items():
                old = base["gateways"].get(gw)
                if old and mac and old != mac:
                    events.append(("high", "Gateway MAC changed (ARP spoofing?)", f"{gw}: {old} -> {mac}"))
                if mac:
                    base["gateways"][gw] = mac
            if fp["dns"] != base["dns"]:
                events.append(("medium", "DNS servers changed", f"{base['dns']} -> {fp['dns']}"))
                base["dns"] = fp["dns"]
            if fp["hosts"] != base["hosts"]:
                events.append(("high", "/etc/hosts changed", "; ".join(fp["hosts"][:3])))
                base["hosts"] = fp["hosts"]
            d = disk_health()
            disk_changed = bool(base.get("low_disk")) != d["low"]
            if d["low"] and disk_changed:
                events.append(("high" if d["critical"] else "medium", "Low disk space",
                               f"{human(d['free'])} free of {human(d['total'])} - run macguard scan"))
            base["low_disk"] = d["low"]
            for sev, title, detail in analyze_net(snap):
                if sev == "high" and (title, detail) not in reported:
                    reported.add((title, detail))
                    events.append((sev, title, detail))
            for sev, title, detail in events:
                log_event(sev, f"{title}: {detail}")
                print(f"{dt.datetime.now():%H:%M:%S} {sev.upper():<6} {title}: {detail}", flush=True)
                if sev in ("high", "medium"):
                    notify(title, detail)
            if events or disk_changed:  # also remember recovery, so the alert re-arms
                write_json(BASELINE, base)
            if args.once:
                return
            time.sleep(args.interval)
        except KeyboardInterrupt:
            return


# ---------------------------------------------------------------- settings

DEFAULT_SETTINGS = {"background_watcher": False, "watch_interval": 60}


def load_settings():
    try:
        with open(SETTINGS) as fh:
            return {**DEFAULT_SETTINGS, **json.load(fh)}
    except (OSError, ValueError):
        return dict(DEFAULT_SETTINGS)


def save_settings(s):
    ensure_state()
    with open(SETTINGS, "w") as fh:
        json.dump(s, fh, indent=1)


def install_agent(interval):
    script = os.path.abspath(__file__)
    # KeepAlive only on crash; a clean exit (e.g. setting turned off) stays stopped
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{AGENT_LABEL}</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>-u</string><string>{script}</string><string>watch</string>
    <string>--interval</string><string>{interval}</string><string>--agent</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>StandardOutPath</key><string>{STATE_DIR}/watch.out</string>
  <key>StandardErrorPath</key><string>{STATE_DIR}/watch.err</string>
</dict></plist>
"""
    ensure_state()
    run(["launchctl", "bootout", f"gui/{os.getuid()}", AGENT_PLIST])
    with open(AGENT_PLIST, "w") as fh:
        fh.write(plist)
    rc, _, err = run(["launchctl", "bootstrap", f"gui/{os.getuid()}", AGENT_PLIST])
    return rc == 0, err


def remove_agent():
    run(["launchctl", "bootout", f"gui/{os.getuid()}", AGENT_PLIST])
    if os.path.exists(AGENT_PLIST):
        os.remove(AGENT_PLIST)


def cmd_settings(args):
    s = load_settings()
    if args.key is None:
        running = run(["launchctl", "print", f"gui/{os.getuid()}/{AGENT_LABEL}"])[0] == 0
        for k, v in s.items():
            print(f"  {k:<20} {v}")
        print(f"\n  background watcher is {'RUNNING' if running else 'not running'}")
        print("\n  macguard settings background_watcher on|off\n  macguard settings watch_interval <seconds>")
        return
    if args.key not in DEFAULT_SETTINGS:
        sys.exit(f"Unknown setting '{args.key}'. Known: {', '.join(DEFAULT_SETTINGS)}")
    if args.value is None:
        print(s[args.key])
        return
    if isinstance(DEFAULT_SETTINGS[args.key], bool):
        if args.value.lower() not in ("on", "off", "true", "false", "1", "0"):
            sys.exit("Use on or off.")
        s[args.key] = args.value.lower() in ("on", "true", "1")
    else:
        s[args.key] = int(args.value)
    save_settings(s)
    # apply: the background agent exists only while the setting is on
    if s["background_watcher"]:
        ok, err = install_agent(s["watch_interval"])
        print("Background watcher ON (starts at login, runs every "
              f"{s['watch_interval']}s)." if ok else f"Setting saved, but launchctl failed: {err}")
    else:
        remove_agent()
        print("Background watcher OFF. Run `macguard watch` to monitor on demand.")


# ---------------------------------------------------------------- doctor

def doctor_checks():
    """Prerequisite / environment checks: list of (ok: bool|None, name, detail). None = optional, missing."""
    checks = []
    checks.append((sys.platform == "darwin", "macOS", os.uname().release if sys.platform == "darwin" else sys.platform))
    checks.append((sys.version_info >= (3, 8), "Python >= 3.8", f"{sys.version.split()[0]} at {sys.executable}"))
    sysp = os.path.exists("/usr/bin/python3") and run(["/usr/bin/python3", "-c", "print(1)"])[0] == 0
    checks.append((sysp, "System python (/usr/bin/python3)", "ok" if sysp else "install Xcode Command Line Tools: xcode-select --install"))
    rc, out, _ = run(["netstat", "-anv", "-p", "tcp"])
    visible = sum(1 for l in out.splitlines() if l.startswith("tcp"))
    checks.append((visible > 0, "Socket visibility (netstat)", f"{visible} TCP sockets visible" if visible else
                   "no sockets visible - run with /usr/bin/python3, not Homebrew/pyenv python"))
    for tool in ("du", "df", "codesign", "launchctl", "lsof", "arp", "route", "scutil", "osascript"):
        checks.append((bool(shutil.which(tool)), f"tool: {tool}", shutil.which(tool) or "missing"))
    for tool, why in (("xcrun", "simulator cleanup"), ("docker", "Docker cleanup"), ("brew", "Homebrew cleanup"), ("npm", "npm cache cleanup")):
        checks.append((True if shutil.which(tool) else None, f"optional: {tool}", shutil.which(tool) or f"not installed ({why} skipped)"))
    try:
        ensure_state()
        test = os.path.join(STATE_DIR, ".write-test")
        open(test, "w").close()
        os.remove(test)
        checks.append((True, "State dir writable", STATE_DIR))
    except OSError as e:
        checks.append((False, "State dir writable", f"{STATE_DIR}: {e}"))
    ui = os.path.exists(os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html"))
    checks.append((ui, "UI page (ui.html)", "ok" if ui else "missing next to macguard.py"))
    return checks


def cmd_doctor(args):
    checks = doctor_checks()
    for ok, name, detail in checks:
        mark = f"{C['g']}✔{C['x']}" if ok else (f"{C['d']}–{C['x']}" if ok is None else f"{C['r']}✘{C['x']}")
        print(f"  {mark} {name:<36} {C['d']}{detail}{C['x']}")
    failed = [c for c in checks if c[0] is False]
    print(f"\n{C['g']}All required checks passed.{C['x']}" if not failed else f"\n{C['r']}{len(failed)} required check(s) failed.{C['x']}")
    if args.bundle:
        ensure_state()
        path = os.path.join(STATE_DIR, f"support-{dt.datetime.now():%Y%m%d-%H%M%S}.txt")
        with open(path, "w") as fh:
            fh.write(f"mac-cleanup support bundle {dt.datetime.now().isoformat()}\n\n")
            fh.writelines(f"{'OK  ' if ok else ('--  ' if ok is None else 'FAIL')} {n}: {d}\n" for ok, n, d in checks)
            fh.write(f"\nsettings: {json.dumps(load_settings())}\n\nlast events:\n")
            if os.path.exists(EVENTS_LOG):
                fh.writelines(read_text(EVENTS_LOG).splitlines(True)[-50:])
        print(f"Support bundle (no file contents, no secrets): {path}")
    sys.exit(1 if failed else 0)


# ---------------------------------------------------------------- web UI

def disk_info():
    _, out, _ = run(["df", "-k", "/System/Volumes/Data"])
    f = out.splitlines()[-1].split()
    return {"total": int(f[1]) * 1024, "used": int(f[2]) * 1024, "free": int(f[3]) * 1024}


def junk_json(results):
    return [{"id": r["id"], "name": r["name"], "risk": r["risk"], "note": r.get("note", ""), "size": r["size"],
             "entries": [{"path": p.replace(HOME, "~"), "size": s, "label": l} for p, s, l in sorted(r["entries"], key=lambda e: -e[1])[:12]]}
            for r in sorted(results, key=lambda r: -r["size"]) if r["size"] > 0]


def findings_json(fl):
    order = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
    return [{"sev": s, "title": t, "detail": d} for s, t, d in sorted(fl, key=lambda x: order[x[0]])]


def cmd_ui(args):
    import secrets
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    token = secrets.token_urlsafe(24)
    page_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui.html")
    state = {"scan": None}
    lock = threading.Lock()
    hosts = set()  # filled once the port is bound (port 0 = pick a free one)

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def send(self, code, body, ctype="application/json"):
            data = body if isinstance(body, bytes) else json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def allowed(self):
            # localhost only, and every API call must carry the per-launch token
            # (blocks other websites / DNS rebinding from triggering deletes)
            return self.headers.get("Host") in hosts and \
                self.headers.get("X-Token") == token

        def do_GET(self):
            if self.path == "/":
                if self.headers.get("Host") not in hosts:
                    return self.send(403, {"error": "forbidden"})
                with open(page_path, "rb") as fh:
                    return self.send(200, fh.read().replace(b"__TOKEN__", token.encode()), "text/html; charset=utf-8")
            if not self.allowed():
                return self.send(403, {"error": "forbidden"})
            if self.path == "/api/disk":
                return self.send(200, disk_health())
            if self.path == "/api/scan":
                with lock:
                    rep = space_report(args.stale_days)
                    state["scan"] = rep["results"]
                return self.send(200, {"disk": rep["disk"], "items": junk_json(rep["results"]), "since": rep["since"],
                                       "grew": [{"path": p, "before": b, "now": n} for p, b, n in rep["grew"][:10]],
                                       "managed": rep["managed"]})
            if self.path == "/api/security":
                return self.send(200, findings_json(cmd_security(args, quiet=True)))
            if self.path == "/api/net":
                snap = net_snapshot()
                seen, listeners = set(), []
                for s in sorted(snap["listeners"], key=lambda s: s["lport"] or 0):
                    if (s["proc"], s["lport"]) not in seen:
                        seen.add((s["proc"], s["lport"]))
                        listeners.append({"port": s["lport"], "proc": s["proc"], "exe": s["exe"], "sig": signature(s["exe"]),
                                          "exposed": not (s["lhost"].startswith("127.") or s["lhost"] == "::1")})
                return self.send(200, {"gateway": snap["gateway"], "gateway_mac": snap["gateway_mac"], "dns": snap["dns"],
                                       "listeners": listeners, "findings": findings_json(analyze_net(snap))})
            if self.path == "/api/apps":
                apps, findings = apps_report(online=False)
                return self.send(200, {"count": len(apps), "findings": findings_json(findings)})
            if self.path == "/api/installed":
                return self.send(200, [dict(name=a["name"], version=a["version"], bundle_id=a["bundle_id"], path=a["path"],
                                            protected=protected_app(a)) for a in app_inventory()])
            if self.path == "/api/traffic":
                procs = traffic_sample(6)
                return self.send(200, {"seconds": 6, "top": traffic_json(procs), "findings": findings_json(analyze_traffic(procs, 6))})
            if self.path == "/api/settings":
                s = load_settings()
                s["running"] = run(["launchctl", "print", f"gui/{os.getuid()}/{AGENT_LABEL}"])[0] == 0
                return self.send(200, s)
            self.send(404, {"error": "not found"})

        def do_POST(self):
            # read the body first so a rejected request still gets a clean response, not a reset
            raw = self.rfile.read(min(int(self.headers.get("Content-Length") or 0), 1 << 20))
            if not self.allowed():
                return self.send(403, {"error": "forbidden"})
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return self.send(400, {"error": "bad json"})
            if self.path == "/api/clean":
                ids = set(body.get("ids") or [])
                with lock:
                    if state["scan"] is None:
                        return self.send(409, {"error": "Run a scan first"})
                    plan = [r for r in state["scan"] if r["id"] in ids and r["size"] > 0]
                    freed = sum(clean_item(r) for r in plan)
                    state["scan"] = None
                log_event("clean", f"[ui] freed ~{human(freed)} ({', '.join(r['id'] for r in plan)})")
                return self.send(200, {"freed": freed, "cleaned": [r["id"] for r in plan]})
            if self.path in ("/api/uninstall/plan", "/api/uninstall"):
                # re-plan from the app's path every time: the page never chooses which files go
                app = next((a for a in app_inventory() if a["path"] == body.get("path")), None)
                if not app:
                    return self.send(404, {"error": "app not found"})
                plan = uninstall_plan(app, bool(body.get("leftovers_only")))
                view = dict(name=app["name"], blocked=plan["blocked"], running=plan["running"], size=plan["size"],
                            items=[{"path": p.replace(HOME, "~"), "size": n} for p, n in plan["items"]])
                if self.path == "/api/uninstall/plan":
                    return self.send(200, view)
                try:
                    moved, failed = do_uninstall(plan)
                except ValueError as e:
                    return self.send(409, {"error": str(e)})
                return self.send(200, dict(view, moved=len(moved), freed=sum(n for _, n in moved),
                                           failed=[{"path": p.replace(HOME, "~"), "error": e} for p, e in failed]))
            if self.path == "/api/settings":
                s = load_settings()
                if "background_watcher" in body:
                    s["background_watcher"] = bool(body["background_watcher"])
                save_settings(s)
                if s["background_watcher"]:
                    install_agent(s["watch_interval"])
                else:
                    remove_agent()
                return self.send(200, s)
            self.send(404, {"error": "not found"})

    if args.parent_pid:
        # launched by the app: exit when the app goes away
        def watchdog():
            while True:
                time.sleep(2)
                try:
                    os.kill(args.parent_pid, 0)
                except OSError:
                    os._exit(0)
        threading.Thread(target=watchdog, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    port = srv.server_address[1]
    hosts.update({f"127.0.0.1:{port}", f"localhost:{port}"})
    url = f"http://127.0.0.1:{port}/"
    print(f"macguard UI on {url}  (Ctrl-C to stop)", flush=True)
    if not args.no_open:
        run(["open", url])
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------- HTML report

def cmd_report(args):
    print("Scanning disk...", flush=True)
    junk = scan_junk(args.stale_days)
    _, out, _ = run(["df", "-k", "/System/Volumes/Data"])
    fs = out.splitlines()[-1].split()
    total, used, avail = int(fs[1]) * 1024, int(fs[2]) * 1024, int(fs[3]) * 1024
    big = big_dirs()
    print("Analyzing network...", flush=True)
    snap = net_snapshot()
    netf = analyze_net(snap)
    print("Auditing security...", flush=True)
    secf = cmd_security(args, quiet=True)
    events = read_text(EVENTS_LOG).splitlines()[-30:] if os.path.exists(EVENTS_LOG) else []
    e = html.escape

    def findings_html(fl):
        order = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
        return "".join(f'<div class="f {s}"><span class="sev">{s}</span><div><b>{e(t)}</b><small>{e(d)}</small></div></div>'
                       for s, t, d in sorted(fl, key=lambda x: order[x[0]])) or '<div class="f ok"><span class="sev">ok</span><div><b>No issues</b></div></div>'

    safe = sum(j["size"] for j in junk if j["risk"] == "safe")
    review = sum(j["size"] for j in junk if j["risk"] == "review")
    junk_rows = "".join(
        f'<tr><td class="num">{human(j["size"])}</td><td><span class="tag {j["risk"]}">{j["risk"]}</span></td>'
        f'<td>{e(j["name"])}<small>{"<br>".join(e(p.replace(HOME, "~")) + " · " + human(s) for p, s, _ in sorted(j["entries"], key=lambda x: -x[1])[:5]) if j["risk"] == "review" or j.get("special") else ""}</small></td>'
        f'<td><code>{e(j["id"])}</code></td></tr>'
        for j in sorted(junk, key=lambda j: -j["size"]) if j["size"] > 0)
    seen = set()
    listen_rows = ""
    for s in sorted(snap["listeners"], key=lambda s: s["lport"] or 0):
        if (s["proc"], s["lport"]) in seen:
            continue
        seen.add((s["proc"], s["lport"]))
        exposed = not (s["lhost"].startswith("127.") or s["lhost"] == "::1")
        listen_rows += (f'<tr><td class="num">{s["lport"]}</td><td><span class="tag {"review" if exposed else "safe"}">{"network" if exposed else "local"}</span></td>'
                        f'<td>{e(s["proc"] or "")}<small>{e(s["exe"])}</small></td><td>{e(signature(s["exe"]))}</td></tr>')
    by = {}
    for c in snap["conns"]:
        by.setdefault(c["proc"], set()).add(c["rhost"])
    conn_rows = "".join(f'<tr><td class="num">{len(h)}</td><td>{e(p or "?")}</td><td><small>{e(", ".join(sorted(x for x in h if not is_private(x))[:6]))}</small></td></tr>'
                        for p, h in sorted(by.items(), key=lambda kv: -len(kv[1]))[:20])
    pct = used / total * 100
    high = sum(1 for x in netf + secf if x[0] == "high")
    page = f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>macguard report</title><style>
:root{{--bg:#f6f7f9;--card:#fff;--fg:#1b1f24;--mute:#6b7280;--line:#e5e7eb;--high:#dc2626;--medium:#d97706;--low:#2563eb;--ok:#16a34a;--info:#6b7280}}
@media (prefers-color-scheme:dark){{:root{{--bg:#0f1115;--card:#171a21;--fg:#e6e8eb;--mute:#9aa1ab;--line:#262a33}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}} h1{{margin:0 0 4px}} h2{{font-size:16px;margin:0 0 12px}}
.sub{{color:var(--mute);margin-bottom:20px}} .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:16px}}
.card{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px;overflow-x:auto}}
.kpi b{{font-size:26px;display:block}} .kpi span{{color:var(--mute)}}
.bar{{height:8px;background:var(--line);border-radius:4px;overflow:hidden;margin-top:8px}} .bar i{{display:block;height:100%;background:{"var(--high)" if pct > 85 else "var(--low)"}}}
table{{width:100%;border-collapse:collapse}} td{{padding:7px 8px;border-top:1px solid var(--line);vertical-align:top}} td small,.f small{{display:block;color:var(--mute);word-break:break-all}}
.num{{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;width:70px}}
.tag{{font-size:11px;padding:2px 8px;border-radius:10px;text-transform:uppercase}} .tag.safe{{background:#16a34a22;color:var(--ok)}} .tag.review{{background:#d9770622;color:var(--medium)}}
.f{{display:flex;gap:12px;padding:8px 0;border-top:1px solid var(--line)}} .f:first-child{{border:0}}
.sev{{font-size:11px;text-transform:uppercase;font-weight:600;min-width:60px}} .f.high .sev{{color:var(--high)}} .f.medium .sev{{color:var(--medium)}} .f.low .sev{{color:var(--low)}} .f.ok .sev{{color:var(--ok)}} .f.info .sev{{color:var(--info)}}
code,pre{{font:12px ui-monospace,Menlo,monospace}} pre{{white-space:pre-wrap;color:var(--mute);margin:0}}
</style></head><body><main>
<h1>macguard</h1><div class="sub">{e(os.uname().nodename)} · {dt.datetime.now():%Y-%m-%d %H:%M}</div>
<div class="grid">
<div class="card kpi"><b>{human(avail)}</b><span>free of {human(total)}</span><div class="bar"><i style="width:{pct:.0f}%"></i></div></div>
<div class="card kpi"><b style="color:var(--ok)">{human(safe)}</b><span>safe to clean now</span></div>
<div class="card kpi"><b style="color:var(--medium)">{human(review)}</b><span>more after review</span></div>
<div class="card kpi"><b style="color:{"var(--high)" if high else "var(--ok)"}">{high}</b><span>high-severity issues</span></div>
</div>
<div class="card"><h2>Security posture</h2>{findings_html(secf)}</div>
<div class="card"><h2>Network threats</h2>{findings_html(netf)}
<p class="sub" style="margin:12px 0 0">Gateway {e(str(snap["gateway"]))} ({e(str(snap["gateway_mac"]))}) · DNS {e(", ".join(snap["dns"]))}</p></div>
<div class="card"><h2>Cleanup candidates</h2><table>{junk_rows}</table>
<p class="sub" style="margin:12px 0 0">Run <code>macguard clean --apply</code> for safe items, <code>macguard clean --only &lt;id&gt; --apply</code> for review items.</p></div>
<div class="card"><h2>Largest folders (not auto-cleaned)</h2><table>{"".join(f'<tr><td class="num">{human(s)}</td><td>{e(p)}</td></tr>' for p, s in big)}</table></div>
<div class="card"><h2>Listening services</h2><table>{listen_rows}</table></div>
<div class="card"><h2>Connections by process (unique remote hosts)</h2><table>{conn_rows}</table></div>
<div class="card"><h2>Recent watch events</h2><pre>{e(chr(10).join(events) or "No events yet. Monitor on demand with: macguard watch")}</pre></div>
</main></body></html>"""
    ensure_state()
    path = args.out or os.path.join(STATE_DIR, "report.html")
    with open(path, "w") as fh:
        fh.write(page)
    print(f"Report: {path}")
    if not args.no_open:
        run(["open", path])


def main():
    # macOS hides other processes' sockets from non-Apple interpreters (e.g. Homebrew python),
    # so always run under the system python.
    if "/opt/homebrew/" in sys.executable or "/usr/local/" in sys.executable or "/.pyenv/" in sys.executable:
        if os.path.exists("/usr/bin/python3") and not os.environ.get("MACGUARD_REEXEC"):
            os.environ["MACGUARD_REEXEC"] = "1"
            os.execv("/usr/bin/python3", ["/usr/bin/python3", os.path.abspath(__file__)] + sys.argv[1:])
    ap = argparse.ArgumentParser(prog="macguard", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan"); p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("clean"); p.add_argument("--apply", action="store_true"); p.add_argument("--yes", action="store_true")
    p.add_argument("--only", help="comma-separated category ids (needed for review items)")
    p.add_argument("--builds", action="store_true", help="also remove build output in active projects (target, build, dist...)")
    p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_clean)
    sub.add_parser("net").set_defaults(fn=cmd_net)
    sub.add_parser("security").set_defaults(fn=cmd_security)
    p = sub.add_parser("apps"); p.add_argument("--online", action="store_true", help="also check Apple for macOS updates")
    p.add_argument("--list", action="store_true", help="print every app"); p.set_defaults(fn=cmd_apps)
    p = sub.add_parser("uninstall", help="remove an app and its ~/Library data (to the Trash)")
    p.add_argument("app", help="app name or bundle id"); p.add_argument("--apply", action="store_true")
    p.add_argument("--yes", action="store_true"); p.add_argument("--leftovers-only", action="store_true",
                                                                 help="keep the app, clear its data (reset)")
    p.set_defaults(fn=cmd_uninstall)
    p = sub.add_parser("traffic"); p.add_argument("--seconds", type=int, default=8); p.set_defaults(fn=cmd_traffic)
    p = sub.add_parser("watch"); p.add_argument("--interval", type=int, default=30); p.add_argument("--once", action="store_true")
    p.add_argument("--reset", action="store_true", help="re-learn the baseline")
    p.add_argument("--agent", action="store_true", help=argparse.SUPPRESS); p.set_defaults(fn=cmd_watch)
    p = sub.add_parser("report"); p.add_argument("--out"); p.add_argument("--no-open", action="store_true")
    p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_report)
    p = sub.add_parser("settings"); p.add_argument("key", nargs="?"); p.add_argument("value", nargs="?"); p.set_defaults(fn=cmd_settings)
    p = sub.add_parser("doctor"); p.add_argument("--bundle", action="store_true", help="write a support bundle file")
    p.set_defaults(fn=cmd_doctor)
    p = sub.add_parser("ui"); p.add_argument("--port", type=int, default=8787); p.add_argument("--no-open", action="store_true")
    p.add_argument("--parent-pid", type=int, help=argparse.SUPPRESS)
    p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_ui)
    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
