#!/usr/bin/python3
"""mac-cleanup (macguard) - clean, monitor and secure a macOS development machine.

Commands:
  scan                 Disk junk analysis (read-only)
  clean                Clean junk (dry-run unless --apply)
  net                  Network snapshot: listeners, connections, ARP/DNS, threats
  security             Security posture audit (firewall, SIP, launch agents, ...)
  deepscan             Everything at once: health score, prioritised findings with fixes, new since last time
                       (--clean also cleans the safe items, --traffic adds a live traffic sample)
  apps                 Installed apps: broken/missing signatures, outdated, risky, EOL
  traffic              Sample live traffic: heavy uploads, scanning, odd ports
  netmon               Record every connection (program -> IP:port, bytes) into a day-by-day history
  netlog               Report that history: requests per day, top programs/destinations, risky traffic
  procs                Heavy CPU/memory processes, which are safe to stop; --kill PID
  uninstall APP        Remove an app and all its ~/Library data (to the Trash); --leftovers-only resets it
  kill APP             Quit an app and every process under it (helpers, children, launch agents)
  ready                Ready for shutdown: what cleanup frees, what stops, what is still running, git work
                       only on this Mac (--apply cleans, restores and stops the safe parts)
  devmode [on|off]     Developer mode: stop idle services, pause non-dev apps, turn off animations,
                       keep the Mac awake - one switch, and `off` puts everything back
  perf                 What's hogging CPU, memory and heat: dev daemons, orphans, thermal/swap state
                       (--apply stops the safe ones, --before heavy checks readiness for a big build,
                       --focus pauses apps that aren't dev tools, --resume continues them)
  watch                Continuously monitor network, alert on anomalies
  report               Full HTML report (scan + net + security), opens in browser
  ui                   Small local web UI: scan, pick categories, clean, run checks
  doctor               Check prerequisites; --bundle writes a support file
  mcp                  MCP server on stdio, so AI clients (Claude, ...) can use the tools
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
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

HOME = os.path.expanduser("~")
STATE_DIR = os.path.join(HOME, ".macguard")
BASELINE = os.path.join(STATE_DIR, "baseline.json")
EVENTS_LOG = os.path.join(STATE_DIR, "events.log")
SETTINGS = os.path.join(STATE_DIR, "settings.json")
NETLOG_DB = os.path.join(STATE_DIR, "netlog.db")
AGENT_LABEL = "ai.macguard.watch"
AGENT_PLIST = os.path.join(HOME, "Library/LaunchAgents", AGENT_LABEL + ".plist")

C = {"r": "\033[31m", "g": "\033[32m", "y": "\033[33m", "b": "\033[34m", "d": "\033[2m", "B": "\033[1m", "x": "\033[0m"}
if not sys.stdout.isatty():
    C = {k: "" for k in C}


def run(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=isinstance(cmd, str),
                           stdin=subprocess.DEVNULL)  # never read our stdin (it is the MCP pipe under `macguard mcp`)
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
    # review, not safe: deleting it under a running daemon breaks builds, and every Spring/Android build re-downloads it.
    # ~/.gradle/daemon is never touched (it holds the running daemons' registry).
    dict(id="gradle", name="Gradle caches", risk="review", paths=[f"{H}/.gradle/caches"],
         note="stops idle Gradle/Kotlin daemons first, skipped while a build runs; dependencies re-download on the next build"),
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
        m = re.fullmatch(group_re, os.path.basename(p))  # full match: "IntelliJIdea2026.2-backup" is not a version
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


def overlaps(a, b):
    return a == b or a.startswith(b.rstrip("/") + "/") or b.startswith(a.rstrip("/") + "/")


def scan_junk(stale_days=30, verbose=False):
    results = [{**item, "entries": resolve(item, stale_days)} for item in JUNK]
    # an app leftover that's already a more specific item (e.g. the stuck Docker installer) is listed once
    claimed = [p for r in results if r["id"] != "app-leftovers" for p, _, _ in r["entries"] if p.startswith("/")]
    for r in results:
        if r["id"] == "app-leftovers":
            r["entries"] = [e for e in r["entries"] if not any(overlaps(e[0], c) for c in claimed)]
        r["size"] = sum(e[1] for e in r["entries"])
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


def simulator_runtimes():
    """Installed simulator runtimes as macOS counts them (`simctl runtime list`), not the raw Volumes folder."""
    if not shutil.which("xcrun"):
        return dict(size=0, runtimes=[])
    _, out, _ = run(["xcrun", "simctl", "runtime", "list"], timeout=60)
    runtimes = [dict(name=m.group(1).strip(), id=m.group(2))
                for m in re.finditer(r"^(\S.*?\(\S+\)) - ([0-9A-F-]{36})", out, re.M)]
    m = re.search(r"Total Disk Images: \d+ \(([\d.]+)\s*([KMGT])B?\)", out)
    size = int(float(m.group(1)) * 1024 ** "KMGT".index(m.group(2)) * 1024) if m else 0
    return dict(size=size, runtimes=runtimes)


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
    ]
    out = []
    rt = simulator_runtimes()
    if rt["size"] >= 100 * 1024 ** 2:
        ids = "; ".join(f"{r['name']}: xcrun simctl runtime delete {r['id']}" for r in rt["runtimes"][:4])
        out.append(dict(name=f"Simulator runtimes ({len(rt['runtimes'])})", path="xcrun simctl runtime list", size=rt["size"],
                        how=ids or "xcrun simctl runtime list, then xcrun simctl runtime delete <id>"))
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
        entries = [(p, size) for p, size, _ in r["entries"] if p.startswith(HOME + "/Library/")]
        result = trash_paths([p for p, _ in entries])
        for p, err in result.items():
            if err:
                print(f"   {C['r']}failed{C['x']} {p}: {err}")
        return sum(size for p, size in entries if p in result and not result[p])
    if r["id"] == "gradle":
        ok, why = gradle_quiesce()
        if not ok:
            print(f"   {C['y']}skipped{C['x']}: {why}")
            return 0
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


def gradle_quiesce():
    """Before deleting ~/.gradle/caches: refuse while a Gradle build runs, otherwise stop the idle Gradle and Kotlin
    daemons so none is left holding deleted jars. Returns (ok, reason)."""
    table = perf_table()
    daemons = [p for p in table if "GradleDaemon" in p["args"] or "KotlinCompileDaemon" in p["args"]]
    clients = [p for p in table if "GradleWrapperMain" in p["args"] or "org.gradle.launcher.GradleMain" in p["args"]]
    busy = [p for p in daemons if p["cpu"] >= IDLE_CPU]
    if clients or busy:
        return False, f"a Gradle build is running (pid {(clients or busy)[0]['pid']}) - run the cleanup when it has finished"
    if daemons:
        if shutil.which("gradle"):
            run(["gradle", "--stop"], timeout=120)
        stop_pids([p["pid"] for p in daemons], daemons)
        log_event("clean", f"stopped {len(daemons)} idle Gradle/Kotlin daemon(s) before clearing ~/.gradle/caches")
    return True, ""


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


_local_v6 = None


def local_v6_prefixes():
    """/48 prefixes of this Mac's global IPv6 addresses: peers inside them are on your own network."""
    global _local_v6
    if _local_v6 is None:
        _, out, _ = run(["ifconfig"], timeout=10)
        _local_v6 = {":".join(a.split(":")[:3]).lower() + ":" for a in re.findall(r"inet6 ([0-9a-fA-F:]+)", out)
                     if not a.lower().startswith(("fe80", "fd", "fc", "::1")) and a.count(":") >= 3}
    return _local_v6


def is_private(host):
    if host in ("*", "127.0.0.1", "::1", "localhost"):
        return True
    # netstat truncates long IPv6 addresses, so classify link-local/ULA/multicast by prefix
    if host.lower().startswith(("fe80:", "fc", "fd", "ff0")) and ":" in host:
        return True
    if ":" in host and any(host.lower().startswith(p) for p in local_v6_prefixes()):
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
        _, out, _ = run(["netstat", "-anvW", "-p", proto])  # -W: no truncated IPv6
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
            elif prog.startswith(SUSPICIOUS_EXE_DIRS):  # checked first: unsigned AND in a temp folder is the worst case
                f.append(("high", "Auto-start program in temp/download folder", f"{p} -> {prog}"))
            elif sig in ("unsigned", "adhoc") and not prog.startswith("/opt/homebrew/"):
                if prog.startswith(HOME + "/") and p.startswith(HOME + "/"):  # user's own automation, most likely
                    f.append(("low", "Your own unsigned script starts automatically (confirm it's yours)", f"{p} -> {prog}"))
                else:
                    f.append(("medium", "Unsigned program starts automatically", f"{p} -> {prog}"))
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
    # dedupe exact repeats only - two different keys (or launch items) are two findings
    seen, uniq = set(), []
    for x in f:
        if x not in seen:
            seen.add(x)
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
        p = subprocess.run(["brew", "outdated", "--json=v2"], capture_output=True, text=True, timeout=90, env=env,
                           stdin=subprocess.DEVNULL)
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
    ("Preferences", "{id}.plist"), ("Preferences", "{id}.*.plist"), ("Preferences/ByHost", "{id}.*.plist"),
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


TRASH_BIN = "/usr/bin/trash"  # macOS 15+: FileManager.trashItem, works without Full Disk Access


def finder_trash(paths):
    """Trash root-owned items through Finder in ONE request, so macOS asks for the password once."""
    files = ", ".join(f'(POSIX file "{p}" as alias)' for p in paths)
    run(["osascript", "-e", f'tell application "Finder" to delete {{{files}}}'], timeout=300)


def _rename_to_trash(path):
    os.makedirs(os.path.join(HOME, ".Trash"), exist_ok=True)
    base = os.path.basename(path.rstrip("/"))
    stem, ext = os.path.splitext(base)
    dest, n = os.path.join(HOME, ".Trash", base), 1
    while os.path.lexists(dest):
        n += 1
        dest = os.path.join(HOME, ".Trash", f"{stem} {n}{ext}")
    try:
        os.rename(path, dest)
    except OSError:
        pass  # verified below


def trash_paths(paths):
    """Move paths to the Trash (recoverable). Returns {path: ''} on success or {path: reason}.
    Success is only ever reported for paths that are actually gone afterwards."""
    paths = [p for p in paths if os.path.lexists(p)]
    if not paths:
        return {}
    if TRASH_BIN and os.path.exists(TRASH_BIN):
        run([TRASH_BIN, *paths], timeout=600)
    else:
        for p in paths:
            _rename_to_trash(p)
    left = [p for p in paths if os.path.lexists(p)]
    if left:  # root-owned or protected: one Finder request, one password prompt
        finder_trash(left)
    return {p: ("still there - macOS refused (password cancelled, or this app may not control Finder; "
                "drag it to the Trash in Finder)" if os.path.lexists(p) else "")
            for p in paths}


def trash(path):
    err = trash_paths([path]).get(path, "")
    return not err, err


def unload_launch_items(paths):
    """Stop an app's launch agents before trashing them, so the app can't relaunch mid-uninstall."""
    for p in paths:
        if "/LaunchAgents/" in p and p.endswith(".plist"):
            run(["launchctl", "bootout", f"gui/{os.getuid()}", p], timeout=30)


def protected_app(app):
    """Apps macguard refuses to uninstall."""
    bid = app.get("bundle_id", "")
    if not bid or bid.startswith("com.apple.") or app["path"].startswith(("/System/", "/Applications/Utilities/")):
        return "Apple/system app"
    if not app["path"].startswith(("/Applications/", f"{HOME}/Applications/")):
        return "not in an Applications folder"
    return None


# processes that keep macOS itself working - never killed
PROTECTED_PROCESS_IDS = {"com.apple.finder", "com.apple.dock", "com.apple.loginwindow", "com.apple.WindowServer",
                         "com.apple.systemuiserver", "com.apple.controlcenter", "com.apple.notificationcenterui",
                         "com.apple.Spotlight", "com.apple.coreservices.uiagent"}


def app_process_tree(app, table=None):
    """Every process belonging to an app: anything run from inside its bundle (main app, helpers, XPC services,
    login items), its root helpers in /Library/PrivilegedHelperTools, and all of their descendants."""
    table = table if table is not None else process_table()
    bundle = app["path"].rstrip("/") + "/"
    helpers = f"/Library/PrivilegedHelperTools/{app.get('bundle_id') or '//none//'}"
    roots = {p["pid"] for p in table if p["exe"].startswith(bundle) or (app.get("bundle_id") and p["exe"].startswith(helpers))}
    children = {}
    for p in table:
        children.setdefault(p["ppid"], []).append(p["pid"])
    tree, todo = set(), list(roots)
    while todo:
        pid = todo.pop()
        if pid not in tree:
            tree.add(pid)
            todo += children.get(pid, [])
    me = {os.getpid()}  # never kill ourselves or whatever launched us (e.g. the Mac Cleanup app, a terminal)
    by_pid = {p["pid"]: p for p in table}
    pid = os.getpid()
    while pid in by_pid and pid > 1:
        pid = by_pid[pid]["ppid"]
        me.add(pid)
    return [by_pid[p] for p in sorted(tree - me) if p in by_pid]


def app_running(app):
    return bool(app_process_tree(app))


def app_launch_labels(app):
    """Loaded launch-agent labels in the user's session that belong to the app (they would respawn it)."""
    bid = app.get("bundle_id", "")
    if not bid:
        return []
    _, out, _ = run(["launchctl", "list"], timeout=15)
    labels = []
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3 and (parts[2] == bid or parts[2].startswith(bid + ".")):
            labels.append(parts[2])
    return labels


def kill_protected(app):
    if app.get("bundle_id") in PROTECTED_PROCESS_IDS or app["path"].startswith("/System/Library/CoreServices/"):
        return "macOS needs this to run"
    return None


def kill_app(app, grace=5.0, keep_agents=False):
    """Stop an app and everything under it: unload its launch agents (no respawn), TERM the whole tree,
    wait `grace` seconds, then KILL what's left. Returns dict(stopped, unloaded, needs_admin, survivors)."""
    if kill_protected(app):
        raise ValueError(f"refusing: {kill_protected(app)}")
    unloaded = []
    if not keep_agents:
        for label in app_launch_labels(app):
            if run(["launchctl", "bootout", f"gui/{os.getuid()}/{label}"], timeout=30)[0] == 0:
                unloaded.append(label)
    procs = app_process_tree(app)
    needs_admin = []
    for p in procs:
        try:
            os.kill(p["pid"], 15)
        except ProcessLookupError:
            pass
        except PermissionError:
            needs_admin.append(p)
    deadline = time.time() + grace
    alive = lambda: {q["pid"] for q in app_process_tree(app)} - {q["pid"] for q in needs_admin}  # noqa: E731
    while alive() and time.time() < deadline:
        time.sleep(0.25)
    for pid in alive():
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.3)
    survivors = [q for q in app_process_tree(app) if q["pid"] not in {n["pid"] for n in needs_admin}]
    stopped = [p for p in procs if p not in needs_admin and p["pid"] not in {s["pid"] for s in survivors}]
    log_event("kill", f"{app['name']}: stopped {len(stopped)} process(es), unloaded {len(unloaded)} agent(s), "
                      f"{len(needs_admin)} need admin")
    return dict(stopped=stopped, unloaded=unloaded, needs_admin=needs_admin, survivors=survivors)


def cmd_kill(args):
    matches = find_app(args.app)
    if len(matches) != 1:
        print("No single app matches - be more specific:" if matches else f"No installed app matches '{args.app}'.")
        for a in matches:
            print(f"  {a['name']}  ({a['bundle_id']})")
        sys.exit(1)
    app = matches[0]
    procs, labels = app_process_tree(app), app_launch_labels(app)
    print(f"{C['B']}{app['name']}{C['x']}  {C['d']}{app['bundle_id']}{C['x']}")
    if not procs and not labels:
        print("  not running")
        return
    for p in procs:
        who = "" if p["uid"] == os.getuid() else f"  {C['y']}(root - needs sudo){C['x']}"
        print(f"  {p['pid']:>7}  {p['exe'].replace(app['path'], '<app>')}{who}")
    for label in labels:
        print(f"  {'agent':>7}  {label}  {C['d']}(would relaunch it){C['x']}")
    if kill_protected(app):
        sys.exit(f"{C['r']}Refusing: {kill_protected(app)}.{C['x']}")
    if not args.yes and input(f"\nQuit {app['name']} and {len(procs)} process(es)? Unsaved work is lost. Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    r = kill_app(app, keep_agents=args.keep_agents)
    print(f"{C['g']}Stopped {len(r['stopped'])} process(es){C['x']}" + (f", unloaded {len(r['unloaded'])} agent(s)" if r["unloaded"] else ""))
    if r["needs_admin"]:
        pids = " ".join(str(p["pid"]) for p in r["needs_admin"])
        print(f"{C['y']}{len(r['needs_admin'])} root process(es) left:{C['x']} sudo kill {pids}")
    if r["survivors"]:
        print(f"{C['r']}Still running:{C['x']} " + ", ".join(str(p["pid"]) for p in r["survivors"]))


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
    ok_paths, failed = [], []
    for path, size in plan["items"]:
        system = path.startswith(("/Library/LaunchDaemons/", "/Library/LaunchAgents/", "/Library/PrivilegedHelperTools/",
                                  "/Library/Application Support/"))
        app_bundle = re.fullmatch(r"/Applications/[^/]+\.app", path) is not None
        home_data = path.startswith(HOME + "/") and path.count("/") >= 4
        (ok_paths if system or app_bundle or home_data else failed).append(path if (system or app_bundle or home_data)
                                                                           else (path, "unsafe path"))
    unload_launch_items(ok_paths)
    result = trash_paths(ok_paths)
    sizes = dict(plan["items"])
    moved = [(p, sizes[p]) for p in ok_paths if result.get(p, "") == "" and not os.path.lexists(p)]
    failed += [(p, result[p]) for p in ok_paths if result.get(p)]
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
    if plan["running"] and args.apply and getattr(args, "quit", False):
        r = kill_app(a)
        print(f"  stopped {len(r['stopped'])} process(es) first")
        plan["running"] = app_running(a)
    if plan["running"]:
        sys.exit(f"{C['y']}{a['name']} is running - quit it first (or add --quit).{C['x']}")
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


# ---------------------------------------------------------------- network monitor (history)

# Samples the kernel socket table (no packet capture, no root). Closed TCP connections linger in TIME_WAIT
# for about 30s, so sampling every 10s also catches most short requests; only UDP blips can slip through.
NETLOG_INTERVAL = 10       # seconds between samples while the watcher runs
NETLOG_KEEP_DAYS = 90
LIVE_STATES = ("ESTABLISHED", "SYN_SENT", "SYN_RCVD", "CLOSE_WAIT", "FIN_WAIT_1", "FIN_WAIT_2", "LAST_ACK", "CLOSING",
               "TIME_WAIT", "UDP")
PLAINTEXT_PORTS = {21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3", 143: "IMAP", 389: "LDAP",
                   1883: "MQTT", 5900: "VNC", 8080: "HTTP", 8000: "HTTP"}


def netlog_db(path=None):
    ensure_state()
    db = sqlite3.connect(path or NETLOG_DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE IF NOT EXISTS conns (
            day TEXT, exe TEXT, proc TEXT, rhost TEXT, rport INTEGER, direction TEXT, proto TEXT,
            conns INTEGER DEFAULT 0, samples INTEGER DEFAULT 0, rx INTEGER DEFAULT 0, tx INTEGER DEFAULT 0,
            first_seen REAL, last_seen REAL,
            PRIMARY KEY (day, exe, rhost, rport, direction, proto));
        CREATE INDEX IF NOT EXISTS conns_rhost ON conns (rhost);
        CREATE TABLE IF NOT EXISTS hosts (ip TEXT PRIMARY KEY, name TEXT, resolved_at REAL);
        CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT);
    """)
    return db


def ipv6_full_addrs():
    """(pid, local port) -> full remote IPv6, from lsof. netstat cuts long IPv6 addresses to 16 characters;
    lsof (no sudo) only sees the user's own processes, so others keep the short form."""
    _, out, _ = run(["lsof", "-nP", "-i6", "-a", "-iTCP", "-iUDP"], timeout=20)
    full = {}
    for line in out.splitlines():
        m = re.search(r"\]:(\d+)->\[([0-9a-fA-F:.%a-z0-9]+)\]:\d+", line)
        f = line.split(None, 2)
        if m and len(f) > 1 and f[1].isdigit():
            full[(int(f[1]), int(m.group(1)))] = m.group(2)
    return full


class NetRecorder:
    """Turns repeated socket-table samples into per-day counts: new connections, bytes, first/last seen."""

    def __init__(self, db=None):
        self.db = db or netlog_db()
        # socket key -> (rx, tx) from the last sample, kept in the db so a restart does not count open sockets again
        row = self.db.execute("SELECT v FROM meta WHERE k = 'prev'").fetchone()
        try:
            self.prev = {tuple(k): tuple(v) for k, v in json.loads(row["v"])} if row else {}
        except (ValueError, TypeError):
            self.prev = {}

    def sample(self, now=None):
        now = now or time.time()
        socks = sockets()
        exes = {p["pid"]: p["exe"] for p in process_table()}
        listen = {s["lport"] for s in socks if s["state"] == "LISTEN"}
        if any(":" in s["rhost"] and len(s["rhost"]) >= 16 for s in socks):
            full = ipv6_full_addrs()
            for s in socks:
                f = full.get((s["pid"], s["lport"]))
                if f and ":" in s["rhost"] and f.startswith(s["rhost"].rstrip(":")):
                    s["rhost"] = f
        agg, seen = {}, {}
        for s in socks:
            if s["state"] not in LIVE_STATES or s["rhost"] in ("*", "") or s["rhost"].startswith("127.") or s["rhost"] == "::1":
                continue
            key = (s["proto"], s["lhost"], s["lport"], s["rhost"], s["rport"], s["pid"])
            old = self.prev.get(key)
            seen[key] = (s["rx"], s["tx"])
            rx, tx = (s["rx"], s["tx"]) if old is None else (max(0, s["rx"] - old[0]), max(0, s["tx"] - old[1]))
            exe = exes.get(s["pid"]) or s["proc"] or "?"
            direction = "in" if s["lport"] in listen else "out"
            a = agg.setdefault((exe, s["rhost"], s["rport"] or 0, direction, s["proto"].rstrip("46")),
                               {"proc": os.path.basename(exe), "conns": 0, "rx": 0, "tx": 0})
            a["conns"] += old is None
            a["rx"] += rx
            a["tx"] += tx
        self.prev = seen
        day = dt.datetime.fromtimestamp(now).strftime("%Y-%m-%d")
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO meta (k, v) VALUES ('prev', ?)", (json.dumps([[list(k), list(v)] for k, v in seen.items()]),))
            self.db.executemany("""
                INSERT INTO conns (day, exe, proc, rhost, rport, direction, proto, conns, samples, rx, tx, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT (day, exe, rhost, rport, direction, proto) DO UPDATE SET
                    conns = conns + excluded.conns, samples = samples + 1, rx = rx + excluded.rx, tx = tx + excluded.tx,
                    last_seen = excluded.last_seen""",
                [(day, exe, a["proc"], rhost, rport, d, proto, a["conns"], a["rx"], a["tx"], now, now)
                 for (exe, rhost, rport, d, proto), a in agg.items()])
        return len(agg)

    def prune(self, keep_days=NETLOG_KEEP_DAYS):
        cutoff = (dt.date.today() - dt.timedelta(days=keep_days)).isoformat()
        with self.db:
            self.db.execute("DELETE FROM conns WHERE day < ?", (cutoff,))


def netlog_rows(days=7, proc=None, db=None):
    db = db or netlog_db()
    cutoff = (dt.date.today() - dt.timedelta(days=days - 1)).isoformat()
    q, params = "SELECT * FROM conns WHERE day >= ?", [cutoff]
    if proc:
        q += " AND (proc LIKE ? OR exe LIKE ?)"
        params += [f"%{proc}%", f"%{proc}%"]
    return [dict(r) for r in db.execute(q, params)]


def resolve_names(ips, db=None, budget=4.0):
    """Reverse DNS (PTR) for IPs, cached in the db. Local resolver only; unresolved IPs stay bare."""
    db = db or netlog_db()
    names = {r["ip"]: r["name"] for r in db.execute("SELECT ip, name FROM hosts")}
    todo = [ip for ip in ips if ip not in names and not is_private(ip)][:60]
    if todo:
        def ptr(ip):
            try:
                return ip, socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                return ip, ""
        ex = ThreadPoolExecutor(max_workers=16)
        futs = [ex.submit(ptr, ip) for ip in todo]
        deadline = time.time() + budget
        done = []
        for f in futs:
            try:
                done.append(f.result(timeout=max(0.01, deadline - time.time())))
            except Exception:
                pass
        ex.shutdown(wait=False)
        with db:
            db.executemany("INSERT OR REPLACE INTO hosts (ip, name, resolved_at) VALUES (?, ?, ?)",
                           [(ip, n, time.time()) for ip, n in done])
        names.update(dict(done))
    return names


def netlog_summary(rows, names=None, limit=15):
    names = names or {}
    days, procs, dests = {}, {}, {}
    for r in rows:
        d = days.setdefault(r["day"], {"day": r["day"], "conns": 0, "rx": 0, "tx": 0, "dests": set(), "procs": set()})
        d["conns"] += r["conns"]; d["rx"] += r["rx"]; d["tx"] += r["tx"]
        d["dests"].add(r["rhost"]); d["procs"].add(r["exe"])
        p = procs.setdefault(r["exe"], {"exe": r["exe"], "name": app_bundle(r["exe"]) or r["proc"], "conns": 0, "rx": 0, "tx": 0,
                                        "dests": set(), "days": set(), "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
        h = dests.setdefault(r["rhost"], {"ip": r["rhost"], "name": names.get(r["rhost"], ""), "private": is_private(r["rhost"]),
                                          "conns": 0, "rx": 0, "tx": 0, "ports": set(), "procs": set(), "days": set(),
                                          "inbound": False, "first_seen": r["first_seen"], "last_seen": r["last_seen"]})
        for x in (p, h):
            x["conns"] += r["conns"]; x["rx"] += r["rx"]; x["tx"] += r["tx"]; x["days"].add(r["day"])
            x["first_seen"] = min(x["first_seen"], r["first_seen"]); x["last_seen"] = max(x["last_seen"], r["last_seen"])
        p["dests"].add(r["rhost"])
        h["ports"].add(r["rport"]); h["procs"].add(p["name"]); h["inbound"] |= r["direction"] == "in"

    def ts(t):
        return dt.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")

    def top(d, key):
        return sorted(d.values(), key=lambda x: (-x[key], -(x["rx"] + x["tx"])))[:limit]
    return {
        "period": {"first_day": min(days) if days else None, "last_day": max(days) if days else None, "days_with_data": len(days)},
        "totals": {"connections": sum(d["conns"] for d in days.values()), "destinations": len(dests), "programs": len(procs),
                   "rx": sum(d["rx"] for d in days.values()), "tx": sum(d["tx"] for d in days.values())},
        "per_day": [{**d, "dests": len(d["dests"]), "procs": len(d["procs"])} for _, d in sorted(days.items())],
        "programs": [{**p, "dests": len(p["dests"]), "days": len(p["days"]), "first_seen": ts(p["first_seen"]),
                      "last_seen": ts(p["last_seen"])} for p in top(procs, "conns")],
        "destinations": [{**h, "ports": sorted(h["ports"])[:10], "procs": sorted(h["procs"])[:6], "days": len(h["days"]),
                          "first_seen": ts(h["first_seen"]), "last_seen": ts(h["last_seen"])} for h in top(dests, "conns")],
    }


def analyze_netlog(rows, names=None, now=None):
    """Findings over recorded history: (severity, title, detail), one per program+issue."""
    names, now = names or {}, now or time.time()
    first_day = min((r["day"] for r in rows), default=None)
    first_seen_host = {}
    for r in rows:
        first_seen_host[r["rhost"]] = min(first_seen_host.get(r["rhost"], r["first_seen"]), r["first_seen"])
    found = {}

    def add(sev, title, exe, what):
        found.setdefault((sev, title, exe), set()).add(what)
    for r in rows:
        if is_private(r["rhost"]):
            continue
        exe, port = r["exe"], r["rport"]
        dest = f"{names.get(r['rhost']) or r['rhost']}:{port}"
        browser = any(b.lower() in exe.lower() for b in BROWSERS)
        sig = signature(exe) if exe.startswith("/") else ("missing" if exe != "?" else "unknown")
        if port in SUSPICIOUS_PORTS or (r["direction"] == "in" and r["rport"] in SUSPICIOUS_PORTS):
            add("high", f"Traffic on suspicious port {port} ({SUSPICIOUS_PORTS.get(port, '?')})", exe, dest)
        if exe.startswith(SUSPICIOUS_EXE_DIRS):
            add("high", "Program in a temp/download folder used the internet", exe, dest)
        elif sig == "adhoc" and (exe.startswith(("/opt/homebrew/", "/usr/local/")) or "/.venv/" in exe or "/venv/" in exe):
            add("low", "Ad-hoc signed Homebrew/venv program used the internet", exe, dest)  # normal for local builds
        elif sig in ("unsigned", "adhoc"):
            add("medium", f"{'Unsigned' if sig == 'unsigned' else 'Ad-hoc signed'} program used the internet", exe, dest)
        elif sig == "missing":
            add("medium", "Program that no longer exists on disk used the internet", exe, dest)
        if r["direction"] == "in":
            add("medium", "Inbound connection from the internet", exe, dest)
        if port in PLAINTEXT_PORTS and sig != "apple" and r["direction"] == "out":
            add("low", f"Unencrypted {PLAINTEXT_PORTS[port]} to the internet", exe, dest)
        elif port and port not in COMMON_PORTS and port not in SUSPICIOUS_PORTS and port < 49152 and not browser \
                and r["direction"] == "out":
            add("low", "Traffic on an uncommon port", exe, dest)
        if first_day and r["day"] > first_day and now - first_seen_host[r["rhost"]] < 86400 and sig not in ("apple",):
            add("info", "New destination in the last 24h", exe, dest)
    out = []
    for (sev, title, exe), whats in found.items():
        name = app_bundle(exe) or os.path.basename(exe)
        w = sorted(whats)
        out.append((sev, title, f"{name} -> {', '.join(w[:5])}" + (f" (+{len(w) - 5} more)" if len(w) > 5 else "") + f" [{exe}]"))
    return out


def netlog_status(db=None):
    db = db or netlog_db()
    r = db.execute("SELECT MIN(day) a, MAX(day) b, COUNT(DISTINCT day) n, COUNT(*) rows, MAX(last_seen) t FROM conns").fetchone()
    s = load_settings()
    running = run(["launchctl", "print", f"gui/{os.getuid()}/{AGENT_LABEL}"])[0] == 0
    return {"recording": running, "background_watcher": s["background_watcher"], "sample_every_seconds": NETLOG_INTERVAL,
            "first_day": r["a"], "last_day": r["b"], "days_with_data": r["n"], "rows": r["rows"],
            "last_sample": dt.datetime.fromtimestamp(r["t"]).strftime("%Y-%m-%d %H:%M:%S") if r["t"] else None,
            "keeps_days": NETLOG_KEEP_DAYS, "db": NETLOG_DB}


def cmd_netmon(args):
    rec = NetRecorder()
    rec.prune()
    print(f"Recording connections every {args.interval}s into {NETLOG_DB}" + ("" if args.seconds else "  (Ctrl-C to stop)"), flush=True)
    end = time.time() + args.seconds if args.seconds else None
    try:
        while True:
            n = rec.sample()
            print(f"{dt.datetime.now():%H:%M:%S}  {n} active destinations", flush=True)
            if end and time.time() + args.interval > end:
                return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass


def cmd_netlog(args):
    rows = netlog_rows(args.days, args.proc)
    st = netlog_status()
    if not rows:
        print(f"No network history yet. Record with {C['B']}macguard netmon{C['x']}, or keep it running in the background:\n"
              f"  {C['B']}macguard settings background_watcher on{C['x']}")
        return
    names = resolve_names({r["rhost"] for r in rows})
    sm = netlog_summary(rows, names, args.limit)
    t = sm["totals"]
    print(f"{C['B']}Network history{C['x']}  {sm['period']['first_day']} .. {sm['period']['last_day']} "
          f"({sm['period']['days_with_data']} days with data; recorder {'on' if st['recording'] else 'off'})")
    print(f"  {t['connections']} connections by {t['programs']} programs to {t['destinations']} addresses, "
          f"{human(t['tx'])} up / {human(t['rx'])} down\n")
    print(f"  {'day':<11} {'conns':>7} {'dests':>6} {'up':>8} {'down':>8}")
    for d in sm["per_day"]:
        print(f"  {d['day']:<11} {d['conns']:>7} {d['dests']:>6} {human(d['tx']):>8} {human(d['rx']):>8}")
    print(f"\n{C['B']}Top programs{C['x']}")
    for p in sm["programs"]:
        print(f"  {p['conns']:>6} conns {p['dests']:>4} dests {p['days']:>3}d  {p['name'][:34]:<34} "
              f"{C['d']}{human(p['tx'])} up, last {p['last_seen']}{C['x']}")
    print(f"\n{C['B']}Top destinations{C['x']}")
    for h in sm["destinations"]:
        label = h["name"] or ("(local network)" if h["private"] else "")
        print(f"  {h['conns']:>6} conns {h['days']:>3}d  {h['ip'][:39]:<39} {label[:40]:<40} "
              f"{C['d']}ports {','.join(map(str, h['ports'][:4]))} by {', '.join(h['procs'][:3])}{C['x']}")
    print(f"\n{C['B']}Findings{C['x']}")
    print_findings(analyze_netlog(rows, names))

# ---------------------------------------------------------------- processes

SYSTEM_DIRS = ("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/", "/Library/Developer/CoreSimulator/")
HEAVY_CPU, HEAVY_MEM = 30.0, 1 << 30  # % of one core, bytes resident


def process_table():
    """Every process: pid, ppid, uid, cpu (% of one core), mem (bytes resident), elapsed, exe."""
    _, out, _ = run(["ps", "-axo", "pid=,ppid=,uid=,pcpu=,rss=,etime=,comm="])
    procs = []
    for line in out.splitlines():
        f = line.split(None, 6)
        if len(f) < 7:
            continue
        try:
            procs.append(dict(pid=int(f[0]), ppid=int(f[1]), uid=int(f[2]), cpu=float(f[3]), mem=int(f[4]) * 1024,
                              elapsed=f[5], exe=f[6].strip()))
        except ValueError:
            continue
    return procs


def ancestors(procs, pid=None):
    """This process and everything above it (the shell, terminal, AI client) - never offered for killing."""
    parent = {p["pid"]: p["ppid"] for p in procs}
    chain, pid = set(), pid or os.getpid()
    while pid and pid not in chain:
        chain.add(pid)
        pid = parent.get(pid)
    return chain


def app_bundle(exe):
    """Outermost .app the executable lives in ('Google Chrome' for its helpers), or ''."""
    m = re.search(r"/([^/]+)\.app/Contents/", exe)
    return m.group(1) if m else ""


def classify_process(p, protected_pids=(), me=None):
    """(kind, advice). kind: system (never kill) | app (quit it from the app) | background (safe for macOS to stop)."""
    me = os.getuid() if me is None else me
    exe = p["exe"]
    if p["pid"] <= 1 or p["pid"] in protected_pids:
        return "system", "runs this tool or the session above it"
    if p["uid"] != me:
        return "system", "owned by root or a system account"
    if exe.startswith(SYSTEM_DIRS) or not exe.startswith("/"):
        return "system", "part of macOS"
    app = app_bundle(exe)
    if app:
        return "app", f"part of {app}: quit {app} normally to keep unsaved work"
    return "background", "your own program; stopping it does not affect macOS"


def heavy_processes(cpu=HEAVY_CPU, mem=HEAVY_MEM, include_system=True):
    """Processes over the CPU or memory threshold, heaviest first, each with kind/advice/killable."""
    procs = process_table()
    protected = ancestors(procs)
    out = []
    for p in procs:
        if p["cpu"] < cpu and p["mem"] < mem:
            continue
        kind, advice = classify_process(p, protected)
        if kind == "system" and not include_system:
            continue
        out.append({**p, "name": app_bundle(p["exe"]) or os.path.basename(p["exe"]), "kind": kind,
                    "advice": advice, "killable": kind != "system"})
    return sorted(out, key=lambda p: (-p["cpu"], -p["mem"]))


def kill_process(pid, expected_exe, force=False, wait=3.0):
    """Stop one non-system process. expected_exe guards against the pid being reused since it was listed."""
    procs = process_table()
    p = next((x for x in procs if x["pid"] == pid), None)
    if not p:
        return {"ok": True, "pid": pid, "detail": "already gone"}
    if p["exe"] != expected_exe:
        return {"ok": False, "pid": pid, "detail": f"pid {pid} is now {p['exe']}, not {expected_exe} - list again"}
    kind, advice = classify_process(p, ancestors(procs))
    if kind == "system":
        return {"ok": False, "pid": pid, "detail": f"refused: {advice}"}
    sig = signal.SIGKILL if force else signal.SIGTERM
    try:
        os.kill(pid, sig)
    except ProcessLookupError:
        return {"ok": True, "pid": pid, "detail": "already gone"}
    except PermissionError:
        return {"ok": False, "pid": pid, "detail": "permission denied"}
    deadline = time.time() + wait
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            log_event("kill", f"{sig.name} {pid} {expected_exe}")
            return {"ok": True, "pid": pid, "detail": f"stopped with {sig.name}"}
        time.sleep(0.1)
    log_event("kill", f"{sig.name} {pid} {expected_exe} (still running)")
    return {"ok": False, "pid": pid, "detail": f"sent {sig.name} but it is still running" + ("" if force else "; try force")}


def cmd_procs(args):
    heavy = heavy_processes(args.cpu, args.mem_mb << 20)
    if args.kill:
        p = next((x for x in heavy_processes(0, 0) if x["pid"] == args.kill), None)
        if not p:
            print(f"No process {args.kill}.")
            return
        if not p["killable"]:
            print(f"{C['r']}Refused{C['x']}: {p['name']} (pid {p['pid']}) - {p['advice']}")
            return
        print(f"{p['name']} (pid {p['pid']}) {p['exe']}\n  {p['advice']}")
        if not args.yes and input(f"{'Force-kill' if args.force else 'Stop'} it? Type 'yes': ").strip() != "yes":
            print("Aborted.")
            return
        ensure_state()
        print(kill_process(p["pid"], p["exe"], args.force)["detail"])
        return
    col = {"system": C["d"], "app": C["y"], "background": C["g"]}
    print(f"{C['B']}Heavy processes{C['x']} {C['d']}(>= {args.cpu:g}% CPU or >= {args.mem_mb} MB){C['x']}")
    if not heavy:
        print(f"  {C['g']}Nothing heavy right now.{C['x']}")
    for p in heavy:
        print(f"  {p['pid']:>6} {p['cpu']:>6.1f}% {human(p['mem']):>7}  {col[p['kind']]}{p['kind']:<10}{C['x']} {p['name'][:40]}"
              f"\n         {C['d']}{p['advice']}{C['x']}")
    print(f"\n{C['d']}system = never killed by macguard. Stop one: macguard procs --kill <pid> [--force]{C['x']}")
# ---------------------------------------------------------------- deep scan

SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3, "ok": 4}
SHARING = {22: "Remote Login (SSH)", 3283: "Remote Management (Apple Remote Desktop)", 5900: "Screen Sharing",
           445: "File Sharing", 548: "File Sharing", 5000: "AirPlay Receiver", 7000: "AirPlay Receiver"}


def fix_for(area, title, detail):
    """One concrete next step for a finding: the setting to change or the command to run."""
    t = title.lower()
    if area == "network":
        m = re.search(r":(\d+)$", detail)
        port = int(m.group(1)) if m else 0
        if port in (5000, 7000):
            return "System Settings > General > AirDrop & Handoff > AirPlay Receiver: off (or allow 'Current User' only)"
        if port in SHARING:
            return f"System Settings > General > Sharing > {SHARING[port]}: off if unused; keep the firewall on either way"
        if "scan" in t or "inbound" in t:
            return "Turn on the firewall (System Settings > Network > Firewall); check who owns the remote address"
        if "spoof" in t:
            return "Disconnect from this network; your router may be compromised or someone is intercepting traffic"
        if port:
            return f"Bind the service to 127.0.0.1, stop it, or block port {port} with the firewall"
    if area == "security":
        if "firewall is off" in t:
            return "System Settings > Network > Firewall: on"
        if "stealth" in t:
            return "System Settings > Network > Firewall > Options: Enable stealth mode"
        if "private key" in t:
            f = detail.split(" - ")[0].replace("~/", "$HOME/", 1)
            return f'mkdir -p ~/.ssh && mv "{f}" ~/.ssh/ && chmod 600 ~/.ssh/"{os.path.basename(f)}"'
        if "orphaned launch item" in t:
            return f"sudo rm '{detail.split(' -> ')[0]}'  (its program is already gone)"
        if "unsigned" in t or "temp/download" in t:
            return f"Check what it is; if you don't recognise it: launchctl bootout gui/$(id -u) '{detail.split(' -> ')[0]}'"
        if "cleaner" in t:
            return "macguard uninstall <app> --apply --quit"
        if "update" in t:
            return "System Settings > General > Software Update"
    if area == "apps":
        m = re.search(r"\((brew upgrade[^)]*)\)", detail)
        if m:
            return m.group(1)
        if "signature broken" in t:
            return "Reinstall it from the vendor, or uninstall: macguard uninstall <app> --apply --quit"
        if "remote-access" in t or "end-of-life" in t or "cleaner" in t:
            return "Uninstall it if you don't use it: macguard uninstall <app> --apply --quit"
        if "orphaned root helper" in t:
            return f"sudo rm '{detail}'"
        if "intel-only" in t:
            return "Look for an Apple Silicon version, or replace the app"
    if area == "traffic":
        return "macguard kill <app> to stop it now; macguard uninstall <app> if you don't recognise it"
    if area == "disk":
        return "macguard clean --apply (safe items), then review the rest below"
    return ""


def finding_key(f):
    detail = re.sub(r"pid \d+", "pid", f["detail"])  # pids change between scans
    return f"{f['area']}|{f['title']}|{detail}"


def deepscan_file():
    return os.path.join(STATE_DIR, "deepscan.json")


def merge_findings(findings):
    """One line per issue: same area+title merged (ports, apps), and a sharing service that the network check
    already reports as exposed isn't repeated by the security check."""
    exposed = " ".join(f["detail"] for f in findings if f["area"] == "network")
    same_root = {"Screen Sharing is enabled": ":5900", "Remote Login (SSH) is enabled": ":22"}
    findings = [f for f in findings if not (f["area"] == "security" and same_root.get(f["title"], "\0") in exposed)]
    merged = {}
    for f in findings:
        k = (f["area"], f["title"])
        if k not in merged:
            merged[k] = dict(f)
            continue
        m = merged[k]
        m["detail"] += "; " + f["detail"]
        if f["fix"] and f["fix"] not in m["fix"]:
            if m["fix"].startswith("brew upgrade --cask") and f["fix"].startswith("brew upgrade --cask"):
                m["fix"] += " " + f["fix"].split()[-1]
            else:
                m["fix"] = " · ".join(x for x in (m["fix"], f["fix"]) if x)
        if SEV_ORDER[f["sev"]] < SEV_ORDER[m["sev"]]:
            m["sev"] = f["sev"]
    for m in merged.values():
        n = m["detail"].count("; ") + 1
        if n > 1 and m["title"].startswith("Outdated app"):
            m["title"] = f"{n} outdated apps (Homebrew casks)"
    return list(merged.values())


def health_score(findings, disk):
    """100 = nothing to do. Each severity's penalty is capped, so many small issues can't zero the score."""
    count = lambda sev: sum(1 for f in findings if f["sev"] == sev)  # noqa: E731
    score = 100 - min(36, 12 * count("high")) - min(28, 4 * count("medium")) - min(8, count("low"))
    score -= 20 if disk.get("critical") else (10 if disk.get("low") else 0)
    return max(0, min(100, score))


def deep_scan(traffic=False, stale_days=30):
    """Every check in one pass, normalised into one prioritised list with fixes and 'new since last time'."""
    space = space_report(stale_days)
    findings = []

    def add(area, items):
        for sev, title, detail in items:
            if sev != "ok":
                findings.append(dict(area=area, sev=sev, title=title, detail=detail, fix=fix_for(area, title, detail)))
    add("security", cmd_security(None, quiet=True))
    snap = net_snapshot()
    add("network", analyze_net(snap))
    apps, app_findings = apps_report(online=False)
    add("apps", app_findings)
    if traffic:
        add("traffic", analyze_traffic(traffic_sample(6), 6))
    d = space["disk"]
    if d["low"]:
        findings.append(dict(area="disk", sev="high" if d["critical"] else "medium",
                             title="Disk almost full" if d["critical"] else "Disk space low",
                             detail=f"{human(d['free'])} free of {human(d['total'])}", fix=fix_for("disk", "", "")))
    for p, before, now in space["grew"][:5]:
        findings.append(dict(area="disk", sev="info", title="Folder grew since the last scan",
                             detail=f"{p}: {human(before)} -> {human(now)}", fix="Check what's inside; macguard scan lists cleanable parts"))
    findings = merge_findings(findings)
    try:
        prev = json.loads(read_text(deepscan_file()))
    except (OSError, ValueError):
        prev = None
    known = set(prev["keys"]) if prev else None
    for f in findings:
        f["new"] = known is not None and finding_key(f) not in known
    findings.sort(key=lambda f: (SEV_ORDER[f["sev"]], not f["new"], f["area"]))
    results = space["results"]
    report = dict(time=time.time(), since=prev["time"] if prev else None, disk=d, score=health_score(findings, d),
                  findings=findings, apps=len(apps), listeners=len({(l["proc"], l["lport"]) for l in snap["listeners"]}),
                  space=dict(safe=sum(r["size"] for r in results if r["risk"] == "safe"),
                             review=sum(r["size"] for r in results if r["risk"] == "review"),
                             managed=sum(m["size"] for m in space["managed"]), managed_items=space["managed"],
                             safe_items=[(r["id"], r["name"], r["size"]) for r in results if r["risk"] == "safe" and r["size"]],
                             review_items=[(r["id"], r["name"], r["size"]) for r in results if r["risk"] == "review" and r["size"]]),
                  results=results)
    ensure_state()
    write_json(deepscan_file(), dict(time=report["time"], keys=[finding_key(f) for f in findings], score=report["score"]))
    return report


def cmd_deepscan(args):
    print("Deep scan: disk, security, network, apps" + (", live traffic" if args.traffic else "") + " (about a minute)...",
          flush=True)
    r = deep_scan(traffic=args.traffic, stale_days=args.stale_days)
    d, sp = r["disk"], r["space"]
    col = C["g"] if r["score"] >= 80 else (C["y"] if r["score"] >= 50 else C["r"])
    print(f"\n{C['B']}Health {col}{r['score']}/100{C['x']}   {human(d['free'])} free of {human(d['total'])}   "
          f"{r['apps']} apps   {r['listeners']} listening services")
    if r["since"]:
        new = sum(f["new"] for f in r["findings"])
        print(f"{C['d']}Compared with the deep scan of {dt.datetime.fromtimestamp(r['since']):%b %d %H:%M}: {new} new finding(s){C['x']}")
    groups = [("Act now", ("high",)), ("Recommended", ("medium",)), ("Good to know", ("low", "info"))]
    for label, sevs in groups:
        items = [f for f in r["findings"] if f["sev"] in sevs]
        if not items:
            continue
        print(f"\n{C['B']}{label}{C['x']}")
        for f in items:
            tag = f" {C['b']}NEW{C['x']}" if f["new"] else ""
            print(f"  {C['r'] if f['sev'] == 'high' else (C['y'] if f['sev'] == 'medium' else C['d'])}{f['area']:<8}{C['x']} "
                  f"{f['title']}{tag}\n           {C['d']}{f['detail']}{C['x']}")
            if f["fix"]:
                print(f"           {C['g']}-> {f['fix']}{C['x']}")
    print(f"\n{C['B']}Space{C['x']}  safe to clean {C['g']}{human(sp['safe'])}{C['x']}  ·  needs review "
          f"{C['y']}{human(sp['review'])}{C['x']}  ·  managed by apps {human(sp['managed'])}")
    for m in sp["managed_items"][:4]:
        print(f"  {human(m['size']):>7}  {m['name']}  {C['d']}- {m['how']}{C['x']}")
    if args.clean:
        plan = [x for x in r["results"] if x["risk"] == "safe" and x["size"] > 0]
        if not plan:
            print(f"\n{C['g']}Nothing safe left to clean.{C['x']}")
        elif args.yes or input(f"\nClean the safe items ({human(sp['safe'])})? Type 'yes': ").strip() == "yes":
            freed = sum(clean_item(x) for x in plan)
            log_event("clean", f"deepscan freed ~{human(freed)}")
            print(f"{C['g']}Freed ~{human(freed)}.{C['x']}")
    elif sp["safe"]:
        print(f"\nNext: {C['B']}macguard deepscan --clean{C['x']} to clean the safe items too.")


# ---------------------------------------------------------------- performance (CPU, memory, heat)

# never signalled: macOS itself, and simulator runtimes (those are shut down with simctl instead)
PERF_SYSTEM_DIRS = ("/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/", "/Library/Developer/CoreSimulator/")
IDLE_CPU = 5.0                      # % of one core: below this a daemon counts as idle
HEAVY_FREE_BYTES = 30 * 1024 ** 3   # free space a Unity or Xcode build wants (Library/, DerivedData, simulators)
RENDER_NAMES = ("chrome-headless-shell", "ffmpeg", "ffprobe")
DEV_MARKERS = ("vite", "next dev", "next-server", "webpack", "react-scripts start", "nodemon", "ts-node-dev", "tsx watch",
               "astro dev", "nuxt dev", "npm run dev", "pnpm dev", "yarn dev", "expo start", "metro", "storybook")


def _base(p):
    return os.path.basename(p["exe"])


# (id, name, match). First match wins; children of a matched process join its group.
DEV_RULES = [
    ("docker", "Docker Desktop", lambda p: "/Docker.app/" in p["exe"] or _base(p).startswith("com.docker.")),
    ("ollama", "Ollama", lambda p: _base(p).lower() == "ollama" or "/Ollama.app/" in p["exe"]),
    ("simulators", "iOS simulators",
     lambda p: "/CoreSimulator/" in p["exe"] or "/CoreSimulator.framework/" in p["exe"] or _base(p) in ("launchd_sim", "Simulator")),
    ("gradle", "Gradle daemons", lambda p: "GradleDaemon" in p["args"]),
    ("kotlin", "Kotlin compile daemon", lambda p: "KotlinCompileDaemon" in p["args"]),
    ("unity", "Unity Hub / Unity Editor", lambda p: "/Unity Hub.app/" in p["exe"] or "/Unity.app/" in p["exe"]),
    ("android-emulator", "Android emulator", lambda p: (_base(p).startswith("qemu-system") and "xtensa" not in _base(p))  # xtensa = ESP32, not Android
     or p["exe"].endswith("/emulator/emulator")),
    ("spotlight", "Spotlight indexing", lambda p: _base(p) in ("mds_stores", "mds", "mdworker", "mdworker_shared")),
    ("render", "Video renders (Remotion, headless Chrome, ffmpeg)",
     lambda p: _base(p) in RENDER_NAMES or _base(p) == "remotion" or "Chrome for Testing" in p["exe"]
     or re.search(r"remotion(-cli\.js)?\s+(render|still|benchmark)\b", p["args"]) is not None),
    ("node-dev", "Node dev servers and watchers",
     lambda p: _base(p) in ("node", "bun", "deno") and any(m in p["args"] for m in DEV_MARKERS)),
]


def perf_table():
    """Every process: pid, ppid, uid, cpu (% of one core), mem (resident bytes), exe, args (full command line)."""
    _, out, _ = run(["ps", "-axo", "pid=,ppid=,uid=,pcpu=,rss=,comm="], timeout=15)
    _, argv, _ = run(["ps", "-axww", "-o", "pid=,args="], timeout=15)
    cmdline = {}
    for line in argv.splitlines():
        pid, _, rest = line.strip().partition(" ")
        if pid.isdigit():
            cmdline[int(pid)] = rest.strip()
    rows = []
    for line in out.splitlines():
        f = line.split(None, 5)
        if len(f) < 6:
            continue
        try:
            row = dict(pid=int(f[0]), ppid=int(f[1]), uid=int(f[2]), cpu=float(f[3]), mem=int(f[4]) * 1024, exe=f[5].strip())
        except ValueError:
            continue
        row["args"] = cmdline.get(row["pid"], row["exe"])
        rows.append(row)
    return rows


def session_pids(table):
    """This process and everything above it (shell, terminal, Claude, the Mac Cleanup app): never stopped."""
    parent = {p["pid"]: p["ppid"] for p in table}
    chain, pid = set(), os.getpid()
    while pid and pid not in chain:
        chain.add(pid)
        pid = parent.get(pid)
    return chain


def stoppable(p, protected):
    """Only your own, non-macOS processes outside this session may be signalled. Nothing here ever needs sudo."""
    return p["pid"] > 1 and p["pid"] not in protected and p["uid"] == os.getuid() and not p["exe"].startswith(PERF_SYSTEM_DIRS)


def owner_name(p):
    """The app a process belongs to (outermost .app: 'Docker' for its helpers), else its program name."""
    m = re.search(r"/([^/]+)\.app/", p["exe"])
    return m.group(1) if m else (_base(p) or "?")


def launchd_jobs():
    """pid -> label of the user's running launchd jobs (a job launchd started on purpose is not an orphan)."""
    _, out, _ = run(["launchctl", "list"], timeout=15)
    jobs = {}
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) == 3 and parts[0].isdigit():
            jobs[int(parts[0])] = parts[2]
    return jobs


def docker_containers():
    """Running container count, or None when the docker CLI can't tell."""
    if not shutil.which("docker"):
        return None
    rc, out, _ = run(["docker", "ps", "-q"], timeout=15)
    return None if rc else len(out.split())


def ollama_loaded():
    """Names of models Ollama has in memory, or None when the CLI can't tell."""
    if not shutil.which("ollama"):
        return None
    rc, out, _ = run(["ollama", "ps"], timeout=10)
    return None if rc else [l.split()[0] for l in out.splitlines()[1:] if l.strip()]


def booted_simulators():
    rc, out, _ = run(["xcrun", "simctl", "list", "devices", "booted", "-j"], timeout=30)
    if rc:
        return []
    try:
        return [d["name"] for devs in json.loads(out).get("devices", {}).values() for d in devs if d.get("state") == "Booted"]
    except ValueError:
        return []


def parse_therm(out):
    """`pmset -g therm` -> dict(state=nominal|warning|throttled, speed_limit, detail)."""
    m = re.search(r"CPU_Speed_Limit\s*=\s*(\d+)", out)
    speed = int(m.group(1)) if m else None
    levels = [int(x) for line in out.splitlines() if not line.strip().lower().startswith("note")
              for x in re.findall(r"warning level\D{0,20}(\d+)", line, re.I)]
    if speed is not None and speed < 100:
        return dict(state="throttled", speed_limit=speed, detail=f"CPU speed limited to {speed}%")
    if any(levels):
        return dict(state="warning", speed_limit=speed, detail=f"thermal/performance warning level {max(levels)}")
    return dict(state="nominal", speed_limit=speed, detail="no thermal warning recorded")


def system_load():
    """Load average, memory pressure, swap, heat and power state. All readable without root."""
    s = dict(cores=os.cpu_count() or 1)
    _, out, _ = run(["sysctl", "-n", "vm.loadavg"])
    s["load"] = ([float(x) for x in re.findall(r"\d+\.\d+", out)[:3]] + [0.0] * 3)[:3]
    _, out, _ = run(["sysctl", "-n", "hw.memsize"])
    s["mem_total"] = int(out.strip()) if out.strip().isdigit() else 0
    _, out, _ = run(["sysctl", "-n", "kern.memorystatus_vm_pressure_level"])
    s["pressure"] = {1: "normal", 2: "warning", 4: "critical"}.get(int(out.strip()) if out.strip().isdigit() else 0, "unknown")
    _, out, _ = run(["memory_pressure", "-Q"], timeout=15)
    m = re.search(r"free percentage:\s*(\d+)%", out)
    s["mem_free_pct"] = int(m.group(1)) if m else None
    _, out, _ = run(["sysctl", "-n", "vm.swapusage"])
    sw = dict(re.findall(r"(total|used) = ([\d.]+)M", out))
    s["swap_total"], s["swap_used"] = (int(float(sw.get(k, 0)) * 1024 ** 2) for k in ("total", "used"))
    s["thermal"] = parse_therm(run(["pmset", "-g", "therm"])[1])
    s["low_power"] = bool(re.search(r"lowpowermode\s+1", run(["pmset", "-g"])[1]))
    s["on_battery"] = "Battery Power" in run(["pmset", "-g", "batt"])[1]
    return s


def dev_items(table, jobs=None):
    """Known heavy dev daemons and leftover processes, grouped, each marked safe/review/system with how to stop
    and how to start it again. Only processes that exist right now show up."""
    jobs = launchd_jobs() if jobs is None else jobs
    protected = session_pids(table)
    by_pid = {p["pid"]: p for p in table}
    group = {}
    for p in table:
        for rid, _, match in DEV_RULES:
            if match(p):
                group[p["pid"]] = rid
                break
    # children join their parent's group (Chrome helpers of a render, esbuild under vite, a VM under Docker)
    for p in table:
        chain, q = [], p
        while q and q["pid"] not in group and q["ppid"] > 1 and len(chain) < 50:
            chain.append(q["pid"])
            q = by_pid.get(q["ppid"])
        if q and q["pid"] in group and q["pid"] != p["pid"]:
            for pid in chain:
                if by_pid[pid]["uid"] == p["uid"]:
                    group[pid] = group[q["pid"]]
    if "docker" in group.values():  # Docker Desktop's Linux VM runs as an Apple Virtualization XPC service
        for p in table:
            if p["exe"].endswith("com.apple.Virtualization.VirtualMachine") and p["uid"] == os.getuid():
                group.setdefault(p["pid"], "docker")

    def parent_gone(p):  # re-parented to launchd, and not a job launchd started on purpose
        return p["ppid"] == 1 and p["uid"] == os.getuid() and p["pid"] not in jobs and p["pid"] not in protected

    def orphan_root(p):
        return parent_gone(p) and not p["exe"].startswith(PERF_SYSTEM_DIRS) and ".app/" not in p["exe"] and p["exe"].startswith("/")

    # renders whose parent has exited are leftovers (the render that started them is over)
    for p in [p for p in table if group.get(p["pid"]) == "render"]:
        q = p
        while group.get(q["ppid"]) in ("render", "leftover-renders") and q["ppid"] in by_pid:
            q = by_pid[q["ppid"]]
        if parent_gone(q):
            group[p["pid"]] = "leftover-renders"
    # any other orphan nobody manages: its parent exited and launchd didn't start it
    for p in table:
        if p["pid"] not in group and orphan_root(p):
            group[p["pid"]] = "orphans"
            for c in table:  # and what it started
                if c["ppid"] == p["pid"] and c["pid"] not in group:
                    group[c["pid"]] = "orphans"

    names = dict((rid, name) for rid, name, _ in DEV_RULES)
    names.update({"leftover-renders": "Leftover render helpers (parent gone)", "orphans": "Orphaned processes (parent gone)"})
    items = []
    for rid in [r[0] for r in DEV_RULES] + ["leftover-renders", "orphans"]:
        procs = [p for p in table if group.get(p["pid"]) == rid]
        if not procs:
            continue
        cpu, mem = sum(p["cpu"] for p in procs), sum(p["mem"] for p in procs)
        it = dict(id=rid, name=names[rid], procs=procs, cpu=cpu, mem=mem, count=len(procs),
                  orphan=rid in ("leftover-renders", "orphans") or (rid in ("render", "node-dev") and any(map(orphan_root, procs))))
        killable = [p["pid"] for p in procs if stoppable(p, protected)]
        term = [("term", killable)] if killable else []
        if rid == "docker":
            n = docker_containers()
            it.update(risk="safe" if n == 0 else "review", stop=[("quit", "Docker")], stop_text="quit Docker Desktop",
                      start="open -a Docker",
                      why="idle: no running containers" if n == 0 else
                      (f"{n} container(s) running - they stop with it" if n else "couldn't ask docker whether containers run"))
        elif rid == "ollama":
            models = ollama_loaded()
            label = next((jobs[p["pid"]] for p in procs if p["pid"] in jobs), None)
            if any("/Ollama.app/" in p["exe"] for p in procs):
                stop, stop_text, start = [("quit", "Ollama")], "quit Ollama", "open -a Ollama"
            elif label:
                stop, stop_text = [("cmd", ["launchctl", "bootout", f"gui/{os.getuid()}/{label}"])], f"unload {label} until next login"
                start = "brew services start ollama" if label.startswith("homebrew.") else \
                    f"launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/{label}.plist"
            else:
                stop, stop_text, start = term, "stop ollama serve", "ollama serve"
            it.update(risk="safe" if models == [] else "review", stop=stop, stop_text=stop_text, start=start,
                      why="idle: no model loaded" if models == [] else
                      (f"model loaded: {', '.join(models)}" if models else "couldn't ask ollama whether a model is loaded"))
        elif rid == "simulators":
            booted = booted_simulators()
            it.update(risk="safe", stop=[("cmd", ["xcrun", "simctl", "shutdown", "all"])], stop_text="shut down booted simulators",
                      start="open -a Simulator, or press Run in Xcode",
                      why=f"booted: {', '.join(booted)}" if booted else "simulator services, no device booted")
        elif rid in ("gradle", "kotlin"):
            idle = cpu < IDLE_CPU
            stop = ([("cmd", ["gradle", "--stop"])] if rid == "gradle" and shutil.which("gradle") else []) + term
            it.update(risk="safe" if idle else "review", stop=stop,
                      stop_text="gradle --stop, then end any daemon left" if rid == "gradle" else "end the daemon",
                      start="starts again with the next build",
                      why=f"idle, holding {human(mem)} of memory" if idle else "busy: a build is probably running")
        elif rid == "unity":
            stop = ([("quit", "Unity")] if any("/Unity.app/" in p["exe"] for p in procs) else []) + \
                ([("quit", "Unity Hub")] if any("/Unity Hub.app/" in p["exe"] for p in procs) else [])
            it.update(risk="review", stop=stop, stop_text="quit Unity (it asks to save)", start="open -a 'Unity Hub'",
                      why="your project may have unsaved work")
        elif rid == "android-emulator":
            it.update(risk="review", stop=term, stop_text="end the emulator (it saves a snapshot when it can)",
                      start="emulator -avd <name>, or Android Studio > Device Manager", why="an app may be running in it")
        elif rid == "spotlight":
            if cpu < IDLE_CPU * 2:
                continue  # always running; only worth a mention while it is busy indexing
            it.update(risk="system", stop=[], stop_text="macOS process - never stopped", start="",
                      why="indexing; exclude build folders (DerivedData, Unity Library, node_modules) in "
                          "System Settings > Spotlight > Search Privacy")
        elif rid == "render":
            it.update(risk="review", stop=term, stop_text="end the render", start="run the render again",
                      why="a render is running - stopping it cancels it")
        elif rid == "leftover-renders":
            it.update(risk="safe", stop=term, stop_text="end the leftover helpers", start="nothing to restart: their render has ended",
                      why="headless Chrome / ffmpeg left behind after a render; parent is pid 1")
        elif rid == "node-dev":
            it.update(risk="review", stop=term, stop_text="end the dev server", start="run its dev command again (npm run dev)",
                      why="you may be using it")
        else:  # orphans
            it.update(risk="review", stop=term, stop_text="end them", start="start it again if you ran it on purpose",
                      why=", ".join(sorted({_base(p) for p in procs if p["ppid"] == 1}))[:120])
        items.append(it)
    return items


def top_owners(table, items, n_cpu=10, n_mem=5):
    """Heaviest owners (app or program): the top by CPU plus the top by memory, each with kind system/app/background."""
    item_of = {p["pid"]: it["name"] for it in items for p in it["procs"]}
    protected = session_pids(table)
    owners = {}
    for p in table:
        name = item_of.get(p["pid"]) or owner_name(p)
        o = owners.setdefault(name, dict(name=name, cpu=0.0, mem=0, count=0, system=True, app=False, session=False))
        o["session"] |= p["pid"] in protected  # runs this tool (terminal, Claude, ...)
        o["cpu"] += p["cpu"]
        o["mem"] += p["mem"]
        o["count"] += 1
        o["system"] &= p["uid"] != os.getuid() or p["exe"].startswith(PERF_SYSTEM_DIRS)
        o["app"] |= ".app/" in p["exe"]
    for o in owners.values():
        o["kind"] = "system" if o.pop("system") else ("app" if o.pop("app") else "background")
        o.pop("app", None)
    by_cpu = sorted(owners.values(), key=lambda o: -o["cpu"])[:n_cpu]
    by_mem = [o for o in sorted(owners.values(), key=lambda o: -o["mem"]) if o not in by_cpu][:n_mem]
    return sorted(by_cpu + by_mem, key=lambda o: (-o["cpu"], -o["mem"]))


def perf_findings(state, items, disk, before=None):
    f = []
    t = state["thermal"]
    if t["state"] == "throttled":
        f.append(("high", "The Mac is hot and throttling the CPU", f"{t['detail']} - close heavy jobs, check vents, use a stand"))
    elif t["state"] == "warning":
        f.append(("medium", "Thermal warning recorded", t["detail"]))
    if state["pressure"] == "critical":
        f.append(("high", "Memory pressure is critical", "macOS is compressing and swapping hard; quit something big"))
    elif state["pressure"] == "warning":
        f.append(("medium", "Memory pressure is high", f"{state['mem_free_pct']}% memory free"))
    if state["swap_used"] > 2 * 1024 ** 3 and state["swap_used"] > state["swap_total"] / 2:
        f.append(("medium", "Heavy swap use", f"{human(state['swap_used'])} of {human(state['swap_total'])} swap used - "
                                               "memory has been short; restarting the heaviest apps gives it back"))
    if state["load"][0] > state["cores"]:
        f.append(("medium", "CPU is saturated", f"load {state['load'][0]:.1f} on {state['cores']} cores"))
    for it in items:
        if it["id"] == "leftover-renders":
            f.append(("medium", "Leftover render helpers still running", f"{it['count']} process(es), {it['cpu']:.0f}% CPU, {human(it['mem'])}"))
        elif it["id"] == "orphans":
            f.append(("low", "Orphaned processes (their parent has exited)", it["why"]))
        elif it["id"] == "spotlight":
            f.append(("info", "Spotlight is indexing", f"{it['cpu']:.0f}% CPU - {it['why']}"))
        elif it["risk"] == "safe" and it["mem"] >= 1024 ** 3:
            f.append(("low", f"Stopping {it['name']} frees {human(it['mem'])}", f"{it['why']} - safe to stop while you don't need it"))
    if state["low_power"]:
        f.append(("medium" if before else "low", "Low Power Mode is on", "slower CPU; turn it off for builds (System Settings > Battery)"))
    if before:
        if disk["free"] < HEAVY_FREE_BYTES:
            f.append(("high" if disk["free"] < HEAVY_FREE_BYTES / 2 else "medium", "Not much free space for a big build",
                      f"{human(disk['free'])} free; Unity imports and Xcode builds want ~{human(HEAVY_FREE_BYTES)}. Run: macguard clean --apply"))
        if state["on_battery"]:
            f.append(("low", "Running on battery", "plug in: macOS slows the CPU on battery during long builds"))
    return f


def heavy_suggestions(items, owners):
    """What to close before a Unity / Xcode / Android build or a video render (beyond the safe items)."""
    out = [f"Stop {it['name']} ({it['why']}): macguard perf --apply" for it in items if it["risk"] == "safe"]
    out += [f"Close {it['name']} if you don't need it now ({it['why']})" for it in items
            if it["risk"] == "review" and it["id"] not in ("unity",)]
    named = {it["name"] for it in items}
    for o in owners:
        if o["kind"] == "app" and not o["session"] and o["name"] not in named and o["mem"] >= 1.5 * 1024 ** 3:
            out.append(f"Quit {o['name']} if you don't need it now ({human(o['mem'])} memory, {o['cpu']:.0f}% CPU)")
    if any(it["id"] == "spotlight" for it in items):
        out.append("Keep Spotlight out of build output: System Settings > Spotlight > Search Privacy")
    return out


def perf_report(before=None):
    table = perf_table()
    state = system_load()
    items = dev_items(table)
    owners = top_owners(table, items)
    disk = disk_health()
    return dict(state=state, items=items, owners=owners, disk=disk, before=before,
                findings=perf_findings(state, items, disk, before),
                suggestions=heavy_suggestions(items, owners) if before else [])


def perf_plan(items, only=None):
    """Safe items by default; review items only when named. System items (Spotlight) are never stopped."""
    return [it for it in items if it["stop"] and it["risk"] != "system" and (it["id"] in only if only else it["risk"] == "safe")]


def stop_pids(pids, before, grace=4.0):
    """TERM then (after `grace`) KILL - but only pids that still run the same program and still pass `stoppable`."""
    exe_then = {p["pid"]: p["exe"] for p in before}
    now = {p["pid"]: p for p in perf_table()}
    protected = session_pids(list(now.values()))
    targets = [pid for pid in pids if pid in now and now[pid]["exe"] == exe_then.get(pid) and stoppable(now[pid], protected)]
    sent = []
    for pid in targets:
        try:
            os.kill(pid, 15)
            sent.append(pid)
        except (ProcessLookupError, PermissionError):
            pass

    def alive():
        left = []
        for pid in sent:
            try:
                os.kill(pid, 0)
                left.append(pid)
            except (ProcessLookupError, PermissionError):
                pass
        return left
    deadline = time.time() + grace
    while alive() and time.time() < deadline:
        time.sleep(0.2)
    for pid in alive():
        try:
            os.kill(pid, 9)
        except (ProcessLookupError, PermissionError):
            pass
    return len(sent)


def apply_perf(plan):
    """Run each item's stop steps. Returns [dict(id, name, ok, detail, start)]. No sudo anywhere."""
    results = []
    for it in plan:
        notes, ok = [], True
        for kind, what in it["stop"]:
            if kind == "quit":
                rc, _, err = run(["osascript", "-e", f'quit app "{what}"'], timeout=60)
                ok &= rc == 0
                notes.append(f"asked {what} to quit" if rc == 0 else f"{what} didn't quit: {err.strip()[:80]}")
            elif kind == "cmd":
                rc, _, err = run(what, timeout=120)
                ok &= rc == 0 or what[:2] == ["gradle", "--stop"]  # the TERM step after it covers other Gradle versions
                notes.append(" ".join(what) + ("" if rc == 0 else f" failed: {err.strip()[:80]}"))
            elif kind == "term":
                n = stop_pids(what, it["procs"])
                notes.append(f"ended {n} process(es)")
        log_event("perf", f"stopped {it['id']}: {'; '.join(notes)}")
        results.append(dict(id=it["id"], name=it["name"], ok=ok, detail="; ".join(notes), start=it["start"]))
    return results


def perf_json(r):
    item = lambda it: {k: it[k] for k in ("id", "name", "risk", "why", "cpu", "mem", "count", "orphan", "stop_text", "start")}  # noqa: E731
    return dict(state=r["state"], disk=r["disk"], before=r["before"], items=[item(it) for it in r["items"]],
                owners=r["owners"], findings=findings_json(r["findings"]), suggestions=r["suggestions"])


def cmd_perf(args):
    if args.focus or args.resume:
        return cmd_focus(args)
    r = perf_report(args.before)
    s, t = r["state"], r["state"]["thermal"]
    tcol = C["r"] if t["state"] == "throttled" else (C["y"] if t["state"] == "warning" else C["g"])
    pcol = C["r"] if s["pressure"] == "critical" else (C["y"] if s["pressure"] == "warning" else C["g"])
    print(f"{C['B']}Performance{C['x']}  load {s['load'][0]:.1f} / {s['cores']} cores  ·  memory {pcol}{s['pressure']}{C['x']}"
          + (f" ({s['mem_free_pct']}% free)" if s["mem_free_pct"] is not None else "")
          + f"  ·  swap {human(s['swap_used'])} of {human(s['swap_total'])}  ·  thermal {tcol}{t['state']}{C['x']}"
          + (f"  ·  {C['y']}Low Power Mode{C['x']}" if s["low_power"] else ""))
    ds = devmode_status()
    if ds["active"]:
        print(f"{C['y']}Developer mode on{C['x']} until {dt.datetime.fromtimestamp(ds['until']):%H:%M}.  Turn off: macguard devmode off")
    fs = focus_status()
    if fs["active"]:
        print(f"{C['y']}Dev focus on:{C['x']} {fs['count']} process(es) paused ({', '.join(fs['names'])}) until "
              f"{dt.datetime.fromtimestamp(fs['until']):%H:%M}.  Resume: macguard perf --resume")
    print(f"\n{C['B']}Findings{C['x']}")
    print_findings(r["findings"])
    col = {"safe": C["g"], "review": C["y"], "system": C["d"]}
    print(f"\n{C['B']}Dev daemons and background jobs{C['x']}")
    if not r["items"]:
        print(f"  {C['g']}None running.{C['x']}")
    for it in r["items"]:
        print(f"  {it['cpu']:>6.1f}% {human(it['mem']):>7}  {col[it['risk']]}{it['risk']:<6}{C['x']} {it['id']:<17} {it['name']}"
              f"  {C['d']}({it['count']} process{'es' if it['count'] != 1 else ''}){C['x']}\n"
              f"{'':>26}{C['d']}{it['why']}{C['x']}")
    print(f"\n{C['B']}Heaviest by app{C['x']}  {C['d']}(CPU % of one core; system = never touched){C['x']}")
    kcol = {"system": C["d"], "app": C["y"], "background": C["g"]}
    for o in r["owners"]:
        print(f"  {o['cpu']:>6.1f}% {human(o['mem']):>7}  {kcol[o['kind']]}{o['kind']:<10}{C['x']} {o['name'][:44]}"
              f"  {C['d']}{o['count']}{C['x']}")
    if r["before"]:
        print(f"\n{C['B']}Before a heavy build{C['x']}  {C['d']}(free {human(r['disk']['free'])}){C['x']}")
        for x in r["suggestions"] or ["Nothing to close - good to go."]:
            print(f"  - {x}")
    wanted = set(args.only.split(",")) if args.only else None
    plan = perf_plan(r["items"], wanted)
    if not args.apply:
        review = [it["id"] for it in r["items"] if it["risk"] == "review"]
        if plan:
            print(f"\nNext: {C['B']}macguard perf --apply{C['x']} stops: {', '.join(it['id'] for it in plan)}"
                  + (f"  ·  review items need --only ({', '.join(review)})" if review else ""))
        return
    if not plan:
        print("\nNothing to stop." + ("" if wanted else " (review items need --only <id>)"))
        return
    print(f"\n{C['B']}Will stop{C['x']}")
    for it in plan:
        print(f"  {it['name']}: {it['stop_text']}  {C['d']}(start again: {it['start']}){C['x']}")
    if not args.yes and input("\nStop the above? Unsaved work in them is lost. Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    for res in apply_perf(plan):
        mark = f"{C['g']}stopped{C['x']}" if res["ok"] else f"{C['y']}partly{C['x']}"
        print(f"  {mark} {res['name']}: {res['detail']}\n          {C['d']}start again: {res['start']}{C['x']}")


# ---------------------------------------------------------------- dev focus (pause apps that aren't dev tools)

FOCUS_MIN_CPU, FOCUS_MIN_MEM = 0.5, 256 << 20  # an app below both isn't worth pausing
# matched (lowercase) against the owning app's name: development tools are never paused
DEV_APPS = ("unity", "xcode", "simulator", "android studio", "visual studio", "code", "cursor", "zed", "intellij", "pycharm",
            "webstorm", "goland", "clion", "rider", "rubymine", "phpstorm", "datagrip", "fleet", "jetbrains", "terminal",
            "iterm", "warp", "ghostty", "alacritty", "kitty", "wezterm", "hyper", "claude", "docker", "postman", "insomnia",
            "github desktop", "sourcetree", "fork", "instruments", "blender", "mac cleanup")
# programs that are development work wherever they run from (and keep whatever started them running too)
DEV_BINS = {"zsh", "bash", "fish", "sh", "tmux", "ssh", "node", "npm", "npx", "bun", "deno", "python", "python3", "java", "dotnet",
            "git", "ffmpeg", "esbuild", "gradle", "make", "cargo", "rustc", "go", "ruby", "postgres", "redis-server", "mongod",
            "mysqld", "claude", "chrome-headless-shell"}
DEV_PATHS = ("/Workspace/", "/node_modules/", "/.gradle/", "/Android/sdk/", "CoreSimulator", "/.dotnet/", "creator-studio", "cbse")
# pausing these breaks input, security, networking or a call - never paused even though they aren't dev tools
NEVER_PAUSE = ("1password", "bitwarden", "lastpass", "dashlane", "keepass", "tailscale", "wireguard", "vpn", "globalprotect",
               "anyconnect", "zscaler", "lulu", "little snitch", "karabiner", "rectangle", "magnet", "raycast", "alfred",
               "bettertouchtool", "bartender", "logi", "steelseries", "razer", "displaylink", "elgato", "stream deck",
               "loopback", "soundsource", "zoom", "webex", "facetime", "macguard")


def focus_file():
    return os.path.join(STATE_DIR, "focus.json")


def load_focus():
    try:
        return json.loads(read_text(focus_file()))
    except (OSError, ValueError):
        return None


def frontmost_pid():
    """The app in front right now (it is never paused). lsappinfo needs no permissions."""
    _, asn, _ = run(["lsappinfo", "front"], timeout=10)
    if not asn.strip():
        return None
    m = re.search(r"pid\s*=\s*(\d+)", run(["lsappinfo", "info", "-only", "pid", asn.strip()], timeout=10)[1])
    return int(m.group(1)) if m else None


def dev_process(p, allow=()):
    low = p["exe"].lower()
    return (os.path.basename(low) in DEV_BINS or any(w in p["exe"] for w in DEV_PATHS)
            or any(w in owner_name(p).lower() for w in DEV_APPS) or any(w in low for w in allow))


def focus_plan(table, front=None, allow=(), ollama_idle=False):
    """Apps (whole bundles: main process and helpers) that may be paused, and why the others stay running.
    Only your own processes inside an .app bundle are candidates; macOS, root, this session, the frontmost app,
    dev tools, anything that starts a dev process and the NEVER_PAUSE list always keep running."""
    allow = tuple(a.lower() for a in allow if a)
    protected = session_pids(table)
    by_pid = {p["pid"]: p for p in table}
    already = {e["pid"] for e in (load_focus() or {}).get("paused", [])}
    keep = {}
    for p in table:
        if dev_process(p, allow):  # the dev process's own app, and every app above it (Terminal -> zsh -> node)
            q, hops = by_pid.get(p["ppid"]), 0
            keep.setdefault(owner_name(p), "in your focus_allow setting" if dev_process(p, allow) and not dev_process(p)
                            else "development tool")
            while q and q["pid"] > 1 and hops < 50:
                keep.setdefault(owner_name(q), f"runs {owner_name(p)}")
                q, hops = by_pid.get(q["ppid"]), hops + 1
        if p["pid"] in protected:
            keep.setdefault(owner_name(p), "runs this tool")
    if front in by_pid:
        keep[owner_name(by_pid[front])] = "the app in front"
    groups = {}
    for p in table:
        if ".app/" in p["exe"] and stoppable(p, protected) and p["pid"] not in already:
            groups.setdefault(owner_name(p), []).append(p)
    pause, kept = [], []
    for name, procs in sorted(groups.items()):
        low = name.lower()
        why = keep.get(name) or ("needed for input, security, network or calls" if any(w in low for w in NEVER_PAUSE) else None) \
            or ("in your focus_allow setting" if any(w in low for w in allow) else None) \
            or ("serving a model" if low == "ollama" and not ollama_idle else None)
        cpu, mem = sum(p["cpu"] for p in procs), sum(p["mem"] for p in procs)
        if why:
            kept.append(dict(name=name, reason=why))
        elif cpu >= FOCUS_MIN_CPU or mem >= FOCUS_MIN_MEM:
            pause.append(dict(name=name, cpu=cpu, mem=mem, count=len(procs), procs=procs))
    return dict(pause=sorted(pause, key=lambda g: (-g["cpu"], -g["mem"])), kept=kept)


def focus_snapshot():
    table = perf_table()
    ollama = next((it for it in dev_items(table) if it["id"] == "ollama"), None)
    return table, focus_plan(table, frontmost_pid(), load_settings()["focus_allow"], bool(ollama and ollama["risk"] == "safe"))


def start_focus_timer():
    """A detached `macguard focus-timer` resumes everything when the time is up, even after this terminal closes."""
    subprocess.Popen([sys.executable, os.path.abspath(__file__), "focus-timer"], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def focus_pause(groups, hours, source="cli"):
    """SIGSTOP every process of the given app groups (re-checked first) and record them in focus.json."""
    now = {p["pid"]: p for p in perf_table()}
    protected = session_pids(list(now.values()))
    state = load_focus() or {"paused": [], "since": time.time()}
    paused = []
    for g in groups:
        for p in g["procs"]:
            q = now.get(p["pid"])
            if not q or q["exe"] != p["exe"] or not stoppable(q, protected):
                continue
            try:
                os.kill(p["pid"], signal.SIGSTOP)
            except (ProcessLookupError, PermissionError):
                continue
            paused.append(dict(pid=p["pid"], exe=p["exe"], name=g["name"]))
    state["paused"] += paused
    state.update(until=time.time() + hours * 3600, source=source)
    ensure_state()
    write_json(focus_file(), state)
    if paused:
        log_event("focus", f"paused {len(paused)} process(es): {', '.join(sorted({e['name'] for e in paused}))}")
        start_focus_timer()
    return paused, state["until"]


def focus_resume(reason="resume"):
    """SIGCONT everything focus paused (only pids that still run the same program), then forget the state."""
    state = load_focus()
    if not state:
        return []
    now = {p["pid"]: p for p in perf_table()}
    resumed = []
    for e in state["paused"]:
        p = now.get(e["pid"])
        if p and p["exe"] == e["exe"]:
            try:
                os.kill(e["pid"], signal.SIGCONT)
                resumed.append(e)
            except (ProcessLookupError, PermissionError):
                pass
    try:
        os.remove(focus_file())
    except OSError:
        pass
    log_event("focus", f"resumed {len(resumed)} process(es) ({reason})")
    return resumed


def focus_check_expired():
    """Nothing stays paused (or in developer mode) forever: called by every command, the watcher and the focus timer."""
    dev = load_devmode()
    if dev and time.time() >= dev.get("until", 0):
        devmode_off("timeout")
    state = load_focus()
    if state and time.time() >= state.get("until", 0):
        return focus_resume("timeout")
    return None


def focus_status():
    state = load_focus() or {}
    return dict(active=bool(state.get("paused")), count=len(state.get("paused", [])), until=state.get("until"),
                names=sorted({e["name"] for e in state.get("paused", [])}), hours=load_settings()["focus_hours"])


def cmd_focus_timer(args):
    """Detached: ends dev focus and developer mode when their time is up, then exits."""
    while True:
        focus_check_expired()
        states = [s for s in (load_focus(), load_devmode()) if s]
        if not states:
            return
        time.sleep(max(1, min(60, min(s.get("until", 0) for s in states) - time.time())))


def cmd_focus(args):
    if args.resume:
        res = focus_resume("macguard perf --resume")
        print(f"{C['g']}Resumed {len(res)} process(es){C['x']}" + (f": {', '.join(sorted({e['name'] for e in res}))}" if res else
                                                                   " (nothing was paused)"))
        return
    _, plan = focus_snapshot()
    hours = load_settings()["focus_hours"]
    print(f"{C['B']}Dev focus{C['x']}  {C['d']}pauses background apps that aren't dev tools (SIGSTOP); they continue exactly "
          f"where they were on resume{C['x']}")
    for g in plan["pause"]:
        print(f"  {g['cpu']:>6.1f}% {human(g['mem']):>7}  {C['y']}pause{C['x']}  {g['name']}  {C['d']}({g['count']} process"
              f"{'es' if g['count'] != 1 else ''}){C['x']}")
    if not plan["pause"]:
        print(f"  {C['g']}Nothing to pause: only dev tools are busy.{C['x']}")
    if plan["kept"]:
        print(f"  {C['d']}keeps running: " + ", ".join(f"{k['name']} ({k['reason']})" for k in plan["kept"][:20]) + C["x"])
    if not args.apply or not plan["pause"]:
        if plan["pause"]:
            print(f"\nDry run. Pause them: {C['B']}macguard perf --focus --apply{C['x']}   "
                  f"(add apps to keep: macguard settings focus_allow 'Spotify,Figma')")
        return
    if not args.yes and input(f"\nPause these apps for up to {hours}h? They may show as 'Not Responding' until resumed. "
                              "Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    paused, until = focus_pause(plan["pause"], hours)
    print(f"{C['g']}Paused {len(paused)} process(es) in {len({e['name'] for e in paused})} app(s).{C['x']}  "
          f"They may look 'Not Responding' - that's expected.")
    print(f"Resume: {C['B']}macguard perf --resume{C['x']}  (automatic at {dt.datetime.fromtimestamp(until):%H:%M})")


# ---------------------------------------------------------------- developer mode (one switch for dev work)

# (domain, key, type, value): user-level settings that turn off motion. The old value is saved and put back on `off`.
MOTION_DEFAULTS = [
    ("com.apple.universalaccess", "reduceMotion", "bool", "true"),         # system-wide Reduce Motion
    ("com.apple.universalaccess", "reduceTransparency", "bool", "true"),   # no blur behind menus and the Dock
    ("NSGlobalDomain", "NSAutomaticWindowAnimationsEnabled", "bool", "false"),  # window open/close zoom
    ("NSGlobalDomain", "NSWindowResizeTime", "float", "0.001"),            # sheets and resizes
    ("NSGlobalDomain", "NSScrollAnimationEnabled", "bool", "false"),       # smooth-scroll animation
    ("com.apple.dock", "launchanim", "bool", "false"),                     # bouncing app launch
    ("com.apple.dock", "mineffect", "string", "scale"),                    # minimize: scale, not genie
    ("com.apple.dock", "expose-animation-duration", "float", "0.1"),       # Mission Control
    ("com.apple.dock", "autohide-delay", "float", "0"),
    ("com.apple.dock", "autohide-time-modifier", "float", "0.15"),
    ("com.apple.finder", "DisableAllAnimations", "bool", "true"),          # Finder windows (from its next launch)
]
DEFAULTS_TYPES = {"boolean": "bool", "float": "float", "integer": "int", "string": "string"}
DEVMODE_PARTS = ("stop", "pause", "motion", "awake")


def devmode_file():
    return os.path.join(STATE_DIR, "devmode.json")


def load_devmode():
    try:
        return json.loads(read_text(devmode_file()))
    except (OSError, ValueError):
        return None


def read_default(domain, key):
    """(type, value) of a user default; (None, None) if it isn't set; ('unsupported', None) for dicts/arrays/dates."""
    rc, out, _ = run(["defaults", "read-type", domain, key], timeout=10)
    if rc:
        return None, None
    kind = DEFAULTS_TYPES.get(out.strip().removeprefix("Type is ").strip(), "unsupported")
    if kind == "unsupported":
        return kind, None
    rc, out, _ = run(["defaults", "read", domain, key], timeout=10)
    return (kind, out.strip()) if rc == 0 else (None, None)


def apply_motion():
    """Write MOTION_DEFAULTS, remembering each previous value. Returns (records, failed keys)."""
    records, failed = [], []
    for domain, key, kind, value in MOTION_DEFAULTS:
        prev_kind, prev = read_default(domain, key)
        if prev_kind == "unsupported":
            continue
        rc, _, err = run(["defaults", "write", domain, key, f"-{kind}", value], timeout=10)
        if rc:
            failed.append(f"{key} ({err.strip()[:60] or 'not allowed'})")
            continue
        records.append(dict(domain=domain, key=key, prev_kind=prev_kind, prev=prev))
    if any(r["domain"] == "com.apple.dock" for r in records):
        run(["killall", "Dock"], timeout=10)  # the Dock re-reads its settings when it restarts (a second, no windows lost)
    return records, failed


def restore_motion(records):
    for r in records:
        if r["prev_kind"] is None:
            run(["defaults", "delete", r["domain"], r["key"]], timeout=10)
        else:
            value = {"1": "true", "0": "false"}.get(r["prev"], r["prev"]) if r["prev_kind"] == "bool" else r["prev"]
            run(["defaults", "write", r["domain"], r["key"], f"-{r['prev_kind']}", value], timeout=10)
    if any(r["domain"] == "com.apple.dock" for r in records):
        run(["killall", "Dock"], timeout=10)


def restart_cmd(item):
    """How `devmode off` brings back a service it stopped (only apps people expect to find running again)."""
    if item["id"] == "docker":
        return ["open", "-a", "Docker"]
    if item["id"] == "ollama":
        if item["stop"] and item["stop"][0][0] == "quit":
            return ["open", "-a", "Ollama"]
        if item["stop"] and item["stop"][0][0] == "cmd" and item["stop"][0][1][:2] == ["launchctl", "bootout"]:
            label = item["stop"][0][1][2].rsplit("/", 1)[-1]
            return ["launchctl", "bootstrap", f"gui/{os.getuid()}", os.path.join(HOME, "Library/LaunchAgents", label + ".plist")]
    return None


def devmode_plan(skip=()):
    """Everything `devmode on` would do, computed fresh: what it stops, pauses and changes, plus advice it can't apply."""
    r = perf_report()
    stop = perf_plan(r["items"]) if "stop" not in skip else []
    stopping = {p["pid"] for it in stop for p in it["procs"]}
    pause = [g for g in focus_snapshot()[1]["pause"] if not stopping & {p["pid"] for p in g["procs"]}] \
        if "pause" not in skip else []  # no point pausing what is about to be stopped
    advice = []
    if r["state"]["low_power"]:
        advice.append("Turn off Low Power Mode: System Settings > Battery (it slows the CPU)")
    advice.append("Silence notifications: Control Center > Focus > Do Not Disturb")
    if any(it["id"] == "spotlight" for it in r["items"]):
        advice.append("Keep Spotlight out of build output: System Settings > Spotlight > Search Privacy")
    if r["disk"].get("low"):
        advice.append("Free disk space first: macguard clean --apply")
    return dict(stop=stop, pause=pause, motion="motion" not in skip, awake="awake" not in skip, advice=advice,
                skip=[s for s in skip if s in DEVMODE_PARTS])


def devmode_on(plan, hours, source="cli"):
    """Apply a devmode_plan and record how to undo every part in ~/.macguard/devmode.json."""
    if load_devmode():
        raise ValueError("developer mode is already on")
    state = dict(since=time.time(), until=time.time() + hours * 3600, source=source, stopped=[], motion=[], failed=[],
                 caffeinate=None, paused=0)
    for res, it in zip(apply_perf(plan["stop"]), plan["stop"]):
        state["stopped"].append(dict(id=it["id"], name=it["name"], start=it["start"], restart=restart_cmd(it), detail=res["detail"]))
    if plan["pause"]:
        paused, _ = focus_pause(plan["pause"], hours, source="devmode")
        state["paused"] = len(paused)
    if plan["motion"]:
        state["motion"], state["failed"] = apply_motion()
    if plan["awake"] and shutil.which("caffeinate"):
        # -i: no idle sleep, -s: no system sleep on power, -t: ends by itself when the time is up anyway
        p = subprocess.Popen(["caffeinate", "-i", "-s", "-t", str(int(hours * 3600))], start_new_session=True,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        state["caffeinate"] = p.pid
    ensure_state()
    write_json(devmode_file(), state)
    start_focus_timer()  # also turns developer mode off when the time is up
    log_event("devmode", f"on: stopped {len(state['stopped'])}, paused {state['paused']}, {len(state['motion'])} motion setting(s)"
                         + (", keeping awake" if state["caffeinate"] else ""))
    return state


def devmode_off(reason="devmode off"):
    """Undo everything devmode_on did: resume paused apps, restore settings, restart stopped services, let the Mac sleep."""
    state = load_devmode()
    if not state:
        return None
    resumed = focus_resume(reason) if (load_focus() or {}).get("source") == "devmode" else []
    restore_motion(state.get("motion", []))
    restarted = []
    for s in state.get("stopped", []):
        if s.get("restart") and run(s["restart"], timeout=60)[0] == 0:
            restarted.append(s["name"])
    pid = state.get("caffeinate")
    if pid and any(p["pid"] == pid and _base(p) == "caffeinate" for p in perf_table()):
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    try:
        os.remove(devmode_file())
    except OSError:
        pass
    log_event("devmode", f"off ({reason}): resumed {len(resumed)}, restored {len(state.get('motion', []))} setting(s), "
                         f"restarted {', '.join(restarted) or 'nothing'}")
    return dict(resumed=len(resumed), restored=len(state.get("motion", [])), restarted=restarted,
                not_restarted=[f"{s['name']}: {s['start']}" for s in state.get("stopped", []) if s["name"] not in restarted])


def devmode_status():
    s = load_devmode() or {}
    return dict(active=bool(s), since=s.get("since"), until=s.get("until"), stopped=[x["name"] for x in s.get("stopped", [])],
                paused=s.get("paused", 0), motion=len(s.get("motion", [])), failed=s.get("failed", []),
                awake=bool(s.get("caffeinate")), hours=load_settings()["focus_hours"])


def cmd_devmode(args):
    st = load_devmode()
    if args.action == "off":
        r = devmode_off("macguard devmode off")
        if r is None:
            print("Developer mode is not on.")
            return
        print(f"{C['g']}Developer mode off.{C['x']} Resumed {r['resumed']} process(es), restored {r['restored']} setting(s)"
              + (f", started {', '.join(r['restarted'])} again" if r["restarted"] else "") + ".")
        for x in r["not_restarted"]:
            print(f"  {C['d']}not restarted (start it when you need it): {x}{C['x']}")
        return
    if st:
        print(f"{C['y']}Developer mode is on{C['x']} since {dt.datetime.fromtimestamp(st['since']):%H:%M}, until "
              f"{dt.datetime.fromtimestamp(st['until']):%H:%M}: stopped {', '.join(x['name'] for x in st['stopped']) or 'nothing'}; "
              f"paused {st['paused']} process(es); animations {'off' if st['motion'] else 'unchanged'}; "
              f"{'keeping the Mac awake' if st['caffeinate'] else 'normal sleep'}.\nTurn it off: {C['B']}macguard devmode off{C['x']}")
        return
    skip = tuple(x.strip() for x in (args.skip or "").split(",") if x.strip())
    plan = devmode_plan(skip)
    hours = load_settings()["focus_hours"]
    print(f"{C['B']}Developer mode{C['x']}  {C['d']}one switch: only development work runs, no animations; "
          f"`macguard devmode off` puts everything back{C['x']}")
    print(f"  stop      {', '.join(it['name'] for it in plan['stop']) or '-'}")
    print(f"  pause     {', '.join(g['name'] for g in plan['pause']) or '-'}  {C['d']}(SIGSTOP, may look 'Not Responding'){C['x']}")
    print(f"  motion    {'Reduce Motion & Transparency, window/Dock/Finder animations off' if plan['motion'] else '-'}")
    print(f"  awake     {'keep the Mac from sleeping during long builds (caffeinate)' if plan['awake'] else '-'}")
    print(f"  ends      by `macguard devmode off`, or by itself after {hours} h")
    for a in plan["advice"]:
        print(f"  {C['d']}tip: {a}{C['x']}")
    if args.action != "on":
        print(f"\nTurn it on: {C['B']}macguard devmode on{C['x']}   (leave parts out: --skip stop,pause,motion,awake)")
        return
    if not args.yes and input("\nTurn on developer mode? Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    st = devmode_on(plan, hours)
    print(f"{C['g']}Developer mode on.{C['x']} Stopped {len(st['stopped'])}, paused {st['paused']} process(es), "
          f"{len(st['motion'])} motion setting(s) changed" + (", keeping the Mac awake." if st["caffeinate"] else "."))
    for f in st["failed"]:
        print(f"  {C['y']}couldn't change{C['x']} {f} - System Settings > Accessibility > Display has the same switches")
    print(f"Turn it off: {C['B']}macguard devmode off{C['x']}  (automatic at {dt.datetime.fromtimestamp(st['until']):%H:%M})")


# ---------------------------------------------------------------- ready for shutdown

GIT_SKIP_DIRS = {"node_modules", "build", "dist", "target", ".venv", "venv", "Pods", "DerivedData", "Library", "Builds"}


def find_repos(max_depth=4):
    """Git repositories under the usual project folders (nested ones too), each once."""
    repos, seen = [], set()
    for base in project_roots():
        for root, dirs, files in os.walk(base):
            depth = root.count(os.sep) - base.count(os.sep)
            if ".git" in dirs or ".git" in files:
                real = os.path.realpath(root)
                if real not in seen:
                    seen.add(real)
                    repos.append(root)
            dirs[:] = [] if depth >= max_depth else [d for d in dirs if not d.startswith(".") and d not in GIT_SKIP_DIRS]
    return sorted(repos, key=str.lower)


def git_state(repo):
    """dict(path, branch, changed, unpushed, local_only) - local_only: the branch has never been pushed anywhere."""
    _, out, _ = run(["git", "-C", repo, "status", "--porcelain"], timeout=60)
    changed = len([l for l in out.splitlines() if l.strip()])
    _, branch, _ = run(["git", "-C", repo, "rev-parse", "--abbrev-ref", "HEAD"], timeout=15)
    branch = branch.strip()
    rc, ahead, _ = run(["git", "-C", repo, "rev-list", "--count", "@{u}..HEAD"], timeout=15)
    has_commits = run(["git", "-C", repo, "rev-parse", "--verify", "-q", "HEAD"], timeout=15)[0] == 0
    local_only = rc != 0 and has_commits and branch not in ("", "HEAD")
    return dict(path=repo.replace(HOME, "~"), branch=branch or "?", changed=changed,
                unpushed=int(ahead.strip()) if rc == 0 and ahead.strip().isdigit() else 0, local_only=local_only)


def shutdown_report(stale_days=30):
    """Everything to know before shutting the Mac down: what cleanup would free, what would be stopped, what is still
    running (and would be cut off), and git work that only exists on this Mac."""
    junk = [r for r in scan_junk(stale_days) if r["risk"] == "safe" and r["size"] > 0]
    r = perf_report()
    with ThreadPoolExecutor(max_workers=8) as ex:
        git = [g for g in ex.map(git_state, find_repos()) if g["changed"] or g["unpushed"] or g["local_only"]]
    stop = perf_plan(r["items"])
    stopping = {it["id"] for it in stop}
    running = []
    for it in r["items"]:
        if it["id"] in stopping or it["risk"] == "system":
            continue
        warn = {"render": "shutting down now cancels it - wait until it finishes",
                "docker": "macOS quits Docker at shutdown; its containers stop with it",
                "node-dev": "it stops at shutdown; start it again next time"}.get(it["id"], "it stops at shutdown")
        running.append(dict(id=it["id"], name=it["name"], why=it["why"], warn=warn, cpu=it["cpu"]))
    findings = []
    if any(x["id"] == "render" for x in running):
        findings.append(("high", "A video render is still running", "shutting down now cancels it"))
    unpushed = [g for g in git if g["unpushed"]]
    local = [g for g in git if g["local_only"]]
    if unpushed:
        findings.append(("medium", f"{len(unpushed)} repo(s) with commits not pushed",
                         ", ".join(f"{g['path']} ({g['unpushed']})" for g in unpushed)))
    if local:
        findings.append(("medium", f"{len(local)} branch(es) never pushed - only on this Mac",
                         ", ".join(f"{g['path']} [{g['branch']}]" for g in local)))
    edited = [g for g in git if g["changed"]]
    if edited:
        findings.append(("info", f"{len(edited)} repo(s) with uncommitted changes",
                         "safe on disk across a shutdown, but not backed up: " + ", ".join(g["path"] for g in edited[:8])
                         + (" ..." if len(edited) > 8 else "")))
    ds, fs = devmode_status(), focus_status()
    return dict(ready=not any(f[0] == "high" for f in findings), findings=findings, disk=r["disk"],
                clean=[dict(id=j["id"], name=j["name"], size=j["size"]) for j in junk], clean_total=sum(j["size"] for j in junk),
                stop=[dict(id=it["id"], name=it["name"], why=it["why"], start=it["start"]) for it in stop],
                running=running, git=git, devmode=ds, focus=fs, _junk=junk, _stop=stop)


def prepare_shutdown(rep):
    """Do the safe part: clean safe caches, end developer mode / dev focus, stop safe services. Never commits,
    pushes, shuts down, or touches running work (renders, dev servers, containers)."""
    done = []
    if rep["_junk"]:
        freed = sum(clean_item(r) for r in rep["_junk"])
        log_event("clean", f"[ready] freed ~{human(freed)} ({', '.join(r['id'] for r in rep['_junk'])})")
        done.append(f"cleaned {human(freed)} of caches")
    if load_devmode():
        devmode_off("ready for shutdown")
        done.append("developer mode off, settings restored")
    if load_focus():
        done.append(f"resumed {len(focus_resume('ready for shutdown'))} paused process(es)")
    for res in apply_perf(rep["_stop"]):
        done.append(f"{res['name']}: {res['detail']}" + ("" if res["ok"] else " (partly)"))
    log_event("ready", "; ".join(done) or "nothing to do")
    return done


def ready_json(rep):
    return {k: v for k, v in rep.items() if not k.startswith("_")} | {"findings": findings_json(rep["findings"])}


def cmd_ready(args):
    print("Checking caches, services and git work (about a minute)...", flush=True)
    rep = shutdown_report()
    verdict = f"{C['g']}Ready for shutdown{C['x']}" if rep["ready"] else f"{C['y']}Check before shutting down{C['x']}"
    print(f"\n{C['B']}{verdict}{C['x']}   {human(rep['disk']['free'])} free")
    print_findings(rep["findings"])
    print(f"\n{C['B']}Will prepare{C['x']}")
    print(f"  clean     {human(rep['clean_total'])} of safe caches" + (f" ({', '.join(c['id'] for c in rep['clean'])})" if rep["clean"] else ""))
    print(f"  stop      {', '.join(s['name'] for s in rep['stop']) or '-'}")
    if rep["devmode"]["active"] or rep["focus"]["active"]:
        print("  restore   " + ", ".join(x for x in ("developer mode off" if rep["devmode"]["active"] else "",
                                                       "resume paused apps" if rep["focus"]["active"] else "") if x))
    if rep["running"]:
        print(f"\n{C['B']}Still running{C['x']}  {C['d']}(left alone){C['x']}")
        for x in rep["running"]:
            print(f"  {x['name']}: {x['why']}\n    {C['d']}{x['warn']}{C['x']}")
    if rep["git"]:
        print(f"\n{C['B']}Git work only on this Mac{C['x']}")
        for g in rep["git"]:
            bits = [f"{g['changed']} changed"] if g["changed"] else []
            bits += [f"{g['unpushed']} unpushed"] if g["unpushed"] else []
            bits += ["branch never pushed"] if g["local_only"] else []
            print(f"  {g['path']} [{g['branch']}]  {C['d']}{', '.join(bits)}{C['x']}")
    if not args.apply:
        print(f"\nPrepare: {C['B']}macguard ready --apply{C['x']}  (it never commits, pushes or shuts down)")
        return
    if not args.yes and input("\nClean, restore and stop the above? Type 'yes': ").strip() != "yes":
        print("Aborted.")
        return
    for line in prepare_shutdown(rep):
        print(f"  {C['g']}✔{C['x']} {line}")
    print("\nDone. Shut down from the Apple menu when you're ready" + ("." if rep["ready"] else " - after the render finishes."))


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
    recorder = NetRecorder()
    recorder.prune()
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
            recorder.sample()
            focus_check_expired()
            if args.once:
                return
            # keep the connection history fine-grained between the (slower) full checks
            end = time.time() + args.interval
            while time.time() + NETLOG_INTERVAL < end:
                time.sleep(NETLOG_INTERVAL)
                recorder.sample()
            time.sleep(max(0, end - time.time()))
        except KeyboardInterrupt:
            return


# ---------------------------------------------------------------- settings

DEFAULT_SETTINGS = {"background_watcher": False, "watch_interval": 60, "focus_allow": [], "focus_hours": 4}


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
        print("\n  macguard settings background_watcher on|off\n  macguard settings watch_interval <seconds>"
              "\n  macguard settings focus_allow 'Spotify,Figma'   (apps dev focus never pauses; '' clears)"
              "\n  macguard settings focus_hours <hours>           (dev focus resumes by itself after this)")
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
    elif isinstance(DEFAULT_SETTINGS[args.key], list):
        s[args.key] = [x.strip().lower() for x in args.value.split(",") if x.strip()]
    else:
        s[args.key] = int(args.value)
    save_settings(s)
    if args.key.startswith("focus_"):
        print(f"{args.key} = {s[args.key]}")
        return
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
            if self.path == "/api/deepscan":
                with lock:
                    r = deep_scan(traffic=False, stale_days=args.stale_days)
                    state["scan"] = r["results"]  # so "Clean selected" works straight after a deep scan
                sp = r["space"]
                return self.send(200, dict(score=r["score"], since=r["since"], disk=r["disk"], findings=r["findings"],
                                           apps=r["apps"], listeners=r["listeners"], items=junk_json(r["results"]),
                                           space=dict(safe=sp["safe"], review=sp["review"], managed=sp["managed"],
                                                      managed_items=sp["managed_items"])))
            if self.path == "/api/installed":
                table = process_table()
                return self.send(200, [dict(name=a["name"], version=a["version"], bundle_id=a["bundle_id"], path=a["path"],
                                            protected=protected_app(a), kill_protected=kill_protected(a),
                                            processes=len(app_process_tree(a, table))) for a in app_inventory()])
            if self.path.split("?")[0] == "/api/perf":
                return self.send(200, dict(perf_json(perf_report("heavy" if self.path.endswith("?before=heavy") else None)),
                                           focus=focus_status(), devmode=devmode_status()))
            if self.path.split("?")[0] == "/api/netlog":
                q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
                d = (q.get("days") or ["7"])[0]
                days = max(1, min(NETLOG_KEEP_DAYS, int(d) if d.isdigit() else 7))
                rows = netlog_rows(days)
                names = resolve_names({r["rhost"] for r in rows})
                return self.send(200, dict(netlog_summary(rows, names, 15), days=days, status=netlog_status(),
                                           findings=findings_json(analyze_netlog(rows, names))))
            if self.path.split("?")[0] in ("/api/captures", "/api/capture", "/api/capture/file"):
                q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).items()}
                cap = capture_mod()
                try:
                    if self.path.startswith("/api/captures"):
                        return self.send(200, {"captures": cap.list_captures(), "keylog": cap.keylog_status(),
                                               "ifaces": cap.interfaces(), "iface": cap.default_iface()})
                    if self.path.startswith("/api/capture?"):
                        return self.send(200, cap.analyze(cid=q.get("id")))
                    if "flow" in q:
                        data, name = cap.flow_bytes(q.get("id"), int(q["flow"]), q.get("dir", "out")), \
                            f"{q.get('id')}-flow{int(q['flow'])}-{q.get('dir', 'out')}.bin"
                    else:
                        path = cap.capture_path(q.get("id"))
                        with open(path, "rb") as fh:
                            data, name = fh.read(), os.path.basename(path)
                except (ValueError, FileNotFoundError) as e:
                    return self.send(404, {"error": str(e)})
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.tcpdump.pcap" if name.endswith(".pcap") else "application/octet-stream")
                self.send_header("Content-Disposition", f'attachment; filename="{name}"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                return self.wfile.write(data)
            if self.path == "/api/procs":
                procs = heavy_processes()
                return self.send(200, [{k: p[k] for k in ("pid", "name", "exe", "cpu", "mem", "elapsed", "kind",
                                                          "advice", "killable")} for p in procs])
            if self.path == "/api/ready":
                with lock:
                    state["ready"] = shutdown_report(args.stale_days)
                    return self.send(200, ready_json(state["ready"]))
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
            if self.path in ("/api/kill/plan", "/api/kill"):
                app = next((a for a in app_inventory() if a["path"] == body.get("path")), None)
                if not app:
                    return self.send(404, {"error": "app not found"})
                procs = app_process_tree(app)
                view = dict(name=app["name"], blocked=kill_protected(app), agents=app_launch_labels(app),
                            processes=[dict(pid=p["pid"], exe=p["exe"].replace(app["path"], "<app>"),
                                            root=p["uid"] != os.getuid()) for p in procs])
                if self.path == "/api/kill/plan":
                    return self.send(200, view)
                try:
                    r = kill_app(app)
                except ValueError as e:
                    return self.send(409, {"error": str(e)})
                return self.send(200, dict(view, stopped=len(r["stopped"]), unloaded=r["unloaded"],
                                           needs_admin=[p["pid"] for p in r["needs_admin"]],
                                           survivors=[p["pid"] for p in r["survivors"]]))
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
                if plan["running"] and body.get("quit"):
                    kill_app(app)
                    plan["running"] = app_running(app)
                try:
                    moved, failed = do_uninstall(plan)
                except ValueError as e:
                    return self.send(409, {"error": str(e)})
                return self.send(200, dict(view, moved=len(moved), freed=sum(n for _, n in moved),
                                           failed=[{"path": p.replace(HOME, "~"), "error": e} for p, e in failed]))
            if self.path == "/api/netlog/record":
                rec, end = NetRecorder(), time.time() + max(2, min(60, int(body.get("seconds") or 10)))
                while True:
                    rec.sample()
                    if time.time() + 2 > end:
                        break
                    time.sleep(2)
                return self.send(200, netlog_status())
            if self.path == "/api/capture/start":
                cap = capture_mod()
                try:
                    meta = cap.capture(body.get("seconds") or 30, body.get("iface") or None, body.get("preset") or "all",
                                       (body.get("host") or "").strip() or None, body.get("port") or None,
                                       (body.get("filter") or "").strip() or None)
                except (ValueError, RuntimeError) as e:
                    return self.send(409, {"error": str(e)})
                return self.send(200, {"id": meta["id"], "size": meta["size"]})
            if self.path == "/api/capture/save":
                # copy a capture (or one flow's payload) to ~/Downloads and show it in Finder
                cap = capture_mod()
                try:
                    cid = cap.capture_path(body.get("id")) and body["id"]
                    if body.get("flow") is not None:
                        data = cap.flow_bytes(cid, int(body["flow"]), body.get("dir", "out"))
                        name = f"{cid}-flow{int(body['flow'])}-{body.get('dir', 'out')}.bin"
                    else:
                        with open(cap.capture_path(cid), "rb") as fh:
                            data, name = fh.read(), f"macguard-{cid}.pcap"
                except (ValueError, FileNotFoundError, KeyError, TypeError) as e:
                    return self.send(404, {"error": str(e)})
                dest = os.path.join(HOME, "Downloads", name)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "wb") as fh:
                    fh.write(data)
                os.chmod(dest, 0o600)
                run(["open", "-R", dest])
                return self.send(200, {"path": dest, "size": len(data)})
            if self.path == "/api/procs/kill":
                # SIGTERM only, and kill_process re-checks the pid/exe pair and refuses system processes
                try:
                    pid, exe = int(body["pid"]), str(body["exe"])
                except (KeyError, TypeError, ValueError):
                    return self.send(400, {"error": "pid and exe required"})
                return self.send(200, kill_process(pid, exe))
            if self.path in ("/api/perf/focus/plan", "/api/perf/focus"):
                # re-planned on the server every time: the page never names pids
                with lock:
                    _, plan = focus_snapshot()
                    view = dict(pause=[{k: g[k] for k in ("name", "cpu", "mem", "count")} for g in plan["pause"]],
                                kept=plan["kept"], hours=load_settings()["focus_hours"])
                    if self.path == "/api/perf/focus/plan":
                        return self.send(200, view)
                    paused, until = focus_pause(plan["pause"], view["hours"], source="ui")
                return self.send(200, dict(view, paused=len(paused), until=until))
            if self.path in ("/api/devmode/plan", "/api/devmode/on"):
                # planned on the server every time; the page only chooses which parts to leave out
                skip = tuple(s for s in body.get("skip") or [] if s in DEVMODE_PARTS)
                with lock:
                    plan = devmode_plan(skip)
                    view = dict(stop=[it["name"] for it in plan["stop"]], pause=[g["name"] for g in plan["pause"]],
                                motion=plan["motion"], awake=plan["awake"], advice=plan["advice"],
                                hours=load_settings()["focus_hours"])
                    if self.path == "/api/devmode/plan":
                        return self.send(200, view)
                    try:
                        devmode_on(plan, view["hours"], source="ui")
                    except ValueError as e:
                        return self.send(409, {"error": str(e)})
                return self.send(200, dict(view, status=devmode_status()))
            if self.path == "/api/ready/prepare":
                # acts on the report the page just showed (like /api/clean on the last scan), then forgets it
                with lock:
                    if not state.get("ready"):
                        return self.send(409, {"error": "Check first"})
                    done, state["ready"] = prepare_shutdown(state["ready"]), None
                return self.send(200, {"done": done})
            if self.path == "/api/devmode/off":
                with lock:
                    return self.send(200, devmode_off("Mac Cleanup UI") or {"error": "not on"})
            if self.path == "/api/perf/resume":
                with lock:
                    return self.send(200, {"resumed": len(focus_resume("Mac Cleanup UI"))})
            if self.path == "/api/perf/stop":
                # re-plan from a fresh snapshot: the page only names item ids, never pids or commands
                ids = {str(i) for i in body.get("ids") or []}
                with lock:
                    plan = perf_plan(perf_report()["items"], ids) if ids else []
                    results = apply_perf(plan)
                return self.send(200, {"stopped": results})
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

    def end_ui_session(*_):
        # the app (or Ctrl-C) ends the session: what the UI paused must not stay paused
        if (load_focus() or {}).get("source") == "ui":
            focus_resume("Mac Cleanup closed")

    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda *a: (end_ui_session(), os._exit(0)))  # the app quits with launchctl bootout
    if args.parent_pid:
        # launched by the app: exit when the app goes away
        def watchdog():
            while True:
                time.sleep(2)
                try:
                    os.kill(args.parent_pid, 0)
                except OSError:
                    end_ui_session()
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
        end_ui_session()


def cmd_mcp(args):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import macguard_mcp
    macguard_mcp.serve()


def capture_mod():
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import macguard_capture
    return macguard_capture


def cmd_capture(args):
    capture_mod().cmd_capture(args)


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
    p = sub.add_parser("deepscan", help="every check in one prioritised report with fixes")
    p.add_argument("--clean", action="store_true", help="then clean the safe items"); p.add_argument("--yes", action="store_true")
    p.add_argument("--traffic", action="store_true", help="also sample live traffic for 6s")
    p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_deepscan)
    p = sub.add_parser("apps"); p.add_argument("--online", action="store_true", help="also check Apple for macOS updates")
    p.add_argument("--list", action="store_true", help="print every app"); p.set_defaults(fn=cmd_apps)
    p = sub.add_parser("uninstall", help="remove an app and its ~/Library data (to the Trash)")
    p.add_argument("app", help="app name or bundle id"); p.add_argument("--apply", action="store_true")
    p.add_argument("--yes", action="store_true"); p.add_argument("--leftovers-only", action="store_true",
                                                                 help="keep the app, clear its data (reset)")
    p.add_argument("--quit", action="store_true", help="stop the app and everything under it first")
    p.set_defaults(fn=cmd_uninstall)
    p = sub.add_parser("kill", help="quit an app and every process under it")
    p.add_argument("app", help="app name or bundle id"); p.add_argument("--yes", action="store_true")
    p.add_argument("--keep-agents", action="store_true", help="don't unload its launch agents (it may relaunch)")
    p.set_defaults(fn=cmd_kill)
    p = sub.add_parser("perf", help="what's hogging CPU/memory/heat; free resources for dev work")
    p.add_argument("--apply", action="store_true", help="stop the safe items (or the --only ones)")
    p.add_argument("--only", help="comma-separated item ids (needed for review items)")
    p.add_argument("--before", choices=["heavy"], help="also check readiness for a Unity/Xcode/Android build or render")
    p.add_argument("--focus", action="store_true", help="pause background apps that aren't dev tools (dry run without --apply)")
    p.add_argument("--resume", action="store_true", help="resume everything --focus paused")
    p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_perf)
    sub.add_parser("focus-timer", help=argparse.SUPPRESS).set_defaults(fn=cmd_focus_timer)
    p = sub.add_parser("ready", help="ready for shutdown: report, and --apply to prepare")
    p.add_argument("--apply", action="store_true"); p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_ready)
    p = sub.add_parser("devmode", help="one switch for dev work: stop, pause, no animations, stay awake")
    p.add_argument("action", nargs="?", choices=["status", "on", "off"], default="status")
    p.add_argument("--skip", help="leave parts out: stop,pause,motion,awake"); p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_devmode)
    p = sub.add_parser("traffic"); p.add_argument("--seconds", type=int, default=8); p.set_defaults(fn=cmd_traffic)
    p = sub.add_parser("netmon"); p.add_argument("--interval", type=int, default=5); p.add_argument("--seconds", type=int)
    p.set_defaults(fn=cmd_netmon)
    p = sub.add_parser("capture", help="record packets (asks for admin) and show what was sent")
    p.add_argument("--seconds", type=int, default=30); p.add_argument("--iface")
    p.add_argument("--preset", choices=["all", "local", "plaintext"], default="all",
                   help="local = only your LAN (IoT devices); plaintext = HTTP/MQTT/CoAP/DNS/... ports")
    p.add_argument("--host", help="only traffic to/from this IP or name"); p.add_argument("--port", type=int)
    p.add_argument("--filter", help="extra tcpdump filter expression")
    p.add_argument("--list", action="store_true", help="list saved captures")
    p.add_argument("--show", metavar="ID", help="analyze a saved capture"); p.add_argument("--file", help="analyze any classic .pcap")
    p.add_argument("--payload", action="store_true", help="also print what was sent")
    p.add_argument("--limit", type=int, default=25); p.set_defaults(fn=cmd_capture)
    p = sub.add_parser("netlog"); p.add_argument("--days", type=int, default=7); p.add_argument("--proc")
    p.add_argument("--limit", type=int, default=15); p.set_defaults(fn=cmd_netlog)
    p = sub.add_parser("procs"); p.add_argument("--cpu", type=float, default=HEAVY_CPU, help="CPU %% threshold")
    p.add_argument("--mem-mb", type=int, default=HEAVY_MEM >> 20, help="memory threshold in MB")
    p.add_argument("--kill", type=int, metavar="PID"); p.add_argument("--force", action="store_true")
    p.add_argument("--yes", action="store_true"); p.set_defaults(fn=cmd_procs)
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
    sub.add_parser("mcp", help="MCP server on stdio for AI clients").set_defaults(fn=cmd_mcp)
    args = ap.parse_args()
    if args.fn is not cmd_focus_timer:
        focus_check_expired()  # nothing stays paused past its time, whichever command runs next
    args.fn(args)


if __name__ == "__main__":
    main()
