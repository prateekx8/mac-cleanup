#!/usr/bin/python3
"""mac-cleanup (macguard) - clean, monitor and secure a macOS development machine.

Commands:
  scan                 Disk junk analysis (read-only)
  clean                Clean junk (dry-run unless --apply)
  net                  Network snapshot: listeners, connections, ARP/DNS, threats
  security             Security posture audit (firewall, SIP, launch agents, ...)
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
import re
import shutil
import subprocess
import sys
import time

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
    dict(id="docker", name="Docker unused images/build cache", risk="safe", special="docker"),
    dict(id="user-logs", name="User logs", risk="safe", paths=[f"{H}/Library/Logs/*"]),
    dict(id="selenium-prisma", name="Selenium / Prisma / Puppeteer caches", risk="safe",
         paths=[f"{H}/.cache/selenium", f"{H}/.cache/prisma", f"{H}/.cache/puppeteer", f"{H}/.cache/ms-playwright"]),
    dict(id="jetbrains-old", name="Old JetBrains IDE versions", risk="safe", special="jetbrains"),
    dict(id="docker-install-tmp", name="Stuck Docker installer download", risk="review",
         paths=[f"{H}/Library/Application Support/com.docker.install/in_progress"], note="quit Docker Desktop first"),
    dict(id="android-avd", name="Android emulator images (AVDs)", risk="review", paths=[f"{H}/.android/avd/*"]),
    dict(id="android-ndk-old", name="Old Android NDK versions", risk="review", special="ndk"),
    dict(id="project-artifacts", name="Stale project build dirs (node_modules/target/build)", risk="review", special="projects"),
    dict(id="trash", name="Trash", risk="review", paths=[f"{H}/.Trash/*"]),
    dict(id="downloads-old", name="Downloads older than 90 days", risk="review", special="downloads"),
]

ARTIFACT_DIRS = {"node_modules", "target", ".next", ".nuxt", ".turbo", ".parcel-cache", "DerivedData", ".venv", "venv", "__pycache__", ".pytest_cache"}
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


def find_project_artifacts(stale_days=30):
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
                is_art = d in ARTIFACT_DIRS or (d in GUARDED_ARTIFACTS and any(f in files for f in GUARDED_ARTIFACTS[d]))
                if d == "target" and "Cargo.toml" not in files and "pom.xml" not in files:
                    is_art = False
                if is_art and not os.path.islink(full):
                    last = newest_mtime(root, d)
                    found.append({"path": full, "project": root, "stale": last < cutoff,
                                  "last_touched": dt.datetime.fromtimestamp(last).strftime("%Y-%m-%d") if last else "?"})
                elif not d.startswith(".") or d in (".github",):
                    keep.append(d)
            dirs[:] = keep
    for f in found:
        f["size"] = du(f["path"])
    return sorted(found, key=lambda x: -x["size"])


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


def docker_reclaimable():
    rc, out, _ = run(["docker", "system", "df", "--format", "{{json .}}"], timeout=20)
    if rc:
        return 0
    total = 0
    for line in out.splitlines():
        m = re.match(r"([\d.]+)\s*([kKMGT]?B)", json.loads(line).get("Reclaimable", "0B"))
        if m:
            mult = {"B": 1, "kB": 1e3, "KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}.get(m.group(2), 1)
            total += float(m.group(1)) * mult
    return int(total)


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
    elif sp == "docker":
        n = docker_reclaimable()
        return [("docker system prune", n, "docker images/containers/build cache")] if n else []
    elif sp == "jetbrains":
        paths = old_versions(f"{HOME}/Library/Application Support/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+") + \
            old_versions(f"{HOME}/Library/Caches/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+") + \
            old_versions(f"{HOME}/Library/Logs/JetBrains/*", r"([A-Za-z]+)\d{4}\.\d+")
    elif sp == "ndk":
        paths = old_versions(f"{HOME}/Library/Android/sdk/ndk/*", r"(\d+)\.")  # keep newest per major
    elif sp == "projects":
        return [(a["path"], a["size"], f"last edited {a['last_touched']}")
                for a in find_project_artifacts(stale_days) if a["stale"] and a["size"] > 1 << 20]
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
    print(f"{C['B']}Disk{C['x']}")
    _, out, _ = run(["df", "-k", "/System/Volumes/Data"])
    f = out.splitlines()[-1].split()
    total, used, avail = int(f[1]) * 1024, int(f[2]) * 1024, int(f[3]) * 1024
    print(f"  Data volume: {human(used)} used / {human(total)}  ({human(avail)} free)\n")
    results = scan_junk(args.stale_days, verbose=True)
    safe = sum(r["size"] for r in results if r["risk"] == "safe")
    review = sum(r["size"] for r in results if r["risk"] == "review")
    print(f"\n{C['g']}Safe to clean: {human(safe)}{C['x']}   {C['y']}Needs review: {human(review)}{C['x']}")
    print(f"\nTop space users not touched by cleanup (for your judgement):")
    for p in big_dirs():
        print(f"  {human(p[1]):>7}  {p[0]}")
    print(f"\nNext: {C['B']}macguard clean{C['x']} (dry-run)  ->  {C['B']}macguard clean --apply{C['x']}")


def scan_junk(stale_days=30, verbose=False):
    results = []
    for item in JUNK:
        entries = resolve(item, stale_days)
        size = sum(e[1] for e in entries)
        results.append({**item, "entries": entries, "size": size})
        if verbose and size > 0:
            col = C["g"] if item["risk"] == "safe" else C["y"]
            print(f"  {human(size):>7}  {col}{item['risk']:<6}{C['x']} {item['id']:<20} {item['name']}"
                  + (f" {C['d']}({item['note']}){C['x']}" if item.get("note") else ""))
            if item["risk"] == "review" or item.get("special") in ("jetbrains", "ndk"):
                for p, s, label in sorted(entries, key=lambda e: -e[1])[:8]:
                    print(f"           {C['d']}{human(s):>7}  {p.replace(HOME, '~')}  {label}{C['x']}")
    return results


def big_dirs():
    cands = [f"{HOME}/Library/Application Support/*", f"{HOME}/Library/Containers/*", f"{HOME}/Library/Group Containers/*", f"{HOME}/.[!.]*"]
    sizes = []
    for pat in cands:
        for p in glob.glob(pat):
            if os.path.isdir(p) and not os.path.islink(p):
                sizes.append((p.replace(HOME, "~"), du(p)))
    return sorted(sizes, key=lambda x: -x[1])[:10]


def cmd_clean(args):
    results = scan_junk(args.stale_days)
    wanted = set(args.only.split(",")) if args.only else None
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
    if sp == "docker":
        run(["docker", "system", "prune", "-f"], timeout=600)
        run(["docker", "builder", "prune", "-f"], timeout=600)
        return r["size"]
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
            rows.append(dict(proto=parts[0], lhost=lh, lport=lp, rhost=rh, rport=rp, state=state, proc=proc, pid=pid))
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
            for sev, title, detail in analyze_net(snap):
                if sev == "high" and (title, detail) not in reported:
                    reported.add((title, detail))
                    events.append((sev, title, detail))
            for sev, title, detail in events:
                log_event(sev, f"{title}: {detail}")
                print(f"{dt.datetime.now():%H:%M:%S} {sev.upper():<6} {title}: {detail}", flush=True)
                if sev in ("high", "medium"):
                    notify(title, detail)
            if events:
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
                return self.send(200, disk_info())
            if self.path == "/api/scan":
                with lock:
                    state["scan"] = scan_junk(args.stale_days)
                return self.send(200, {"disk": disk_info(), "items": junk_json(state["scan"])})
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
            if self.path == "/api/settings":
                s = load_settings()
                s["running"] = run(["launchctl", "print", f"gui/{os.getuid()}/{AGENT_LABEL}"])[0] == 0
                return self.send(200, s)
            self.send(404, {"error": "not found"})

        def do_POST(self):
            if not self.allowed():
                return self.send(403, {"error": "forbidden"})
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
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
    p.add_argument("--stale-days", type=int, default=30); p.set_defaults(fn=cmd_clean)
    sub.add_parser("net").set_defaults(fn=cmd_net)
    sub.add_parser("security").set_defaults(fn=cmd_security)
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
