"""Dev session security monitor for macguard (Phase 1: no root, no entitlements).

Watches what a development session does while you run local LLMs (Ollama, Hugging Face), AI agents
(Claude Code) and Node projects:

  network      live outbound connections per process, reverse DNS, risky destinations, per-project baselines,
               Ollama exposure
  processes    parent/child trees under watched roots (node, npm, python, ollama, claude, docker, editors);
               shells, downloaders, osascript, launchctl... spawned under them; orphans left behind
  persistence  launch agents/daemons, login items, crontab, shell configs, /etc/hosts, git hooks, .npmrc:
               snapshot at session start, diff at the end
  files        FSEvents on ~/.ssh, ~/.aws, ~/.config, .env files, browser credential stores, keychains
               (modifications only: FSEvents cannot see reads)
  lulu         read-only audit of LuLu's allow rules, with expiry reminders you tag yourself
  deps         package-lock.json: install scripts, and known vulnerabilities from OSV.dev (opt-in, names and
               versions only)
  session      start/stop/report tying it all together, with Markdown and JSON reports

Everything is local. The only network call is the opt-in OSV lookup. Stdlib only, like macguard.
"""
import ctypes
import ctypes.util
import datetime as dt
import difflib
import fnmatch
import glob
import hashlib
import json
import os
import plistlib
import re
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.request

import macguard as mg

SEVERITIES = ("info", "warning", "critical")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
DEFAULT_INTERVAL = 3          # seconds between polls during a session (settings: session_interval, 2-5 advised)
ALERT_LOG_MAX = 1 << 20       # rotate alerts.jsonl at 1 MB
ALERT_LOG_KEEP = 5
DNS_TTL = 86400
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"


def sec_dir():
    return os.path.join(mg.STATE_DIR, "devsec")


def sec_path(*parts):
    return os.path.join(sec_dir(), *parts)


def ensure_dir(path=None):
    path = path or sec_dir()
    os.makedirs(path, mode=0o700, exist_ok=True)
    return path


def now_iso(t=None):
    return dt.datetime.fromtimestamp(t or time.time()).isoformat(timespec="seconds")


def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def save_json(path, data):
    ensure_dir(os.path.dirname(path))
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh, indent=1, default=str)
    os.replace(tmp, path)


def home_short(path):
    return path.replace(mg.HOME, "~", 1) if path and path.startswith(mg.HOME) else path


# ---------------------------------------------------------------- alerts

def alert(kind, severity, title, detail="", **extra):
    """One alert: kind (network|process|persistence|file|lulu|deps), severity (info|warning|critical)."""
    assert severity in SEV_RANK, severity
    return {"time": now_iso(), "kind": kind, "severity": severity, "title": title, "detail": detail, **extra}


def alert_key(a):
    return f"{a['kind']}|{a['title']}|{a.get('key', a['detail'])}"


def log_alerts(alerts, path=None):
    """Append to the rotating local alert log (alerts.jsonl, .1 ... .5)."""
    if not alerts:
        return
    path = path or sec_path("alerts.jsonl")
    ensure_dir(os.path.dirname(path))
    try:
        if os.path.getsize(path) > ALERT_LOG_MAX:
            for i in range(ALERT_LOG_KEEP - 1, 0, -1):
                if os.path.exists(f"{path}.{i}"):
                    os.replace(f"{path}.{i}", f"{path}.{i + 1}")
            os.replace(path, path + ".1")
    except OSError:
        pass
    with open(path, "a") as fh:
        for a in alerts:
            fh.write(json.dumps(a, default=str) + "\n")


def read_alerts(limit=200, min_severity="info", path=None):
    path = path or sec_path("alerts.jsonl")
    rows = []
    for p in (path + ".1", path):
        try:
            with open(p) as fh:
                rows += [json.loads(l) for l in fh if l.strip()]
        except (OSError, ValueError):
            continue
    rows = [r for r in rows if SEV_RANK.get(r.get("severity"), 0) >= SEV_RANK[min_severity]]
    return rows[-limit:]


# ---------------------------------------------------------------- processes

WATCHED_ROOTS = {"node", "npm", "npx", "pnpm", "yarn", "bun", "deno", "python", "python3", "ollama", "claude",
                 "docker", "com.docker.backend", "code", "cursor", "windsurf", "zed", "antigravity", "electron"}
WATCHED_ROOT_RE = re.compile(r"^(python3?(\.\d+)?|node\d*|.*code helper.*|cursor helper.*)$", re.I)
EDITOR_APPS = ("Visual Studio Code", "Cursor", "Windsurf", "Zed", "Antigravity", "Code - Insiders")
SHELLS = {"sh", "bash", "zsh", "dash", "fish", "ksh", "tcsh", "csh"}
RISKY_CHILDREN = {
    "curl": ("warning", "downloader"), "wget": ("warning", "downloader"), "base64": ("warning", "decodes hidden payloads"),
    "osascript": ("critical", "can drive other apps and show password prompts"),
    "nc": ("critical", "raw network tool (reverse shells)"), "ncat": ("critical", "raw network tool (reverse shells)"),
    "netcat": ("critical", "raw network tool (reverse shells)"), "socat": ("critical", "raw network tool"),
    "launchctl": ("critical", "can install persistence"), "crontab": ("critical", "can install persistence"),
    "security": ("warning", "keychain access tool"), "xattr": ("warning", "can strip quarantine"),
    "chmod": ("info", "makes files executable"),
}
DROP_DIRS = ("/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/")
PIPE_TO_SHELL = re.compile(r"(curl|wget)[^|;&]*\|\s*(ba|z|da)?sh\b|base64\s+(-d|--decode|-D)|\beval\s*\$\(|/dev/tcp/", re.I)


def proc_snapshot():
    """pid -> {pid, ppid, uid, exe, args, name, start} for every process (two ps calls, no root)."""
    _, out, _ = mg.run(["ps", "-axo", "pid=,ppid=,uid=,lstart=,comm="], timeout=15)
    _, argv, _ = mg.run(["ps", "-axww", "-o", "pid=,args="], timeout=15)
    cmdline = {}
    for line in argv.splitlines():
        pid, _, rest = line.strip().partition(" ")
        if pid.isdigit():
            cmdline[int(pid)] = rest.strip()
    procs = {}
    for line in out.splitlines():
        f = line.split(None, 8)  # pid ppid uid  Wed Nov 12 10:00:00 2026  comm
        if len(f) < 9:
            continue
        try:
            pid, ppid, uid = int(f[0]), int(f[1]), int(f[2])
        except ValueError:
            continue
        exe = f[8].strip()
        procs[pid] = dict(pid=pid, ppid=ppid, uid=uid, exe=exe, args=cmdline.get(pid, exe),
                          name=proc_name(exe, cmdline.get(pid, exe)), start=" ".join(f[3:8]))
    return procs


def proc_name(exe, args=""):
    base = os.path.basename(exe or "")
    if base in ("node", "python", "python3") or not base:
        return base or os.path.basename((args or "").split(" ")[0])
    return base


def is_watched_root(p):
    name = p["name"].lower()
    if name in WATCHED_ROOTS or WATCHED_ROOT_RE.match(name):
        return True
    exe = p["exe"]
    if any(f"/{a}.app/" in exe for a in EDITOR_APPS):
        return True
    # Claude Code ships as node; its args name it
    return name == "node" or "claude" in os.path.basename((p.get("args") or "").split(" ")[0]).lower()


def children_map(procs):
    kids = {}
    for p in procs.values():
        kids.setdefault(p["ppid"], []).append(p["pid"])
    return kids


def watched_trees(procs):
    """Top-most watched roots (a node under npm under claude counts once, under claude) with descendants."""
    kids = children_map(procs)
    mine, todo = set(), [os.getpid()]  # macguard itself and what it runs (ps, lsof) are not news
    while todo:
        pid = todo.pop()
        if pid not in mine:
            mine.add(pid)
            todo += kids.get(pid, [])
    procs = {pid: p for pid, p in procs.items() if pid not in mine}
    kids = children_map(procs)
    roots = []
    for p in procs.values():
        if not is_watched_root(p) or p["uid"] != os.getuid():
            continue
        parent, seen = procs.get(p["ppid"]), set()
        covered = False
        while parent and parent["pid"] not in seen and parent["pid"] > 1:
            seen.add(parent["pid"])
            if is_watched_root(parent):
                covered = True
                break
            parent = procs.get(parent["ppid"])
        if not covered:
            roots.append(p["pid"])

    def build(pid, depth=0):
        p = procs[pid]
        return {**{k: p[k] for k in ("pid", "ppid", "name", "exe", "args", "start")},
                "children": [build(c, depth + 1) for c in sorted(kids.get(pid, [])) if depth < 30 and c in procs]}
    return [build(r) for r in sorted(roots)]


def walk(tree, root=None):
    for node in tree:
        r = root or node
        yield node, r
        yield from walk(node["children"], r)


def classify_spawn(node, root):
    """The alert for a process spawned under a watched root, or None."""
    if node is root:
        return None
    name, exe, args = node["name"].lower(), node["exe"], node.get("args") or ""
    where = f"{root['name']} ({root['pid']}) -> {node['name']} ({node['pid']})"
    downloads = os.path.join(mg.HOME, "Downloads") + "/"
    if exe.startswith(DROP_DIRS) or exe.startswith(downloads):
        return alert("process", "critical", f"Program from {'Downloads' if exe.startswith(downloads) else 'a temp folder'} "
                     f"started under {root['name']}", f"{where}: {home_short(exe)}", key=f"drop|{node['pid']}",
                     pid=node["pid"], exe=exe, args=args[:400])
    if PIPE_TO_SHELL.search(args):
        return alert("process", "critical", f"{root['name']} ran a download-and-execute or decode command",
                     f"{where}: {args[:300]}", key=f"pipe|{node['pid']}", pid=node["pid"], exe=exe, args=args[:400])
    if name in RISKY_CHILDREN:
        sev, why = RISKY_CHILDREN[name]
        return alert("process", sev, f"{root['name']} spawned {name} ({why})", f"{where}: {args[:300]}",
                     key=f"spawn|{node['pid']}", pid=node["pid"], exe=exe, args=args[:400])
    if name in SHELLS or name.lstrip("-") in SHELLS:
        return alert("process", "info", f"{root['name']} spawned a shell", f"{where}: {args[:300]}",
                     key=f"shell|{node['pid']}", pid=node["pid"], exe=exe, args=args[:400])
    return None


def tree_alerts(trees):
    return [a for node, root in walk(trees) for a in [classify_spawn(node, root)] if a]


class ProcessWatcher:
    """Remembers which pids grew under a watched root, so it can tell when one is left behind."""

    def __init__(self):
        self.lineage = {}   # pid -> {"root": name, "root_pid", "exe", "start"}
        self.reported = set()

    def poll(self, procs=None, jobs=None):
        procs = procs if procs is not None else proc_snapshot()
        trees = watched_trees(procs)
        alerts = []
        for a in tree_alerts(trees):
            if alert_key(a) not in self.reported:
                self.reported.add(alert_key(a))
                alerts.append(a)
        for node, root in walk(trees):
            if node is not root:
                self.lineage.setdefault(node["pid"], {"root": root["name"], "root_pid": root["pid"], "exe": node["exe"],
                                                      "start": node["start"], "args": node.get("args", "")})
        jobs = jobs if jobs is not None else mg.launchd_jobs()
        for pid, info in list(self.lineage.items()):
            p = procs.get(pid)
            if not p or p["exe"] != info["exe"] or p["start"] != info["start"]:
                del self.lineage[pid]  # gone, or the pid was reused
                continue
            if p["ppid"] == 1 and pid not in jobs and info["root_pid"] not in procs and f"orphan|{pid}" not in self.reported:
                self.reported.add(f"orphan|{pid}")
                alerts.append(alert("process", "warning", f"Left running after {info['root']} exited",
                                    f"{p['name']} ({pid}) keeps running with no parent: {info['args'][:200]}",
                                    key=f"orphan|{pid}", pid=pid, exe=p["exe"]))
        return trees, alerts

    def orphans(self, procs):
        return [{"pid": pid, "name": procs[pid]["name"], "exe": procs[pid]["exe"], "root": info["root"]}
                for pid, info in self.lineage.items()
                if pid in procs and procs[pid]["ppid"] == 1 and info["root_pid"] not in procs]


# ---------------------------------------------------------------- network

KNOWN_GOOD = ("registry.npmjs.org", "npmjs.org", "npmjs.com", "github.com", "githubusercontent.com", "githubassets.com",
              "pypi.org", "pythonhosted.org", "huggingface.co", "hf.co", "anthropic.com", "claude.ai", "nodejs.org",
              "yarnpkg.com", "docker.io", "docker.com", "ollama.com", "ollama.ai", "googleapis.com", "apple.com",
              "icloud.com", "cloudflare.com", "openai.com", "jsdelivr.net", "unpkg.com", "pnpm.io")
OLLAMA_OK = ("ollama.com", "ollama.ai", "huggingface.co", "hf.co", "cloudflarestorage.com", "r2.cloudflarestorage.com",
             "github.com", "githubusercontent.com")
EXFIL_DOMAINS = {
    "discord.com": "Discord (webhooks)", "discordapp.com": "Discord (webhooks)", "discord.gg": "Discord",
    "api.telegram.org": "Telegram bot API", "telegram.org": "Telegram", "t.me": "Telegram",
    "ngrok.io": "ngrok tunnel", "ngrok.app": "ngrok tunnel", "ngrok-free.app": "ngrok tunnel", "ngrok.dev": "ngrok tunnel",
    "pastebin.com": "Pastebin", "paste.ee": "paste site", "hastebin.com": "paste site", "ghostbin.co": "paste site",
    "transfer.sh": "file transfer", "file.io": "file transfer", "gofile.io": "file transfer", "catbox.moe": "file host",
    "0x0.st": "file host", "temp.sh": "file transfer", "tmpfiles.org": "file transfer", "anonfiles.com": "file host",
    "webhook.site": "webhook catcher", "requestbin.com": "webhook catcher", "pipedream.net": "webhook catcher",
    "interact.sh": "OOB callback", "oast.fun": "OOB callback", "burpcollaborator.net": "OOB callback",
    "trycloudflare.com": "Cloudflare quick tunnel", "serveo.net": "SSH tunnel", "localhost.run": "SSH tunnel",
}
HIGH_UPLOAD = 50 << 20        # bytes sent by one process to one destination in a session


def domain_matches(name, domains):
    name = (name or "").lower().rstrip(".")
    return next((d for d in domains if name == d or name.endswith("." + d)), None)


def site_of(name):
    """registrable-ish site: last two labels (three for co.uk-style)."""
    labels = (name or "").lower().rstrip(".").split(".")
    n = 3 if len(labels) > 2 and len(labels[-1]) == 2 and labels[-2] in ("co", "com", "org", "net", "ac", "gov") else 2
    return ".".join(labels[-n:])


class DnsCache:
    """Reverse DNS (PTR) with a 24 h on-disk cache. Uses the system resolver only."""

    def __init__(self, path=None):
        self.path = path or sec_path("dns.json")
        self.cache = load_json(self.path, {})
        self.dirty = False

    def lookup_many(self, ips, budget=3.0):
        now = time.time()
        todo = [ip for ip in set(ips) if ip and (ip not in self.cache or now - self.cache[ip][1] > DNS_TTL)]
        if todo:
            # daemon threads: a PTR lookup that hangs must never keep macguard from exiting
            found = {}

            def ptr(ip):
                try:
                    found[ip] = socket.gethostbyaddr(ip.split("%")[0])[0]
                except (OSError, UnicodeError):
                    found[ip] = ""
            threads = [threading.Thread(target=ptr, args=(ip,), daemon=True) for ip in todo[:200]]
            for i in range(0, len(threads), 16):
                for t in threads[i:i + 16]:
                    t.start()
            end = time.time() + budget
            for t in threads:
                t.join(max(0.0, end - time.time()))
            for ip, name in list(found.items()):
                self.cache[ip] = [name, now]
                self.dirty = True
        return {ip: (self.cache.get(ip) or ["", 0])[0] for ip in ips}

    def save(self):
        if self.dirty:
            save_json(self.path, self.cache)
            self.dirty = False


def live_connections(procs=None, conns=None):
    """Outbound connections to the internet, per process, with parent and bytes (netstat -anv, no root)."""
    procs = procs if procs is not None else proc_snapshot()
    conns = conns if conns is not None else mg.sockets()
    out = []
    for c in conns:
        if c["state"] in ("LISTEN",) or not c["rhost"] or c["rhost"] in ("*",) or mg.is_private(c["rhost"]):
            continue
        if c["proto"].startswith("udp") and not c["rport"]:
            continue
        p = procs.get(c["pid"] or -1, {})
        parent = procs.get(p.get("ppid", -1), {})
        out.append(dict(pid=c["pid"], proc=p.get("name") or c["proc"], exe=p.get("exe", ""), ppid=p.get("ppid"),
                        parent=parent.get("name", ""), proto=c["proto"], rhost=c["rhost"], rport=c["rport"],
                        state=c["state"], rx=c["rx"], tx=c["tx"]))
    return out


def ollama_alerts(conns_all, procs, names):
    """Ollama must only listen on loopback and only talk to its model registries."""
    alerts = []
    ollama = {pid for pid, p in procs.items() if "ollama" in p["name"].lower()}
    if not ollama:
        return alerts
    for c in conns_all:
        if c["pid"] not in ollama:
            continue
        if c["state"] == "LISTEN" and c["lhost"] not in ("127.0.0.1", "::1", "localhost"):
            alerts.append(alert("network", "critical", f"Ollama listens on {c['lhost']}:{c['lport']}",
                                "Anyone on your network can use your models and read prompts. Set OLLAMA_HOST=127.0.0.1 "
                                "and restart Ollama.", key=f"ollama-listen|{c['lhost']}|{c['lport']}"))
        elif c["state"] != "LISTEN" and c["rhost"] and not mg.is_private(c["rhost"]):
            name = names.get(c["rhost"], "")
            if not domain_matches(name, OLLAMA_OK):
                alerts.append(alert("network", "warning", "Ollama connected to an unexpected destination",
                                    f"{name or c['rhost']}:{c['rport']} (expected only ollama.com / Hugging Face model "
                                    "downloads)", key=f"ollama-out|{c['rhost']}"))
    return alerts


def connection_alerts(conn, name, totals=None):
    """Alerts for one live connection: raw IP, exfil domains, odd ports, heavy upload."""
    alerts, dest = [], name or conn["rhost"]
    who = f"{conn['proc']} ({conn['pid']})" + (f" under {conn['parent']}" if conn.get("parent") else "")
    key = f"{conn['proc']}|{conn['rhost']}|{conn['rport']}"
    hit = domain_matches(name, EXFIL_DOMAINS)
    if hit:
        alerts.append(alert("network", "critical" if conn["tx"] > 1 << 20 else "warning",
                            f"{conn['proc']} talks to {EXFIL_DOMAINS[hit]}", f"{who} -> {dest}:{conn['rport']}. "
                            "These services are common exfiltration and command channels.", key="exfil|" + key))
    if not name:
        alerts.append(alert("network", "info", f"{conn['proc']} connects to an IP with no DNS name",
                            f"{who} -> {conn['rhost']}:{conn['rport']}", key="rawip|" + key))
    port = conn["rport"] or 0
    if port in mg.SUSPICIOUS_PORTS:
        alerts.append(alert("network", "critical", f"{conn['proc']} uses port {port} ({mg.SUSPICIOUS_PORTS[port]})",
                            f"{who} -> {dest}:{port}", key="badport|" + key))
    elif port and port not in mg.COMMON_PORTS and port < 49152 and port not in (8080, 8000, 11434, 5000, 3000):
        alerts.append(alert("network", "info", f"{conn['proc']} uses uncommon port {port}", f"{who} -> {dest}:{port}",
                            key="port|" + key))
    sent = (totals or {}).get(key, conn["tx"])
    if sent >= HIGH_UPLOAD:
        alerts.append(alert("network", "warning", f"{conn['proc']} uploaded {mg.human(sent)}", f"{who} -> {dest}:{port}",
                            key="upload|" + key))
    return alerts


class Baselines:
    """Per-project learned destinations (sites). A project's first session only learns; later new sites alert."""

    def __init__(self, path=None):
        self.path = path or sec_path("baselines.json")
        self.data = load_json(self.path, {})
        self.dirty = False

    def check(self, project, dest, learning=False):
        """True if dest is new for this (already learned) project."""
        if not project or not dest:
            return False
        site = dest if re.match(r"^[\d.:a-fA-F]+$", dest) else site_of(dest)
        if domain_matches(site, KNOWN_GOOD):
            return False
        entry = self.data.setdefault(project, {"learned": False, "sites": {}})
        if site in entry["sites"]:
            entry["sites"][site]["last"] = now_iso()
            return False
        entry["sites"][site] = {"first": now_iso(), "last": now_iso()}
        self.dirty = True
        return entry["learned"] and not learning

    def finish_learning(self, projects):
        for p in projects:
            if p in self.data and not self.data[p]["learned"]:
                self.data[p]["learned"] = True
                self.dirty = True

    def save(self):
        if self.dirty:
            save_json(self.path, self.data)
            self.dirty = False


def process_cwds(pids):
    """pid -> current directory (lsof, own processes only, no root)."""
    pids = sorted({p for p in pids if p})
    if not pids:
        return {}
    _, out, _ = mg.run(["lsof", "-a", "-d", "cwd", "-p", ",".join(map(str, pids[:300])), "-Fpn"], timeout=15)
    cwds, pid = {}, None
    for line in out.splitlines():
        if line.startswith("p"):
            pid = int(line[1:]) if line[1:].isdigit() else None
        elif line.startswith("n") and pid:
            cwds[pid] = line[1:]
    return cwds


def project_of(path, roots=None):
    """The project folder a path is in: the nearest folder with .git or package.json, under the dev roots."""
    if not path or not path.startswith(mg.HOME):
        return None
    d = path
    while d.startswith(mg.HOME) and d != mg.HOME:
        if any(os.path.exists(os.path.join(d, m)) for m in (".git", "package.json", "pyproject.toml")):
            return d
        d = os.path.dirname(d)
    return None


class NetworkWatcher:
    def __init__(self, learning_projects=()):
        self.dns = DnsCache()
        self.baselines = Baselines()
        self.first_seen = {}      # key -> iso time
        self.totals = {}          # key -> max bytes sent seen
        self.reported = set()
        self.projects = set()
        self.learning = set(learning_projects)

    def poll(self, procs=None, conns_all=None, cwds=None):
        procs = procs if procs is not None else proc_snapshot()
        conns_all = conns_all if conns_all is not None else mg.sockets()
        conns = live_connections(procs, conns_all)
        names = self.dns.lookup_many([c["rhost"] for c in conns] + [c["rhost"] for c in conns_all
                                                                     if c["pid"] and "ollama" in (c["proc"] or "").lower()])
        roots = {pid for pid, p in procs.items() if is_watched_root(p)}
        watched = {c["pid"] for c in conns if c["pid"] in roots or self._under(procs, c["pid"], roots)}
        cwds = cwds if cwds is not None else process_cwds(watched)
        alerts = []
        for c in conns:
            key = f"{c['proc']}|{c['rhost']}|{c['rport']}"
            c["name"] = names.get(c["rhost"], "")
            c["first_seen"] = self.first_seen.setdefault(key, now_iso())
            self.totals[key] = max(self.totals.get(key, 0), c["tx"])
            project = project_of(cwds.get(c["pid"], "")) if c["pid"] in watched else None
            c["project"] = home_short(project) if project else ""
            found = connection_alerts(c, c["name"], self.totals)
            if project:
                self.projects.add(project)
                if self.baselines.check(project, c["name"] or c["rhost"], learning=project in self.learning
                                        or project not in self.baselines.data):
                    found.append(alert("network", "warning", f"New destination for {os.path.basename(project)}",
                                       f"{c['proc']} ({c['pid']}) -> {c['name'] or c['rhost']}:{c['rport']}; never seen "
                                       "in this project before", key=f"new|{project}|{c['name'] or c['rhost']}"))
            for a in found:
                a.setdefault("pid", c["pid"])
                if alert_key(a) not in self.reported:
                    self.reported.add(alert_key(a))
                    alerts.append(a)
        for a in ollama_alerts(conns_all, procs, names):
            if alert_key(a) not in self.reported:
                self.reported.add(alert_key(a))
                alerts.append(a)
        return conns, alerts

    @staticmethod
    def _under(procs, pid, roots):
        seen = set()
        while pid and pid not in seen and pid > 1:
            seen.add(pid)
            if pid in roots:
                return True
            pid = procs.get(pid, {}).get("ppid")
        return False

    def save(self):
        self.dns.save()
        self.baselines.save()


# ---------------------------------------------------------------- persistence

SECRET_LINE = re.compile(r"((?:_authToken|_auth|_password|password|passwd|token|secret|api[_-]?key|access[_-]?key)"
                         r"[A-Za-z0-9_]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)", re.I)
TEXT_MAX = 256 << 10


def redact(text):
    """Hide token/password values before anything is stored or shown (keeps the key name, hides the value)."""
    return SECRET_LINE.sub(lambda m: m.group(1) + "***", text)


def persistence_sources(projects=()):
    """(group, severity on change, path or glob) to snapshot."""
    h = mg.HOME
    src = [("launch agents (yours)", "critical", f"{h}/Library/LaunchAgents/*"),
           ("launch agents (all users)", "critical", "/Library/LaunchAgents/*"),
           ("launch daemons", "critical", "/Library/LaunchDaemons/*")]
    for f in (".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bashrc", ".bash_profile", ".profile", ".config/fish/config.fish"):
        src.append(("shell config", "warning", f"{h}/{f}"))
    src += [("/etc/hosts", "warning", "/etc/hosts"), ("git config", "warning", f"{h}/.gitconfig"),
            ("git config", "warning", f"{h}/.config/git/config"), ("npm config", "warning", f"{h}/.npmrc"),
            ("ssh config", "warning", f"{h}/.ssh/config"), ("ssh authorized keys", "critical", f"{h}/.ssh/authorized_keys")]
    _, hooks, _ = mg.run(["git", "config", "--global", "core.hooksPath"], timeout=5)
    if hooks.strip():
        src.append(("git hooks (global)", "warning", os.path.expanduser(hooks.strip()) + "/*"))
    for p in projects:
        src.append(("git hooks", "warning", os.path.join(p, ".git/hooks/*")))
        src.append(("npm config", "warning", os.path.join(p, ".npmrc")))
    return src


def file_entry(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    if not os.path.isfile(path) or path.endswith(".sample"):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(TEXT_MAX + 1)
    except OSError:
        return {"hash": "unreadable", "size": st.st_size, "mtime": st.st_mtime, "text": None}
    text = None
    if path.endswith(".plist") and raw.startswith(b"bplist"):
        try:
            text = json.dumps(plistlib.loads(raw), indent=1, default=str, sort_keys=True)
        except Exception:
            text = None
    elif b"\0" not in raw[:4096] and len(raw) <= TEXT_MAX:
        text = raw.decode("utf-8", "replace")
    return {"hash": hashlib.sha256(raw).hexdigest(), "size": st.st_size, "mtime": st.st_mtime,
            "text": redact(text) if text is not None else None, "exec": bool(st.st_mode & 0o111)}


def login_items():
    """Login items via System Events (macOS may ask once to allow it). Empty when not allowed."""
    rc, out, _ = mg.run(["osascript", "-e", 'tell application "System Events" to get the path of every login item'],
                        timeout=8)
    return sorted(x.strip() for x in out.split(",") if x.strip()) if rc == 0 else None


def persistence_snapshot(projects=(), with_login_items=True):
    files = {}
    for group, sev, pattern in persistence_sources(projects):
        paths = glob.glob(pattern) if "*" in pattern else [pattern]
        for p in paths:
            e = file_entry(p)
            if e:
                files[p] = {**e, "group": group, "sev": sev}
    _, cron, _ = mg.run(["crontab", "-l"], timeout=5)
    snap = {"time": now_iso(), "files": files, "crontab": redact(cron), "projects": list(projects)}
    if with_login_items:
        snap["login_items"] = login_items()
    return snap


def unified(a, b, path):
    return "".join(difflib.unified_diff((a or "").splitlines(True), (b or "").splitlines(True),
                                        f"{home_short(path)} (before)", f"{home_short(path)} (now)", n=2))[:6000]


def persistence_diff(before, after):
    """Added / modified / removed entries, each as an alert with the path and a diff."""
    alerts = []
    bf, af = before.get("files", {}), after.get("files", {})
    for path in sorted(set(bf) | set(af)):
        b, a = bf.get(path), af.get(path)
        if b and a and b["hash"] == a["hash"]:
            continue
        e = a or b
        what = "added" if not b else "removed" if not a else "modified"
        sev = e["sev"] if what != "removed" else "info"
        diff = unified(b and b.get("text"), a and a.get("text"), path) if (b or {}).get("text") is not None \
            or (a or {}).get("text") is not None else ""
        alerts.append(alert("persistence", sev, f"{e['group'].capitalize()} {what}: {home_short(path)}", diff[:300],
                            key=f"{what}|{path}", path=path, change=what, diff=diff))
    if (before.get("crontab") or "") != (after.get("crontab") or ""):
        alerts.append(alert("persistence", "critical", "crontab changed", "", key="crontab", path="crontab -l",
                            change="modified", diff=unified(before.get("crontab"), after.get("crontab"), "crontab")))
    bl, al = before.get("login_items"), after.get("login_items")
    if bl is not None and al is not None:
        for item in sorted(set(al) - set(bl)):
            alerts.append(alert("persistence", "warning", f"Login item added: {home_short(item)}", "", key=f"login|{item}",
                                path=item, change="added", diff=""))
        for item in sorted(set(bl) - set(al)):
            alerts.append(alert("persistence", "info", f"Login item removed: {home_short(item)}", "", key=f"login-|{item}",
                                path=item, change="removed", diff=""))
    return alerts


def persist_baseline_path():
    return sec_path("persistence.json")


# ---------------------------------------------------------------- sensitive files (FSEvents)

def sensitive_places(projects=()):
    """(path, severity, label, filename filter or None)."""
    h = mg.HOME
    app = f"{h}/Library/Application Support"
    places = [(f"{h}/.ssh", "warning", "SSH keys", None), (f"{h}/.aws", "warning", "AWS credentials", None),
              (f"{h}/.config", "info", "~/.config", None), (f"{h}/.kube", "warning", "Kubernetes config", None),
              (f"{h}/.docker", "info", "Docker config", ["config.json"]), (f"{h}/.gnupg", "warning", "GPG keys", None),
              (f"{h}/.netrc", "warning", ".netrc", None), (f"{h}/Library/Keychains", "info", "keychains", None)]
    browser_files = ["Login Data", "Cookies", "Web Data", "Local State", "logins.json", "key4.db", "cookies.sqlite"]
    for b in ("Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Arc/User Data", "Firefox/Profiles",
              "Vivaldi", "com.operasoftware.Opera"):
        places.append((f"{app}/{b}", "info", f"browser profile ({b.split('/')[0]})", browser_files))
    for p in projects:
        places.append((p, "warning", f".env in {os.path.basename(p)}", [".env", ".env.*"]))
    return [(p, s, l, f) for p, s, l, f in places if os.path.exists(p)]


CRITICAL_FILES = ("authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "credentials")
FSEVENT_FLAGS = {0x100: "created", 0x200: "removed", 0x800: "renamed", 0x1000: "modified", 0x400: "attributes changed",
                 0x2000: "owner changed", 0x8000: "xattr changed"}


def describe_flags(flags):
    return ", ".join(v for k, v in FSEVENT_FLAGS.items() if flags & k) or "changed"


def file_event_alert(path, flags, places):
    """Turn one FSEvents path into an alert, or None when it is outside the filters."""
    if flags & 0x20000:  # kFSEventStreamEventFlagItemIsDir: the files inside carry the news
        return None
    for root, sev, label, filt in places:
        if path != root and not path.startswith(root.rstrip("/") + "/"):
            continue
        base = os.path.basename(path)
        if filt and not any(fnmatch.fnmatch(base, f) for f in filt):
            return None
        if "/node_modules/" in path or "/.git/" in path:
            return None
        if base in CRITICAL_FILES or (label == "SSH keys" and flags & 0x100):
            sev = "critical"
        if label == "~/.config" and re.search(r"/(gh/hosts\.yml|gcloud/|op/|configstore/)", path):
            sev = "warning"
        return alert("file", sev, f"{label}: {base} {describe_flags(flags)}", home_short(path), key=f"{path}|{flags}",
                     path=path)
    return None


class FSWatcher:
    """FSEvents through CoreServices (ctypes). Falls back to polling mtimes when FSEvents can't start."""

    def __init__(self, places, latency=1.0):
        self.places = places
        self.latency = latency
        self.queue, self.lock = [], threading.Lock()
        self.mode, self.stream, self._cb = None, None, None
        self.snap = {}

    def start(self):
        try:
            self._start_fsevents()
            self.mode = "fsevents"
        except Exception as e:  # pragma: no cover - depends on the OS
            self.mode = "polling"
            self.error = str(e)
            self.snap = self._scan()
        return self.mode

    def _start_fsevents(self):
        cs = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreServices"))
        cf = ctypes.cdll.LoadLibrary(ctypes.util.find_library("CoreFoundation"))
        libsys = ctypes.cdll.LoadLibrary("/usr/lib/libSystem.B.dylib")
        cf.CFStringCreateWithCString.restype = ctypes.c_void_p
        cf.CFStringCreateWithCString.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_uint32]
        cf.CFArrayCreate.restype = ctypes.c_void_p
        cf.CFArrayCreate.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p), ctypes.c_long, ctypes.c_void_p]
        CB = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_char_p),
                              ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint64))

        def callback(stream, info, n, paths, flags, ids):
            with self.lock:
                for i in range(n):
                    self.queue.append((paths[i].decode("utf-8", "replace"), flags[i]))
        self._cb = CB(callback)
        roots = sorted({p if os.path.isdir(p) else os.path.dirname(p) for p, _, _, _ in self.places})
        strs = (ctypes.c_void_p * len(roots))(*[cf.CFStringCreateWithCString(None, r.encode(), 0x08000100) for r in roots])
        arr = cf.CFArrayCreate(None, strs, len(roots), None)
        cs.FSEventStreamCreate.restype = ctypes.c_void_p
        cs.FSEventStreamCreate.argtypes = [ctypes.c_void_p, CB, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64,
                                           ctypes.c_double, ctypes.c_uint32]
        # kFSEventStreamEventIdSinceNow, flags: FileEvents (0x10) | NoDefer (0x02)
        self.stream = cs.FSEventStreamCreate(None, self._cb, None, arr, 0xFFFFFFFFFFFFFFFF, self.latency, 0x12)
        if not self.stream:
            raise OSError("FSEventStreamCreate failed")
        libsys.dispatch_queue_create.restype = ctypes.c_void_p
        libsys.dispatch_queue_create.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
        q = libsys.dispatch_queue_create(b"macguard.fsevents", None)
        cs.FSEventStreamSetDispatchQueue.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        cs.FSEventStreamSetDispatchQueue(self.stream, q)
        cs.FSEventStreamStart.argtypes = [ctypes.c_void_p]
        cs.FSEventStreamStart.restype = ctypes.c_bool
        if not cs.FSEventStreamStart(self.stream):
            raise OSError("FSEventStreamStart failed")
        self._cs = cs

    def stop(self):
        if self.stream and self.mode == "fsevents":
            for fn in ("FSEventStreamStop", "FSEventStreamInvalidate", "FSEventStreamRelease"):
                getattr(self._cs, fn).argtypes = [ctypes.c_void_p]
                getattr(self._cs, fn)(self.stream)
            self.stream = None

    def _scan(self, max_files=20000):
        snap = {}
        for root, _, _, filt in self.places:
            if os.path.isfile(root):
                try:
                    snap[root] = os.stat(root).st_mtime
                except OSError:
                    pass
                continue
            for d, dirs, files in os.walk(root):
                dirs[:] = [x for x in dirs if x not in ("node_modules", ".git", "Cache", "Code Cache", "GPUCache")]
                for f in files:
                    if filt and not any(fnmatch.fnmatch(f, x) for x in filt):
                        continue
                    p = os.path.join(d, f)
                    try:
                        snap[p] = os.stat(p).st_mtime
                    except OSError:
                        pass
                    if len(snap) >= max_files:
                        return snap
        return snap

    def poll(self):
        if self.mode == "polling":
            new = self._scan()
            events = [(p, 0x100) for p in new if p not in self.snap] + [(p, 0x200) for p in self.snap if p not in new] + \
                [(p, 0x1000) for p in new if p in self.snap and new[p] != self.snap[p]]
            self.snap = new
        else:
            with self.lock:
                events, self.queue = self.queue, []
        out, seen = [], set()
        for path, flags in events:
            a = file_event_alert(path, flags, self.places)
            if a and (path, a["title"]) not in seen:
                seen.add((path, a["title"]))
                out.append(a)
        return out


# ---------------------------------------------------------------- LuLu

LULU_RULES = "/Library/Objective-See/LuLu/rules.plist"
COCOA_EPOCH = 978307200
INTERPRETERS = {"node", "python", "python3", "ruby", "perl", "bash", "sh", "zsh", "curl", "wget", "nc", "ncat",
                "osascript", "deno", "bun", "java", "php", "pwsh", "socat", "ssh"}
LULU_OLD_DAYS = 180


def unarchive(data):
    """Decode an NSKeyedArchiver plist into plain dicts/lists (enough for LuLu's rules)."""
    objs = data["$objects"]

    def res(x, depth=0):
        if isinstance(x, plistlib.UID):
            x = objs[x.data]
        if depth > 12:
            return None
        if x == "$null":
            return None
        if isinstance(x, dict):
            if "NS.keys" in x:
                return {str(res(k, depth + 1)): res(v, depth + 1) for k, v in zip(x["NS.keys"], x["NS.objects"])}
            if "NS.objects" in x:
                return [res(v, depth + 1) for v in x["NS.objects"]]
            if "NS.time" in x:
                return COCOA_EPOCH + x["NS.time"]
            if "NS.string" in x:
                return x["NS.string"]
            return {k: res(v, depth + 1) for k, v in x.items() if k != "$class"}
        return x
    return res(data["$top"].get("root") or next(iter(data["$top"].values())))


def lulu_rules(path=LULU_RULES):
    """(rules, error). Each rule: uuid, name, path, action (allow|block), addr, port, created, expires, signer, type."""
    if not os.path.exists(path):
        return None, "LuLu isn't installed (no rules file at " + path + ")."
    try:
        with open(path, "rb") as fh:
            top = unarchive(plistlib.load(fh))
    except PermissionError:
        return None, ("macOS doesn't let this user read LuLu's rules. Open LuLu > Rules to review them, or run "
                      f"`sudo plutil -p {path}` yourself.")
    except Exception as e:
        return None, f"Couldn't read LuLu's rules ({type(e).__name__}); this LuLu version may store them differently."
    rules = []
    for key, entry in (top or {}).items():
        for r in (entry or {}).get("rules") or []:
            cs = r.get("csInfo") or {}
            rules.append(dict(uuid=r.get("uuid"), key=key, name=r.get("name") or os.path.basename(r.get("path") or key),
                              path=r.get("path") or "", action="allow" if r.get("action") == 1 else "block",
                              addr=str(r.get("endpointAddr") or r.get("endpointHost") or "*"),
                              port=str(r.get("endpointPort") or "*"), created=r.get("creation"),
                              expires=r.get("expiration"), disabled=bool(r.get("isDisabled")), type=r.get("type"),
                              signed=cs.get("signatureStatus") == 0 and bool(cs), signer=cs.get("signatureSigner"),
                              apple=cs.get("signatureSigner") == 1))
    return rules, None


def lulu_tags_path():
    return sec_path("lulu_tags.json")


def lulu_audit(rules, tags=None, now=None):
    now = now or time.time()
    tags = tags if tags is not None else load_json(lulu_tags_path(), {})
    alerts, out = [], []
    for r in rules:
        if r["action"] != "allow" or r["disabled"]:
            continue
        flags = []
        name = r["name"].lower()
        broad = r["addr"] == "*" and r["port"] == "*"
        base = re.sub(r"\d+(\.\d+)*$", "", os.path.basename(r["path"]).lower())
        if broad and (name in INTERPRETERS or base in INTERPRETERS):
            flags.append(("warning", "lets an interpreter connect anywhere: any script it runs gets the same access"))
        elif broad and not r["apple"]:
            flags.append(("info", "any address, any port"))
        if not r["signed"] and not r["apple"]:
            flags.append(("warning", "unsigned program"))
        if r["path"].startswith(DROP_DIRS) or "/Downloads/" in r["path"]:
            flags.append(("critical", "program lives in a temp or Downloads folder"))
        if r["path"] and not r["path"].startswith("/System/") and not os.path.exists(r["path"]):
            flags.append(("info", "program no longer exists: stale rule"))
        if r["created"] and now - r["created"] > LULU_OLD_DAYS * 86400 and not r["apple"]:
            flags.append(("info", f"over {LULU_OLD_DAYS} days old"))
        tag = tags.get(r["uuid"] or "")
        if tag:
            if now >= tag["until"]:
                flags.append(("warning", f"your {tag.get('label', 'temporary')} permission expired "
                                         f"{now_iso(tag['until'])}: revoke it in LuLu"))
            else:
                flags.append(("info", f"temporary until {now_iso(tag['until'])}"))
        row = {**r, "created_iso": now_iso(r["created"]) if r["created"] else "", "flags": [f[1] for f in flags],
               "severity": max((f[0] for f in flags), key=SEV_RANK.get, default="info"), "tag": tag}
        out.append(row)
        for sev, why in flags:
            if sev != "info" or "temporary" in why:
                alerts.append(alert("lulu", sev, f"LuLu allows {r['name']}: {why}",
                                    f"{home_short(r['path'])} -> {r['addr']}:{r['port']}", key=f"{r['uuid']}|{why[:20]}",
                                    uuid=r["uuid"]))
    out.sort(key=lambda r: (-SEV_RANK[r["severity"]], r["apple"], r["name"].lower()))
    return out, alerts


def lulu_tag(uuid, hours, label="temporary"):
    tags = load_json(lulu_tags_path(), {})
    if hours <= 0:
        tags.pop(uuid, None)
    else:
        tags[uuid] = {"until": time.time() + hours * 3600, "label": label, "tagged": now_iso()}
    save_json(lulu_tags_path(), tags)
    return tags.get(uuid)


def lulu_expired(tags=None, now=None):
    now = now or time.time()
    tags = tags if tags is not None else load_json(lulu_tags_path(), {})
    return [u for u, t in tags.items() if now >= t["until"] and not t.get("notified")]


# ---------------------------------------------------------------- npm packages

INSTALL_SCRIPTS = ("preinstall", "install", "postinstall")  # "prepare" never runs for registry packages


def lock_packages(lock):
    """[(name, version, has_install_script, path)] from package-lock v1, v2 or v3."""
    pkgs = []
    if "packages" in lock:
        for path, info in lock["packages"].items():
            if not path or info.get("link"):
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[-1]
            if info.get("version"):
                pkgs.append((name, info["version"], bool(info.get("hasInstallScript")), path))
    else:
        def walk_deps(deps, prefix=""):
            for name, info in (deps or {}).items():
                path = f"{prefix}node_modules/{name}"
                if info.get("version") and not str(info["version"]).startswith(("file:", "link:")):
                    pkgs.append((name, info["version"], False, path))
                walk_deps(info.get("dependencies"), path + "/")
        walk_deps(lock.get("dependencies"))
    return pkgs


def installed_scripts(project, path):
    try:
        with open(os.path.join(project, path, "package.json")) as fh:
            scripts = json.load(fh).get("scripts") or {}
    except (OSError, ValueError):
        return {}
    return {k: v for k, v in scripts.items() if k in INSTALL_SCRIPTS}


def osv_query(pkgs, timeout=20, opener=None):
    """{(name, version): [vuln ids]} from OSV.dev. Sends only package names and versions."""
    opener = opener or urllib.request.urlopen
    found, uniq = {}, sorted({(n, v) for n, v, _, _ in pkgs})
    for i in range(0, len(uniq), 500):
        chunk = uniq[i:i + 500]
        body = json.dumps({"queries": [{"package": {"name": n, "ecosystem": "npm"}, "version": v} for n, v in chunk]})
        req = urllib.request.Request(OSV_URL, body.encode(), {"Content-Type": "application/json",
                                                              "User-Agent": "mac-cleanup"})
        with opener(req, timeout=timeout) as r:
            res = json.loads(r.read())
        for (n, v), item in zip(chunk, res.get("results", [])):
            ids = [x["id"] for x in item.get("vulns") or []]
            if ids:
                found[(n, v)] = ids
    return found


def osv_details(ids, timeout=10, opener=None, limit=40):
    opener = opener or urllib.request.urlopen
    out = {}
    for vid in list(ids)[:limit]:
        try:
            with opener(urllib.request.Request(OSV_VULN_URL + urllib.request.quote(vid),
                                               headers={"User-Agent": "mac-cleanup"}), timeout=timeout) as r:
                v = json.loads(r.read())
        except Exception:
            continue
        sev = (v.get("database_specific") or {}).get("severity") or ""
        out[vid] = {"summary": v.get("summary") or (v.get("details") or "")[:160], "severity": sev.lower(),
                    "aliases": v.get("aliases") or []}
    return out


def scan_deps(project, online=False, opener=None):
    """Install scripts and (online) known vulnerabilities for a project's package-lock.json."""
    project = os.path.abspath(os.path.expanduser(project))
    lock_path = os.path.join(project, "package-lock.json")
    if not os.path.exists(lock_path):
        raise FileNotFoundError(f"no package-lock.json in {home_short(project)} (run npm install --package-lock-only "
                                "--ignore-scripts to make one)")
    with open(lock_path) as fh:
        lock = json.load(fh)
    pkgs = lock_packages(lock)
    scripts = []
    for name, ver, flagged, path in pkgs:
        found = installed_scripts(project, path)
        if flagged or found:
            scripts.append({"name": name, "version": ver, "scripts": found or {"(lockfile)": "hasInstallScript"}})
    alerts = [alert("deps", "warning", f"{s['name']}@{s['version']} runs an install script",
                    "; ".join(f"{k}: {v}" for k, v in s["scripts"].items())[:300], key=f"script|{s['name']}@{s['version']}")
              for s in scripts]
    vulns, error = [], None
    if online:
        try:
            hits = osv_query(pkgs, opener=opener)
            details = osv_details({i for ids in hits.values() for i in ids}, opener=opener)
            for (n, v), ids in sorted(hits.items()):
                sev = max((details.get(i, {}).get("severity") or "moderate" for i in ids),
                          key=lambda s: ["low", "moderate", "medium", "high", "critical"].index(s)
                          if s in ("low", "moderate", "medium", "high", "critical") else 1)
                vulns.append({"name": n, "version": v, "ids": ids, "severity": sev,
                              "summary": [details.get(i, {}).get("summary", "") for i in ids][:3]})
                alerts.append(alert("deps", "critical" if sev in ("high", "critical") else "warning",
                                    f"{n}@{v} has known vulnerabilities ({sev})", ", ".join(ids[:5]), key=f"vuln|{n}@{v}"))
        except Exception as e:
            error = f"OSV lookup failed: {type(e).__name__}: {e}"
    return {"project": home_short(project), "lockfile_version": lock.get("lockfileVersion", 1), "packages": len(pkgs),
            "install_scripts": scripts, "vulnerabilities": vulns, "online": online, "error": error, "alerts": alerts,
            "advice": ["Install with `npm install --ignore-scripts`, then run only the scripts you trust "
                       "(`npm rebuild <pkg>`).", "Run `npm audit` for npm's own advisory check.",
                       "Set `ignore-scripts=true` in the project's .npmrc to make it the default."]}


# ---------------------------------------------------------------- dev session

def session_file():
    return sec_path("session.json")


def sessions_dir(sid=None):
    return sec_path("sessions", sid) if sid else sec_path("sessions")


def current_session():
    s = load_json(session_file(), None)
    if s and s.get("monitor_pid") and not pid_alive(s["monitor_pid"], "session"):
        s["monitor_running"] = False
    elif s:
        s["monitor_running"] = bool(s.get("monitor_pid"))
    return s


def pid_alive(pid, marker=None):
    try:
        os.kill(pid, 0)
    except (OSError, TypeError):
        return False
    if marker:
        _, out, _ = mg.run(["ps", "-o", "args=", "-p", str(pid)], timeout=5)
        return marker in out
    return True


def settings():
    s = mg.load_settings()
    return {"interval": max(1, min(60, int(s.get("session_interval", DEFAULT_INTERVAL)))),
            "osv": bool(s.get("osv_lookups", False))}


def start_session(projects=(), background=True, label=""):
    """Snapshot persistence, then run the monitors in a detached process until stop_session()."""
    cur = current_session()
    if cur and cur.get("monitor_running"):
        raise RuntimeError(f"session {cur['id']} is already running (started {cur['started']})")
    sid = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    d = ensure_dir(sessions_dir(sid))
    projects = sorted({os.path.abspath(os.path.expanduser(p)) for p in projects})
    save_json(os.path.join(d, "persist-start.json"), persistence_snapshot(projects))
    sess = {"id": sid, "label": label, "started": now_iso(), "projects": projects, "interval": settings()["interval"],
            "lulu_at_start": [r["uuid"] for r in (lulu_rules()[0] or []) if r["action"] == "allow"]}
    save_json(session_file(), sess)
    if background:
        log = open(os.path.join(d, "monitor.log"), "a")
        p = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "macguard.py"),
                              "session", "run", "--id", sid], stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                             start_new_session=True, env={**os.environ, "MACGUARD_REEXEC": "1"})
        sess["monitor_pid"] = p.pid
        save_json(session_file(), sess)
    mg.log_event("session", f"dev session {sid} started")
    return sess


def run_monitor(sid, max_seconds=None, interval=None):
    """The session's poll loop (runs detached). Stops on SIGTERM or when the session file changes."""
    d = sessions_dir(sid)
    sess = load_json(session_file(), {})
    interval = interval or sess.get("interval") or DEFAULT_INTERVAL
    projects = set(sess.get("projects") or [])
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *a: stop.update(now=True))
    net, procw = NetworkWatcher(learning_projects=()), ProcessWatcher()
    fsw = FSWatcher(sensitive_places(projects))
    mode = fsw.start()
    events_path = os.path.join(d, "events.jsonl")
    write_events(events_path, [alert("session", "info", f"monitor started (files: {mode})", key="start")])
    start, last_fs_rebuild = time.time(), time.time()
    seen_conns = load_json(os.path.join(d, "connections.json"), {})
    while not stop["now"]:
        try:
            procs = proc_snapshot()
            conns_all = mg.sockets()
            conns, a1 = net.poll(procs, conns_all)
            _, a2 = procw.poll(procs)
            a3 = fsw.poll()
            for c in conns:
                k = f"{c['proc']}|{c['name'] or c['rhost']}|{c['rport']}"
                prev = seen_conns.get(k)
                seen_conns[k] = {"proc": c["proc"], "dest": c["name"] or c["rhost"], "ip": c["rhost"], "port": c["rport"],
                                 "project": c["project"], "first": prev["first"] if prev else c["first_seen"],
                                 "last": now_iso(), "tx": max(c["tx"], (prev or {}).get("tx", 0)),
                                 "rx": max(c["rx"], (prev or {}).get("rx", 0))}
            new_projects = net.projects - projects
            if new_projects and time.time() - last_fs_rebuild > 30:
                projects |= new_projects
                fsw.places = sensitive_places(projects)  # watch .env files of projects that showed up
                last_fs_rebuild = time.time()
            alerts = a1 + a2 + a3
            if alerts:
                write_events(events_path, alerts)
                log_alerts(alerts)
                crit = [a for a in alerts if a["severity"] == "critical"]
                if crit:
                    mg.notify("Dev session: " + crit[0]["title"][:60], crit[0]["detail"][:150])
            save_json(os.path.join(d, "connections.json"), seen_conns)
            save_json(os.path.join(d, "projects.json"), sorted(projects | net.projects))
            net.save()
        except Exception as e:  # keep monitoring; record what broke
            write_events(events_path, [alert("session", "info", f"poll error: {type(e).__name__}: {e}", key="err")])
        if max_seconds and time.time() - start >= max_seconds:
            break
        cur = load_json(session_file(), {})
        if cur.get("id") != sid:
            break
        for _ in range(int(interval * 10)):
            if stop["now"]:
                break
            time.sleep(0.1)
    fsw.stop()
    procs = proc_snapshot()
    save_json(os.path.join(d, "orphans.json"), procw.orphans(procs))
    write_events(events_path, [alert("session", "info", "monitor stopped", key="stop")])


def write_events(path, alerts):
    ensure_dir(os.path.dirname(path))
    with open(path, "a") as fh:
        for a in alerts:
            fh.write(json.dumps(a, default=str) + "\n")


def read_events(sid):
    try:
        with open(os.path.join(sessions_dir(sid), "events.jsonl")) as fh:
            return [json.loads(l) for l in fh if l.strip()]
    except (OSError, ValueError):
        return []


def stop_session(online=None):
    """Stop the monitor, diff persistence, scan the projects the session touched, write the report."""
    sess = load_json(session_file(), None)
    if not sess:
        raise RuntimeError("no dev session is running (start one with `macguard session start`)")
    sid, d = sess["id"], sessions_dir(sess["id"])
    pid = sess.get("monitor_pid")
    if pid and pid_alive(pid, "session"):
        os.kill(pid, signal.SIGTERM)
        for _ in range(60):
            if not pid_alive(pid):
                break
            time.sleep(0.1)
    sess["stopped"] = now_iso()
    projects = sorted(set(sess.get("projects") or []) | set(load_json(os.path.join(d, "projects.json"), [])))
    before = load_json(os.path.join(d, "persist-start.json"), {"files": {}})
    after = persistence_snapshot(projects)
    # projects found during the session have no start snapshot for their hooks/.npmrc: only report what exists
    persist = persistence_diff(before, {**after, "files": {k: v for k, v in after["files"].items()
                                                           if k in before.get("files", {}) or
                                                           not any(k.startswith(p + "/") for p in projects
                                                                   if p not in before.get("projects", []))}})
    save_json(os.path.join(d, "persist-end.json"), after)
    log_alerts(persist)
    online = settings()["osv"] if online is None else online
    deps = []
    for p in projects:
        if os.path.exists(os.path.join(p, "package-lock.json")):
            try:
                deps.append(scan_deps(p, online=online))
            except Exception as e:
                deps.append({"project": home_short(p), "error": str(e), "install_scripts": [], "vulnerabilities": [],
                             "alerts": []})
    rules, lulu_err = lulu_rules()
    lulu_rows, lulu_alerts = lulu_audit(rules) if rules else ([], [])
    at_start = set(sess.get("lulu_at_start") or [])
    open_rules = [r for r in lulu_rows if r["uuid"] not in at_start or r.get("tag")]
    b = Baselines()
    b.finish_learning(projects)
    b.save()
    report = build_report(sess, read_events(sid), persist, deps, open_rules, lulu_err,
                          load_json(os.path.join(d, "connections.json"), {}), load_json(os.path.join(d, "orphans.json"), []),
                          projects)
    save_json(os.path.join(d, "report.json"), report)
    with open(os.path.join(d, "report.md"), "w") as fh:
        fh.write(report_markdown(report))
    os.remove(session_file())
    mg.log_event("session", f"dev session {sid} stopped: {report['summary']['critical']} critical, "
                            f"{report['summary']['warning']} warnings")
    return report


def build_report(sess, events, persist, deps, open_rules, lulu_err, conns, orphans, projects):
    alerts = [e for e in events if e["kind"] != "session"] + persist + [a for d in deps for a in d.get("alerts", [])]
    count = {s: sum(1 for a in alerts if a["severity"] == s) for s in SEVERITIES}
    new_dest = [a for a in alerts if a["kind"] == "network" and a["title"].startswith("New destination")]
    spawned = [a for a in alerts if a["kind"] == "process" and a["severity"] != "info"]
    shells = [a for a in alerts if a["kind"] == "process" and a["severity"] == "info"]
    return {"id": sess["id"], "label": sess.get("label", ""), "started": sess["started"], "stopped": sess.get("stopped"),
            "projects": [home_short(p) for p in projects], "summary": {**count, "alerts": len(alerts)},
            "new_destinations": new_dest, "destinations": sorted(conns.values(), key=lambda c: -c.get("tx", 0)),
            "network_alerts": [a for a in alerts if a["kind"] == "network"], "spawned": spawned,
            "shells": len(shells), "orphans": orphans, "persistence": persist,
            "files": [a for a in alerts if a["kind"] == "file"], "packages": deps,
            "lulu_open": [{k: r[k] for k in ("uuid", "name", "path", "addr", "port", "created_iso", "flags", "tag")}
                          for r in open_rules], "lulu_error": lulu_err,
            "limits": ["File watching sees changes, not reads (FSEvents). Read detection needs Phase 2 (Endpoint "
                       "Security).", "Connections are sampled every few seconds: very short ones can be missed."]}


def report_markdown(r):
    L = [f"# Dev session report {r['id']}", "", f"{r['started']} to {r.get('stopped') or 'now'}"
         + (f" · {r['label']}" if r.get("label") else ""), ""]
    s = r["summary"]
    L += [f"**{s['critical']} critical · {s['warning']} warnings · {s['info']} info**", ""]
    if r["projects"]:
        L += ["Projects: " + ", ".join(f"`{p}`" for p in r["projects"]), ""]

    def section(title, rows, fmt):
        L.extend([f"## {title}", ""])
        L.extend([fmt(x) for x in rows] or ["None."])
        L.append("")
    sev = lambda a: f"**{a['severity']}**"
    section("New destinations", r["new_destinations"], lambda a: f"- {sev(a)} {a['title']}: {a['detail']}")
    net_rest = [a for a in r["network_alerts"] if a not in r["new_destinations"]]
    section("Network alerts", [a for a in net_rest if a["severity"] != "info"],
            lambda a: f"- {sev(a)} {a['title']}: {a['detail']}")
    n_info = sum(1 for a in net_rest if a["severity"] == "info")
    if n_info:
        L.insert(len(L) - 1, f"{n_info} info note(s) (IPs without a DNS name, uncommon ports) are in report.json.")
    section("Destinations contacted", r["destinations"][:40],
            lambda c: f"- `{c['proc']}` → {c['dest']}:{c['port']} · sent {mg.human(c.get('tx', 0))} "
                      f"received {mg.human(c.get('rx', 0))}" + (f" · {c['project']}" if c.get("project") else ""))
    section("Spawned scripts and tools", r["spawned"], lambda a: f"- {sev(a)} {a['title']}: `{a['detail'][:200]}`")
    L.insert(len(L) - 1, f"Shells spawned by watched tools: {r['shells']} (normal for npm scripts and agents).")
    section("Left running", r["orphans"], lambda o: f"- `{o['name']}` ({o['pid']}) after {o['root']} exited")
    section("Persistence changes", r["persistence"],
            lambda a: f"- {sev(a)} {a['title']}" + (f"\n\n```diff\n{a['diff']}\n```" if a.get("diff") else ""))
    section("Sensitive file changes", r["files"], lambda a: f"- {sev(a)} {a['title']} (`{a['detail']}`)")
    L.extend(["## Packages", ""])
    for d in r["packages"] or []:
        L.append(f"- `{d['project']}`: {len(d.get('install_scripts', []))} with install scripts, "
                 f"{len(d.get('vulnerabilities', []))} vulnerable" + ("" if d.get("online") else " (OSV lookup off)")
                 + (f" · {d['error']}" if d.get("error") else ""))
        for v in d.get("vulnerabilities", [])[:20]:
            L.append(f"  - **{v['severity']}** {v['name']}@{v['version']}: {', '.join(v['ids'][:3])}")
    if not r["packages"]:
        L.append("No package-lock.json in this session's projects.")
    L.append("")
    section("LuLu rules still open", r["lulu_open"],
            lambda x: f"- {x['name']} → {x['addr']}:{x['port']}" + (f" · {'; '.join(x['flags'])}" if x["flags"] else ""))
    if r.get("lulu_error"):
        L += [r["lulu_error"], ""]
    L += ["## Limits", ""] + [f"- {x}" for x in r["limits"]] + [""]
    return "\n".join(L)


def list_sessions():
    d = sessions_dir()
    if not os.path.isdir(d):
        return []
    out = []
    for sid in sorted(os.listdir(d), reverse=True):
        r = load_json(os.path.join(d, sid, "report.json"), None)
        out.append({"id": sid, "finished": bool(r), "summary": (r or {}).get("summary"), "started": (r or {}).get("started")})
    return out


def load_report(sid=None):
    sid = sid or next((s["id"] for s in list_sessions() if s["finished"]), None)
    if not sid:
        return None
    return load_json(os.path.join(sessions_dir(sid), "report.json"), None)


def live_status():
    """What the UI/MCP show while a session runs: session, recent alerts, connections and the process tree now."""
    sess = current_session()
    procs = proc_snapshot()
    conns = live_connections(procs)
    names = DnsCache().lookup_many([c["rhost"] for c in conns], budget=2.0)
    for c in conns:
        c["name"] = names.get(c["rhost"], "")
        c["alerts"] = [a["title"] for a in connection_alerts(c, c["name"])]
    trees = watched_trees(procs)
    return {"session": sess, "connections": conns, "trees": trees, "tree_alerts": tree_alerts(trees),
            "alerts": read_alerts(100)}


# ---------------------------------------------------------------- CLI

def _c(sev):
    return {"critical": mg.C["r"], "warning": mg.C["y"], "info": mg.C["d"]}[sev]


def dedupe(alerts):
    seen, out = set(), []
    for a in alerts:
        k = (a["kind"], a["title"], a["detail"])
        if k not in seen:
            seen.add(k)
            out.append(a)
    return out


def print_alerts(alerts, limit=50, hide_info=False):
    alerts = dedupe(alerts)
    info = [a for a in alerts if a["severity"] == "info"]
    if hide_info and len(info) < len(alerts):
        alerts = [a for a in alerts if a["severity"] != "info"]
    elif hide_info and info:
        print(f"  {mg.C['g']}No warnings.{mg.C['x']} {mg.C['d']}{len(info)} info note(s), e.g. {info[0]['title']} "
              f"(--json for all){mg.C['x']}")
        return
    if not alerts:
        print(f"  {mg.C['g']}Nothing to flag.{mg.C['x']}")
    for a in sorted(alerts, key=lambda a: -SEV_RANK[a["severity"]])[:limit]:
        print(f"  {_c(a['severity'])}{a['severity']:<8}{mg.C['x']} {a['title']}")
        if a.get("detail"):
            print(f"           {mg.C['d']}{a['detail'][:220]}{mg.C['x']}")


def cmd_net_live(args):
    procs = proc_snapshot()
    conns = live_connections(procs)
    dns = DnsCache()
    names = dns.lookup_many([c["rhost"] for c in conns])
    dns.save()
    if args.json:
        for c in conns:
            c["name"] = names.get(c["rhost"], "")
            c["alerts"] = connection_alerts(c, c["name"])
        print(json.dumps(conns, indent=1, default=str))
        return
    print(f"{mg.C['B']}Live outbound connections{mg.C['x']} {mg.C['d']}({len(conns)}; netstat -anv, no root){mg.C['x']}")
    alerts = []
    for c in sorted(conns, key=lambda c: (c["proc"] or "", -c["tx"])):
        name = names.get(c["rhost"], "")
        found = connection_alerts(c, name)
        alerts += found
        mark = max((a["severity"] for a in found), key=SEV_RANK.get, default="")
        print(f"  {(c['proc'] or '?')[:18]:<18} {c['pid'] or '':>6} {mg.C['d']}{(c['parent'] or '')[:14]:<14}{mg.C['x']} "
              f"{(name or c['rhost'])[:44]:<44}:{c['rport'] or '':<5} {mg.C['d']}up {mg.human(c['tx']):>6} "
              f"down {mg.human(c['rx']):>6}{mg.C['x']} {_c(mark) + mark + mg.C['x'] if mark else ''}")
    for a in ollama_alerts(mg.sockets(), procs, names):
        alerts.append(a)
    print(f"\n{mg.C['B']}Findings{mg.C['x']}")
    print_alerts(alerts, hide_info=True)


def print_tree(nodes, depth=0, alerts_by_pid=None):
    for n in nodes:
        a = (alerts_by_pid or {}).get(n["pid"])
        tag = f" {_c(a['severity'])}<- {a['severity']}{mg.C['x']}" if a else ""
        args = (n.get("args") or n["exe"]).replace(mg.HOME, "~")
        print(f"  {'  ' * depth}{'└ ' if depth else ''}{n['name']} {mg.C['d']}{n['pid']}  {args[:90]}{mg.C['x']}{tag}")
        print_tree(n["children"], depth + 1, alerts_by_pid)


def cmd_procs_tree(args):
    procs = proc_snapshot()
    trees = watched_trees(procs)
    alerts = tree_alerts(trees)
    if args.json:
        print(json.dumps({"trees": trees, "alerts": alerts}, indent=1, default=str))
        return
    print(f"{mg.C['B']}Process trees under watched tools{mg.C['x']} {mg.C['d']}(node, npm, python, ollama, claude, docker, "
          f"editors){mg.C['x']}")
    print_tree(trees, alerts_by_pid={a["pid"]: a for a in alerts})
    print(f"\n{mg.C['B']}Findings{mg.C['x']}")
    print_alerts([a for a in alerts if a["severity"] != "info"])
    shells = sum(1 for a in alerts if a["severity"] == "info")
    if shells:
        print(f"  {mg.C['d']}{shells} shell(s) under watched tools: normal for npm scripts and AI agents.{mg.C['x']}")


def cmd_persist(args):
    path = persist_baseline_path()
    if args.snapshot or not os.path.exists(path):
        save_json(path, persistence_snapshot())
        print(f"Saved a persistence baseline ({now_iso()}). Run `macguard persist --diff` later to see changes.")
        if not args.diff:
            return
    before = load_json(path, {"files": {}})
    changes = persistence_diff(before, persistence_snapshot())
    if args.json:
        print(json.dumps({"since": before.get("time"), "changes": changes}, indent=1, default=str))
        return
    print(f"{mg.C['B']}Persistence changes since {before.get('time')}{mg.C['x']}")
    print_alerts(changes)
    for a in changes:
        if a.get("diff") and args.diff:
            print(f"\n{a['diff']}")
    print(f"\n{mg.C['d']}Accept the current state as the new baseline: macguard persist --snapshot{mg.C['x']}")


def cmd_scan_deps(args):
    online = args.online or settings()["osv"]
    if online and not args.online and not args.json:
        print(f"{mg.C['d']}OSV lookups are on in settings (osv_lookups).{mg.C['x']}")
    try:
        r = scan_deps(args.path, online=online)
    except (FileNotFoundError, ValueError) as e:
        sys.exit(str(e))
    if args.json:
        print(json.dumps(r, indent=1, default=str))
        return
    print(f"{mg.C['B']}{r['project']}{mg.C['x']}  {r['packages']} packages (lockfile v{r['lockfile_version']})")
    print(f"\n{mg.C['B']}Install scripts{mg.C['x']} ({len(r['install_scripts'])})")
    for s in r["install_scripts"][:60]:
        print(f"  {mg.C['y']}{s['name']}@{s['version']}{mg.C['x']}  {mg.C['d']}"
              f"{'; '.join(f'{k}: {v}' for k, v in s['scripts'].items())[:120]}{mg.C['x']}")
    print(f"\n{mg.C['B']}Known vulnerabilities{mg.C['x']}")
    if not online:
        print(f"  {mg.C['d']}Not checked. --online asks OSV.dev (sends package names and versions only).{mg.C['x']}")
    elif r["error"]:
        print(f"  {mg.C['r']}{r['error']}{mg.C['x']}")
    elif not r["vulnerabilities"]:
        print(f"  {mg.C['g']}None known.{mg.C['x']}")
    for v in r["vulnerabilities"]:
        print(f"  {_c('critical' if v['severity'] in ('high', 'critical') else 'warning')}{v['severity']:<9}{mg.C['x']}"
              f"{v['name']}@{v['version']}  {mg.C['d']}{', '.join(v['ids'][:4])}{mg.C['x']}")
    print(f"\n{mg.C['B']}Advice{mg.C['x']}")
    for a in r["advice"]:
        print(f"  - {a}")


def cmd_lulu(args):
    if args.tag:
        rules, err = lulu_rules()
        if err:
            sys.exit(err)
        match = [r for r in rules if (r["uuid"] or "").lower().startswith(args.tag.lower())]
        if len(match) != 1:
            sys.exit(f"{len(match)} rules match {args.tag!r}; give more of the uuid.")
        t = lulu_tag(match[0]["uuid"], args.hours, args.label or "temporary")
        print(f"{match[0]['name']}: " + (f"reminder at {now_iso(t['until'])}. macguard never changes LuLu; it tells you "
                                         "when to revoke the rule." if t else "reminder removed."))
        return
    rules, err = lulu_rules()
    if err:
        print(err)
        return
    rows, alerts = lulu_audit(rules)
    if args.json:
        print(json.dumps({"rules": rows, "alerts": alerts}, indent=1, default=str))
        return
    shown = rows if args.all else [r for r in rows if not r["apple"]]
    print(f"{mg.C['B']}LuLu allow rules{mg.C['x']} {mg.C['d']}({len(rows)} allow, {len(shown)} shown; read-only)"
          f"{mg.C['x']}")
    for r in shown[:args.limit]:
        print(f"  {_c(r['severity'])}{r['severity']:<8}{mg.C['x']} {r['name'][:28]:<28} {r['addr'][:24]}:{r['port']:<6} "
              f"{mg.C['d']}{(r['uuid'] or '')[:8]}  {'; '.join(r['flags'])[:90]}{mg.C['x']}")
    print(f"\n{mg.C['d']}Temporary permission reminder: macguard lulu --tag <uuid> --hours 24  "
          f"(--hours 0 removes it){mg.C['x']}")


def cmd_session(args):
    if args.action == "run":
        return run_monitor(args.id, args.seconds)
    if args.action == "start":
        try:
            s = start_session(args.project or [os.getcwd()] if not args.no_cwd else args.project or [], label=args.label or "")
        except RuntimeError as e:
            sys.exit(str(e))
        print(f"Dev session {s['id']} started (monitor pid {s.get('monitor_pid')}, every {s['interval']}s).\n"
              f"Persistence snapshot taken. Stop with: macguard session stop")
        return
    if args.action == "stop":
        try:
            r = stop_session(online=True if args.online else None)
        except RuntimeError as e:
            sys.exit(str(e))
        print(report_markdown(r) if not args.json else json.dumps(r, indent=1, default=str))
        print(f"\n{mg.C['d']}Saved: {home_short(os.path.join(sessions_dir(r['id']), 'report.md'))} (and report.json)"
              f"{mg.C['x']}")
        return
    if args.action == "status":
        s = current_session()
        if not s:
            print("No dev session running.")
        else:
            ev = read_events(s["id"])
            n = {sev: sum(1 for e in ev if e["severity"] == sev and e["kind"] != "session") for sev in SEVERITIES}
            print(f"Session {s['id']} since {s['started']} · monitor {'running' if s['monitor_running'] else 'NOT running'}"
                  f" · {n['critical']} critical, {n['warning']} warnings, {n['info']} info")
            print_alerts([e for e in ev if e["kind"] != "session" and e["severity"] != "info"][-15:])
        return
    if args.action == "report":
        r = load_report(args.id)
        if not r:
            sys.exit("No finished session yet.")
        if args.format == "json" or args.json:
            print(json.dumps(r, indent=1, default=str))
        else:
            print(report_markdown(r))
        return
    if args.action == "list":
        for s in list_sessions():
            sm = s["summary"] or {}
            print(f"  {s['id']}  {'done' if s['finished'] else 'running/unfinished'}  "
                  f"{sm.get('critical', '-')} critical, {sm.get('warning', '-')} warnings")


def cmd_alerts(args):
    rows = read_alerts(args.limit, args.min)
    if args.json:
        print(json.dumps(rows, indent=1))
        return
    for a in rows:
        print(f"  {a['time']}  {_c(a['severity'])}{a['severity']:<8}{mg.C['x']} [{a['kind']}] {a['title']}")
