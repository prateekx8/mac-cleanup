#!/usr/bin/python3
"""MCP server for mac-cleanup: exposes macguard's scans, audits and cleanup as tools.

Speaks the Model Context Protocol (JSON-RPC 2.0, one message per line) on stdio, so any
MCP client can use it. Register it with Claude Code:

  claude mcp add mac-cleanup -- /usr/bin/python3 /path/to/mac-cleanup/macguard_mcp.py

Everything is read-only except `apply_cleanup`, which only deletes what an earlier
`plan_cleanup` call listed (by plan id), so the client always sees the exact paths first,
and `kill_process`, which never touches macOS, root-owned or this session's processes.
Stdlib only, like macguard.
"""
import contextlib
import json
import os
import secrets
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macguard as mg  # noqa: E402

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
PLAN_TTL = 15 * 60
_plans = {}  # plan_id -> {"created", "stale_days", "items": {category id: set(paths)}}

READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}


def _obj(props=None, required=()):
    return {"type": "object", "properties": props or {}, "required": list(required), "additionalProperties": False}


STALE = {"type": "integer", "minimum": 1, "maximum": 3650, "default": 30,
         "description": "Project build dirs untouched for this many days count as stale"}


# ---------------------------------------------------------------- tool implementations

def t_disk_info(a):
    d = mg.disk_info()
    return {**d, "human": {k: mg.human(v) for k, v in d.items()}}


def t_scan_junk(a):
    results = mg.scan_junk(a.get("stale_days", 30))
    items = mg.junk_json(results)
    for it in items:
        it["human_size"] = mg.human(it["size"])
    return {"disk": t_disk_info({}), "items": items,
            "safe_total": mg.human(sum(r["size"] for r in results if r["risk"] == "safe")),
            "review_total": mg.human(sum(r["size"] for r in results if r["risk"] == "review"))}


def t_plan_cleanup(a):
    """Dry run: what apply_cleanup would delete. Safe items by default; review items only by id."""
    stale_days = a.get("stale_days", 30)
    known = {j["id"] for j in mg.JUNK}
    ids = a.get("ids")
    if ids is not None:
        bad = sorted(set(ids) - known)
        if bad:
            raise ValueError(f"unknown category ids: {bad}. Known: {sorted(known)}")
    results = mg.scan_junk(stale_days)
    plan = [r for r in results if r["size"] > 0 and (r["id"] in ids if ids is not None else r["risk"] == "safe")]
    now = time.time()
    for pid in [p for p, v in _plans.items() if now - v["created"] > PLAN_TTL]:
        del _plans[pid]
    plan_id = secrets.token_hex(8)
    _plans[plan_id] = {"created": now, "stale_days": stale_days, "items": {r["id"]: {p for p, _, _ in r["entries"]} for r in plan}}
    total = sum(r["size"] for r in plan)
    return {"plan_id": plan_id, "expires_in_seconds": PLAN_TTL, "total": total, "human_total": mg.human(total),
            "items": [{"id": r["id"], "name": r["name"], "risk": r["risk"], "note": r.get("note", ""),
                       "size": r["size"], "human_size": mg.human(r["size"]),
                       "entries": [{"path": p.replace(mg.HOME, "~"), "size": s, "label": l}
                                   for p, s, l in sorted(r["entries"], key=lambda e: -e[1])]} for r in plan],
            "next": "Show the user this plan. Call apply_cleanup with this plan_id and confirm=true only after they agree."}


def t_apply_cleanup(a):
    plan = _plans.get(a["plan_id"])
    if not plan or time.time() - plan["created"] > PLAN_TTL:
        raise ValueError("unknown or expired plan_id - call plan_cleanup again")
    if a.get("confirm") is not True:
        raise ValueError("refusing to delete without confirm=true")
    del _plans[a["plan_id"]]  # one use only
    mg.ensure_state()
    # rescan, then only touch paths that were in the plan the user saw
    fresh = {r["id"]: r for r in mg.scan_junk(plan["stale_days"])}
    freed, cleaned = 0, []
    for cid, paths in plan["items"].items():
        r = fresh.get(cid)
        if not r:
            continue
        entries = [e for e in r["entries"] if e[0] in paths]
        if not entries:
            continue
        freed += mg.clean_item({**r, "entries": entries, "size": sum(e[1] for e in entries)})
        cleaned.append(cid)
    mg.log_event("clean", f"[mcp] freed ~{mg.human(freed)} ({', '.join(cleaned)})")
    return {"freed": freed, "human_freed": mg.human(freed), "cleaned": cleaned, "disk": t_disk_info({})}


def t_security_audit(a):
    return {"findings": mg.findings_json(mg.cmd_security(None, quiet=True))}


def t_network_snapshot(a):
    snap = mg.net_snapshot()
    seen, listeners = set(), []
    for s in sorted(snap["listeners"], key=lambda s: s["lport"] or 0):
        if (s["proc"], s["lport"]) not in seen:
            seen.add((s["proc"], s["lport"]))
            listeners.append({"port": s["lport"], "host": s["lhost"], "proc": s["proc"], "pid": s["pid"], "exe": s["exe"],
                              "sig": mg.signature(s["exe"]), "exposed": not (s["lhost"].startswith("127.") or s["lhost"] == "::1")})
    return {"gateway": snap["gateway"], "gateway_mac": snap["gateway_mac"], "iface": snap["iface"], "dns": snap["dns"],
            "hosts_overrides": snap["hosts"], "listeners": listeners, "connections": len(snap["conns"]),
            "findings": mg.findings_json(mg.analyze_net(snap))}


def t_apps_audit(a):
    apps, findings = mg.apps_report(online=a.get("online", False))
    out = {"count": len(apps), "findings": mg.findings_json(findings)}
    if a.get("list"):
        out["apps"] = [{"name": x["name"], "version": x["version"], "sig": x["sig"], "archs": x["archs"]} for x in apps]
    return out


def t_traffic_sample(a):
    seconds = a.get("seconds", 6)
    procs = mg.traffic_sample(seconds)
    return {"seconds": seconds, "top": mg.traffic_json(procs), "findings": mg.findings_json(mg.analyze_traffic(procs, seconds))}


def t_process_check(a):
    procs = mg.heavy_processes(a.get("cpu_percent", mg.HEAVY_CPU), a.get("memory_mb", mg.HEAVY_MEM >> 20) << 20,
                               a.get("include_system", True))
    for p in procs:
        p["human_mem"] = mg.human(p["mem"])
    return {"processes": procs,
            "legend": {"system": "macOS, root or this session: never killed", "app": "part of an app: better to quit "
                       "the app so it can save", "background": "user program: stopping it does not affect macOS"}}


def t_kill_process(a):
    if a.get("confirm") is not True:
        raise ValueError("refusing to kill without confirm=true")
    mg.ensure_state()
    return mg.kill_process(a["pid"], a["exe"], a.get("force", False))


def t_network_monitor_status(a):
    return mg.netlog_status()


def _history(a):
    rows = mg.netlog_rows(a.get("days", 7), a.get("process"))
    names = mg.resolve_names({r["rhost"] for r in rows}) if a.get("resolve", True) else {}
    return rows, names


def t_network_history(a):
    rows, names = _history(a)
    out = mg.netlog_summary(rows, names, a.get("limit", 20))
    out["recorder"] = mg.netlog_status()
    if not rows:
        out["hint"] = "No history yet: the user can run `macguard netmon`, or `macguard settings background_watcher on` to record all the time."
    return out


def t_network_alerts(a):
    rows, names = _history(a)
    return {"days": a.get("days", 7), "findings": mg.findings_json(mg.analyze_netlog(rows, names)),
            "note": "Built from sampled socket tables: very short connections between samples are not seen."}


def t_network_record(a):
    seconds, interval = a.get("seconds", 10), a.get("interval", 2)
    rec = mg.NetRecorder()
    end, samples = time.time() + seconds, 0
    while True:
        rec.sample()
        samples += 1
        if time.time() + interval > end:
            break
        time.sleep(interval)
    return {"samples": samples, "status": mg.netlog_status()}


def t_doctor(a):
    return {"checks": [{"ok": ok, "name": n, "detail": d} for ok, n, d in mg.doctor_checks()]}


def t_recent_events(a):
    lines = mg.read_text(mg.EVENTS_LOG).splitlines() if os.path.exists(mg.EVENTS_LOG) else []
    return {"events": lines[-a.get("limit", 30):], "settings": mg.load_settings()}


TOOLS = [
    ("disk_info", "Free/used space on the Mac's data volume.", _obj(), READ_ONLY, t_disk_info),
    ("scan_junk", "Size up rebuildable junk by category (Xcode, simulators, npm/pip/uv/Gradle/Cargo caches, Homebrew, Docker, "
     "old JetBrains versions, stale node_modules, Trash, old Downloads). Each category is 'safe' (caches that regenerate) "
     "or 'review' (the user's call). Read-only.", _obj({"stale_days": STALE}), READ_ONLY, t_scan_junk),
    ("plan_cleanup", "Dry run of a cleanup: returns the exact paths that would be deleted and a plan_id. With no ids, plans "
     "every 'safe' category; 'review' categories are included only when named in ids. Deletes nothing.",
     _obj({"ids": {"type": "array", "items": {"type": "string", "enum": [j["id"] for j in mg.JUNK]},
                   "description": "Category ids to include (see scan_junk)"}, "stale_days": STALE}), READ_ONLY, t_plan_cleanup),
    ("apply_cleanup", "Delete what a plan_cleanup call listed. Only paths in that plan are touched, only inside the home "
     "folder, and each plan_id works once (15 min expiry). Show the user the plan and get their OK first. Irreversible.",
     _obj({"plan_id": {"type": "string"}, "confirm": {"type": "boolean", "description": "Must be true"}}, ("plan_id", "confirm")),
     {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": False}, t_apply_cleanup),
    ("security_audit", "Security posture: firewall and stealth mode, SIP, Gatekeeper, FileVault, Screen Sharing/SSH, "
     "unsigned or orphaned launch agents/daemons, private keys left in Downloads/Desktop/Documents. Read-only.",
     _obj(), READ_ONLY, t_security_audit),
    ("network_snapshot", "Listening ports with owning binary and code signature, gateway, DNS, /etc/hosts, plus threat "
     "findings (exposed services, suspicious ports, unsigned programs online, inbound scans, ARP spoofing). Read-only.",
     _obj(), READ_ONLY, t_network_snapshot),
    ("apps_audit", "Installed apps: broken/missing signatures, outdated (Homebrew), end-of-life or remote-access apps, "
     "Intel-only, orphaned root helpers, system extensions. online=true also asks Apple for macOS updates (slow).",
     _obj({"online": {"type": "boolean", "default": False}, "list": {"type": "boolean", "default": False,
                                                                       "description": "Include every app"}}),
     {**READ_ONLY, "openWorldHint": True}, t_apps_audit),
    ("traffic_sample", "Sample live network traffic per process for a few seconds: heavy uploads, outbound scanning, "
     "unsigned or temp-folder programs online, odd ports. Read-only.",
     _obj({"seconds": {"type": "integer", "minimum": 2, "maximum": 30, "default": 6}}), READ_ONLY, t_traffic_sample),
    ("process_check", "Processes using heavy CPU or memory, heaviest first. Each is classed system (macOS, root-owned or "
     "this session - never killable), app (part of an app; quitting the app is safer) or background (user program, "
     "safe for macOS to stop). Read-only.",
     _obj({"cpu_percent": {"type": "number", "minimum": 0, "default": mg.HEAVY_CPU, "description": "% of one core"},
           "memory_mb": {"type": "integer", "minimum": 0, "default": mg.HEAVY_MEM >> 20},
           "include_system": {"type": "boolean", "default": True}}), READ_ONLY, t_process_check),
    ("kill_process", "Stop one process listed by process_check (SIGTERM; force=true sends SIGKILL). Refuses system, "
     "root-owned and this session's own processes, and refuses if the pid now runs a different executable. "
     "Get the user's OK first: unsaved work in that program is lost.",
     _obj({"pid": {"type": "integer"}, "exe": {"type": "string", "description": "The exe path process_check reported"},
           "force": {"type": "boolean", "default": False}, "confirm": {"type": "boolean", "description": "Must be true"}},
          ("pid", "exe", "confirm")),
     {"readOnlyHint": False, "destructiveHint": True, "idempotentHint": True, "openWorldHint": False}, t_kill_process),
    ("network_monitor_status", "Is the connection recorder running, and how many days of network history exist.",
     _obj(), READ_ONLY, t_network_monitor_status),
    ("network_history", "Recorded network connections over the last N days: connections per day, top programs and "
     "top destination IPs (with reverse-DNS names, ports, which programs, days seen, first/last seen, bytes up/down). "
     "Read-only.",
     _obj({"days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 7},
           "process": {"type": "string", "description": "Only programs whose name or path contains this"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
           "resolve": {"type": "boolean", "default": True, "description": "Reverse-DNS the IPs (local resolver)"}}),
     READ_ONLY, t_network_history),
    ("network_alerts", "Risky traffic in the recorded history: suspicious ports, programs in temp/download folders, "
     "unsigned or deleted programs online, inbound connections from the internet, unencrypted protocols, uncommon "
     "ports, and destinations first seen in the last 24h. Read-only.",
     _obj({"days": {"type": "integer", "minimum": 1, "maximum": 90, "default": 7},
           "process": {"type": "string"}, "resolve": {"type": "boolean", "default": True}}), READ_ONLY, t_network_alerts),
    ("network_record", "Sample the connection table now for a few seconds and add it to the history (useful when the "
     "background recorder is off). Only writes macguard's own history file.",
     _obj({"seconds": {"type": "integer", "minimum": 1, "maximum": 120, "default": 10},
           "interval": {"type": "integer", "minimum": 1, "maximum": 30, "default": 2}}),
     {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_network_record),
    ("doctor", "Check prerequisites (system Python, socket visibility, required and optional tools).", _obj(), READ_ONLY, t_doctor),
    ("recent_events", "Recent macguard events (cleanups, watcher alerts) and current settings.",
     _obj({"limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 30}}), READ_ONLY, t_recent_events),
]
BY_NAME = {t[0]: t for t in TOOLS}


# ---------------------------------------------------------------- protocol

def call_tool(name, args):
    if name not in BY_NAME:
        raise KeyError(name)
    # macguard prints progress; stdout is the protocol channel, so send it to stderr
    with contextlib.redirect_stdout(sys.stderr):
        try:
            data = BY_NAME[name][4](args or {})
        except Exception as e:  # tool errors go back to the model, not as protocol errors
            traceback.print_exc(file=sys.stderr)
            return {"content": [{"type": "text", "text": f"{type(e).__name__}: {e}"}], "isError": True}
    return {"content": [{"type": "text", "text": json.dumps(data, indent=1, default=str)}], "structuredContent": data}


def handle(msg):
    """Return the response for one JSON-RPC message, or None for notifications."""
    method, mid = msg.get("method"), msg.get("id")
    if mid is None:
        return None  # notifications (initialized, cancelled) need no reply
    params = msg.get("params") or {}
    if method == "initialize":
        want = params.get("protocolVersion")
        result = {"protocolVersion": want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                  "capabilities": {"tools": {"listChanged": False}},
                  "serverInfo": {"name": "mac-cleanup", "version": mg.__version__},
                  "instructions": "Disk cleanup, heavy processes, network history (network_history / network_alerts), security, apps and network checks for this Mac. Everything "
                                  "is read-only except apply_cleanup and kill_process: show the user the plan or process "
                                  "first and act only after they agree."}
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": [{"name": n, "description": d, "inputSchema": s, "annotations": ann} for n, d, s, ann, _ in TOOLS]}
    elif method == "tools/call":
        if params.get("name") not in BY_NAME:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": f"unknown tool: {params.get('name')}"}}
        result = call_tool(params["name"], params.get("arguments"))
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": f"method not found: {method}"}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def serve(inp=None, out=None):
    inp, out = inp or sys.stdin, out or sys.stdout
    for line in inp:
        if not line.strip():
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        else:
            resp = handle(msg) if isinstance(msg, dict) else \
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        if resp is not None:
            out.write(json.dumps(resp) + "\n")
            out.flush()


if __name__ == "__main__":
    serve()
