#!/usr/bin/python3
"""MCP server for mac-cleanup: exposes macguard's scans, audits and cleanup as tools.

Speaks the Model Context Protocol (JSON-RPC 2.0, one message per line) on stdio, so any
MCP client can use it. Register it with Claude Code:

  claude mcp add mac-cleanup -- /usr/bin/python3 /path/to/mac-cleanup/macguard_mcp.py

Everything is read-only except `apply_cleanup`, which only deletes what an earlier
`plan_cleanup` call listed (by plan id), so the client always sees the exact paths first,
and `kill_process`, which never touches macOS, root-owned or this session's processes.
The dev session tools only write macguard's own state; scan_dependencies goes online only with consent.
Tools that copy, move or image (recover_restore, recover_image_card, recover_save_files, photos_apply, photos_undo)
need confirm=true; none of them deletes anything.
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
import macguard_capture as cap  # noqa: E402
import macguard_devsec as sec  # noqa: E402
import macguard_aicheck as aic  # noqa: E402
import macguard_carve as carve  # noqa: E402
import macguard_photos as photos  # noqa: E402
import macguard_recover as rec  # noqa: E402
import macguard_tools as mtools  # noqa: E402

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


def t_capture_list(a):
    return {"captures": cap.list_captures(), "keylog": cap.keylog_status(), "interfaces": cap.interfaces(),
            "default_interface": cap.default_iface()}


def t_capture_analyze(a):
    rep = cap.analyze(cid=a.get("id"), path=a.get("file"), limit=a.get("limit", 50))
    if not a.get("payloads", True):
        for r in rep["items"]:
            r["preview_out"]["text"] = r["preview_in"]["text"] = ""
    return rep


def t_packet_capture(a):
    if a.get("confirm") is not True:
        raise ValueError("refusing to capture without confirm=true (it shows the user an admin password dialog)")
    meta = cap.capture(a.get("seconds", 30), a.get("interface"), a.get("preset", "all"), a.get("host"), a.get("port"),
                       a.get("filter"))
    return {"id": meta["id"], "size": meta["size"], "filter": meta["filter"], "next": "call capture_analyze with this id"}


def t_doctor(a):
    return {"checks": [{"ok": ok, "name": n, "detail": d} for ok, n, d in mg.doctor_checks()]}


def t_recent_events(a):
    lines = mg.read_text(mg.EVENTS_LOG).splitlines() if os.path.exists(mg.EVENTS_LOG) else []
    return {"events": lines[-a.get("limit", 30):], "settings": mg.load_settings()}


def t_live_connections(a):
    procs = sec.proc_snapshot()
    conns = sec.live_connections(procs)
    dns = sec.DnsCache()
    names = dns.lookup_many([c["rhost"] for c in conns]) if a.get("resolve", True) else {}
    dns.save()
    alerts = []
    for c in conns:
        c["name"] = names.get(c["rhost"], "")
        found = sec.connection_alerts(c, c["name"])
        c["flags"] = [x["title"] for x in found]
        alerts += found
    alerts += sec.ollama_alerts(mg.sockets(), procs, names)
    return {"connections": conns, "alerts": sec.dedupe(alerts)}


def t_process_tree(a):
    trees = sec.watched_trees(sec.proc_snapshot())
    return {"trees": trees, "alerts": sec.tree_alerts(trees)}


def t_persistence_changes(a):
    path = sec.persist_baseline_path()
    if a.get("snapshot") or not os.path.exists(path):
        sec.save_json(path, sec.persistence_snapshot())
        return {"baseline_saved": True, "changes": [], "next": "call again later to see what changed"}
    before = sec.load_json(path, {"files": {}})
    return {"since": before.get("time"), "changes": sec.persistence_diff(before, sec.persistence_snapshot())}


def t_lulu_audit(a):
    rules, err = sec.lulu_rules()
    if err:
        return {"available": False, "guidance": err}
    rows, alerts = sec.lulu_audit(rules)
    if not a.get("include_apple"):
        rows = [r for r in rows if not r["apple"]]
    return {"available": True, "rules": rows[:a.get("limit", 100)], "alerts": alerts,
            "note": "Read-only: macguard never edits LuLu. Revoke rules in LuLu > Rules."}


def t_lulu_reminder(a):
    return {"uuid": a["uuid"], "reminder": sec.lulu_tag(a["uuid"], a.get("hours", 24), a.get("label") or "temporary")}


def t_scan_dependencies(a):
    if a.get("online") and a.get("confirm_online") is not True:
        raise ValueError("online=true sends package names and versions to OSV.dev: ask the user, then pass confirm_online=true")
    return sec.scan_deps(a["path"], online=bool(a.get("online")))


def t_dev_session(a):
    act = a.get("action", "status")
    if act == "start":
        return {"session": sec.start_session(a.get("projects") or [], label=a.get("label") or "")}
    if act == "stop":
        r = sec.stop_session(online=bool(a.get("online")) if a.get("online") is not None else None)
        return {"report": r, "markdown": sec.report_markdown(r)}
    if act == "report":
        r = sec.load_report(a.get("id"))
        if not r:
            raise ValueError("no finished session yet")
        return {"report": r, "markdown": sec.report_markdown(r)}
    s = sec.current_session()
    return {"session": s, "events": sec.read_events(s["id"])[-a.get("limit", 50):] if s else [],
            "sessions": sec.list_sessions()[:10]}


def t_security_alerts(a):
    return {"alerts": sec.read_alerts(a.get("limit", 100), a.get("min_severity", "info"))}


def t_tools_list(a):
    return {"tools": mtools.TOOLS, "helpers": mtools.helpers()}


def t_recover_search(a):
    sources = a.get("sources") or list(rec.SOURCES)
    bad = set(sources) - set(rec.SOURCES)
    if bad:
        raise ValueError(f"unknown sources {sorted(bad)}; known: {list(rec.SOURCES)}")
    r = rec.search(a.get("query"), tuple(sources), repo=a.get("repo"), path=a.get("path"), finder=bool(a.get("finder")))
    r["items"] = r["items"][:a.get("limit", 100)]
    r["next"].append("To restore one, show the user the item, then call recover_restore with the same query/sources "
                     "and its id, and confirm=true.")
    return r


def t_recover_restore(a):
    if a.get("confirm") is not True:
        raise ValueError("refusing to restore without confirm=true (show the user the item first)")
    sources = a.get("sources") or list(rec.SOURCES)
    r = rec.search(a.get("query"), tuple(sources), repo=a.get("repo"), path=a.get("path"), finder=bool(a.get("finder")))
    item = next((i for i in r["items"] if i["id"] == a["id"]), None)
    if not item:
        raise ValueError("no item with that id in this search; search again with the same query and sources")
    return rec.restore(item, a.get("to"))


def _confirm(a, what):
    if a.get("confirm") is not True:
        raise ValueError(f"refusing to {what} without confirm=true (show the user the plan first)")


def t_ai_check(a):
    path = os.path.expanduser(a["path"])
    if not os.path.isfile(path):
        raise ValueError("no such file")
    return aic.check(os.path.abspath(path))


def t_photos_index(a):
    return photos.index(a["folder"], vision=a.get("vision", True))


def t_photos_summary(a):
    r = photos.summary(a["folder"], a.get("gap_hours", 3.0), a.get("trust_file_dates", False))
    r["events"] = r.get("events", [])[-a.get("events", 40):]
    return r


def t_photos_plan(a):
    p = photos.plan(a["folder"], a.get("layout", "event"), a.get("dest"), a.get("gap_hours", 3.0),
                    a.get("trust_file_dates", False))
    return {k: v for k, v in p.items() if k != "moves"} | {"files": len(p["moves"]), "sample": p["moves"][:30],
            "next": "show the user the folders, then call photos_apply with plan_id, mode and confirm=true"}


def t_photos_apply(a):
    _confirm(a, "sort photos")
    return photos.apply(a["plan_id"], a.get("mode", "copy"))


def t_photos_undo(a):
    _confirm(a, "undo the last move")
    return photos.undo()


def t_photos_find(a):
    return {"matches": photos.find(a["query"], a.get("folder"), a.get("limit", 100))}


def t_recover_scan_image(a):
    r = carve.scan(a["image"], undelete=a.get("undelete", True), do_carve=a.get("carve", True),
                   everything=a.get("everything", False))
    r["items"] = r["items"][:a.get("limit", 200)]
    r["next"].append("To save files, show the user the list, then call recover_save_files with ids and confirm=true.")
    return r


def t_recover_save_files(a):
    _confirm(a, "save recovered files")
    return carve.save("all" if a["ids"] == ["all"] else [str(i) for i in a["ids"]], a.get("to"))


def t_recover_image_card(a):
    _confirm(a, "image a card")
    return carve.image_device(a["disk"], a.get("to"))


def t_recover_analyze(a):
    if not a.get("disk"):
        return {"devices": rec.devices(), "next": "call again with disk=<id> for details"}
    r = rec.analyze(a["disk"])
    if not r:
        raise ValueError(f"no disk {a['disk']}")
    return r


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
    ("capture_list", "Saved packet captures (pcap files under ~/.macguard/captures), network interfaces, and how to "
     "set up an SSLKEYLOGFILE so Wireshark can decrypt TLS. Read-only.", _obj(), READ_ONLY, t_capture_list),
    ("capture_analyze", "Read a saved capture (id) or any classic .pcap (file): every TCP/UDP flow with process, bytes "
     "each way, protocol, and what was sent when it is readable: HTTP requests, MQTT CONNECT/PUBLISH topics and "
     "payloads, DNS/mDNS names, CoAP paths, SSDP, raw text/hex. TLS shows only the server name (SNI). Flags "
     "plaintext credentials and unencrypted IoT protocols to the internet. Read-only.",
     _obj({"id": {"type": "string"}, "file": {"type": "string"},
           "payloads": {"type": "boolean", "default": True, "description": "include payload previews (may hold secrets)"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50}}), READ_ONLY, t_capture_analyze),
    ("packet_capture", "Record packets with tcpdump for a few seconds. Needs root, so macOS shows the user an admin "
     "password dialog; they type it, never you. Presets: all, local (LAN only, for IoT devices), plaintext (HTTP/MQTT/"
     "CoAP/DNS ports). Ask the user first and pass confirm=true.",
     _obj({"seconds": {"type": "integer", "minimum": 1, "maximum": 300, "default": 30},
           "preset": {"type": "string", "enum": ["all", "local", "plaintext"], "default": "all"},
           "host": {"type": "string", "description": "only this IP or hostname (e.g. an IoT device)"},
           "port": {"type": "integer"}, "filter": {"type": "string", "description": "extra tcpdump filter"},
           "interface": {"type": "string"}, "confirm": {"type": "boolean", "description": "Must be true"}}, ("confirm",)),
     {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_packet_capture),
    ("live_connections", "Live outbound internet connections per process (pid, parent, remote host/IP with reverse DNS, "
     "port, bytes up/down) with flags: raw IPs, exfiltration/tunnel domains (Discord/Telegram webhooks, ngrok, pastebin, "
     "transfer sites), suspicious or uncommon ports, heavy uploads, Ollama listening beyond 127.0.0.1. No root. Read-only.",
     _obj({"resolve": {"type": "boolean", "default": True}}), READ_ONLY, t_live_connections),
    ("process_tree", "Process trees under watched dev tools (node, npm, npx, python, ollama, claude, docker, code editors), "
     "flagging shells, curl/wget, osascript, base64, nc, launchctl, crontab and programs from /tmp or Downloads they "
     "spawned. Read-only.", _obj(), READ_ONLY, t_process_tree),
    ("persistence_changes", "Diff launch agents/daemons, login items, crontab, shell configs, /etc/hosts, git config and "
     "hooks, .npmrc and ssh config against a saved baseline (token values are redacted). snapshot=true saves the current "
     "state as the baseline (writes only macguard's own state file).",
     _obj({"snapshot": {"type": "boolean", "default": False}}), READ_ONLY, t_persistence_changes),
    ("lulu_audit", "Read-only audit of the LuLu firewall's allow rules: interpreters allowed anywhere, unsigned or temp-"
     "folder programs, stale and old rules, expired temporary permissions. Gives guidance when the rules aren't readable.",
     _obj({"include_apple": {"type": "boolean", "default": False}, "limit": {"type": "integer", "minimum": 1, "default": 100}}),
     READ_ONLY, t_lulu_audit),
    ("lulu_reminder", "Remind the user to revoke a LuLu allow rule after some hours (hours=0 removes the reminder). "
     "Never changes LuLu itself.",
     _obj({"uuid": {"type": "string"}, "hours": {"type": "number", "minimum": 0, "default": 24}, "label": {"type": "string"}},
          ("uuid",)), {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_lulu_reminder),
    ("scan_dependencies", "Scan a project's package-lock.json: packages with install scripts (preinstall/install/"
     "postinstall). online=true also asks OSV.dev for known vulnerabilities, sending only package names and versions: "
     "ask the user first and pass confirm_online=true.",
     _obj({"path": {"type": "string", "description": "project folder"}, "online": {"type": "boolean", "default": False},
           "confirm_online": {"type": "boolean"}}, ("path",)), {**READ_ONLY, "openWorldHint": True}, t_scan_dependencies),
    ("dev_session", "Dev session security monitor. start: snapshot persistence and run the network, process and "
     "sensitive-file monitors in the background. status: live events. stop: end it and get the report (new "
     "destinations, spawned scripts, persistence changes, sensitive file changes, flagged packages, LuLu rules still "
     "open). report: the last (or given) report.",
     _obj({"action": {"type": "string", "enum": ["start", "status", "stop", "report"], "default": "status"},
           "projects": {"type": "array", "items": {"type": "string"}, "description": "start: project folders to watch"},
           "label": {"type": "string"}, "id": {"type": "string", "description": "report: session id"},
           "online": {"type": "boolean", "description": "stop: ask OSV.dev about npm packages (the user must agree)"},
           "limit": {"type": "integer", "minimum": 1, "default": 50}}), {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_dev_session),
    ("security_alerts", "The local, rotating security alert log (network, process, persistence, file, LuLu, package "
     "alerts) from dev sessions. Read-only.",
     _obj({"limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 100},
           "min_severity": {"type": "string", "enum": ["info", "warning", "critical"], "default": "info"}}),
     READ_ONLY, t_security_alerts),
    ("tools_list", "The Tools section (Recover files, AI image and voice check, Photo sorter) and which optional helpers "
     "(PhotoRec, ddrescue, Sleuth Kit, c2patool, exiftool) are installed. Read-only.", _obj(), READ_ONLY, t_tools_list),
    ("recover_search", "Find deleted or lost files that can be restored: the Trash (read through Finder when macOS "
     "blocks direct access), editor local history (VS Code, Cursor, Windsurf, Antigravity), lost git commits and "
     "staged files in a repo, and older versions in Time Machine (with path). Also lists local snapshots and where "
     "iCloud Drive and Photos keep deleted items. Read-only.",
     _obj({"query": {"type": "string", "description": "part of a name or path, or a pattern like *.jpg"},
           "sources": {"type": "array", "items": {"type": "string", "enum": list(rec.SOURCES)}},
           "repo": {"type": "string", "description": "git repository to search"},
           "path": {"type": "string", "description": "file or folder to find Time Machine versions of"},
           "finder": {"type": "boolean", "default": False, "description": "read a protected Trash through Finder "
                      "(macOS may show the user a one-time permission prompt; ask first)"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}), READ_ONLY, t_recover_search),
    ("recover_restore", "Restore a COPY of one item from recover_search into a folder (default ~/Downloads/Recovered "
     "<date>). Never moves or overwrites; a lost git commit becomes a new branch recovered/<sha>. Pass the same "
     "query/sources, the item id, and confirm=true after the user agrees.",
     _obj({"id": {"type": "string"}, "query": {"type": "string"},
           "sources": {"type": "array", "items": {"type": "string", "enum": list(rec.SOURCES)}},
           "repo": {"type": "string"}, "path": {"type": "string"}, "finder": {"type": "boolean"},
           "to": {"type": "string", "description": "destination folder"},
           "confirm": {"type": "boolean", "description": "Must be true"}}, ("id", "confirm")), {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_recover_restore),
    ("recover_analyze", "Memory cards and external disks: without disk, list connected ones with a quick verdict; with "
     "disk (e.g. disk4), its filesystems, encryption, SMART status and the honest chance of recovering deleted "
     "files, with what to do. The Mac's internal SSD is explained as not recoverable by scanning. Read-only.",
     _obj({"disk": {"type": "string"}}), READ_ONLY, t_recover_analyze),
    ("ai_check", "Does this picture, voice clip or video carry signs of being made by AI? Reads Content Credentials "
     "(C2PA), IPTC digital source type, EXIF/XMP, PNG text from image generators and audio tags; c2patool verifies "
     "signatures when installed. Gives a verdict with the evidence, its strength and the limits. It never says a "
     "file is real: 'no-markers' means nothing was found. Local only. Read-only.",
     _obj({"path": {"type": "string", "description": "the file"}}, ("path",)), READ_ONLY, t_ai_check),
    ("photos_index", "Photo sorter: build or update the index of a folder of photos (date taken, camera, GPS, and "
     "what Apple Vision sees: labels, faces, text, quality, screenshots/receipts, a fingerprint for similar photos). "
     "Writes only macguard's own index; never touches the photos. The Photos library is refused.",
     _obj({"folder": {"type": "string"}, "vision": {"type": "boolean", "default": True}}, ("folder",)),
     READ_ONLY, t_photos_index),
    ("photos_summary", "Photo sorter: what an indexed folder holds: kinds, years, events, duplicates, similar groups, "
     "undated files. Read-only.",
     _obj({"folder": {"type": "string"}, "gap_hours": {"type": "number", "default": 3},
           "trust_file_dates": {"type": "boolean", "default": False},
           "events": {"type": "integer", "minimum": 1, "maximum": 200, "default": 40}}, ("folder",)),
     READ_ONLY, t_photos_summary),
    ("photos_plan", "Photo sorter: plan where every file goes (layout event, month or kind; duplicates and undated set "
     "aside). Nothing moves. Returns a plan id for photos_apply.",
     _obj({"folder": {"type": "string"}, "layout": {"type": "string", "enum": ["event", "month", "kind"]},
           "dest": {"type": "string"}, "gap_hours": {"type": "number"}, "trust_file_dates": {"type": "boolean"}},
          ("folder",)), READ_ONLY, t_photos_plan),
    ("photos_apply", "Photo sorter: carry out a plan after the user agrees. mode copy (default; source untouched), move "
     "(same disk only; journalled, undo with photos_undo) or tag (Finder tags only). Never deletes.",
     _obj({"plan_id": {"type": "string"}, "mode": {"type": "string", "enum": ["copy", "move", "tag"]},
           "confirm": {"type": "boolean", "description": "Must be true"}}, ("plan_id", "confirm")),
     {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_photos_apply),
    ("photos_undo", "Photo sorter: put every file of the last move back where it was.",
     _obj({"confirm": {"type": "boolean", "description": "Must be true"}}, ("confirm",)), {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_photos_undo),
    ("photos_find", "Photo sorter: search indexed photos by what's in them, kind, camera, month or year "
     "(e.g. 'beach 2024', 'receipt', 'dog august'). Read-only.",
     _obj({"query": {"type": "string"}, "folder": {"type": "string"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}, ("query",)),
     READ_ONLY, t_photos_find),
    ("recover_scan_image", "Deep recovery: scan a card IMAGE file (from recover_image_card) for deleted files: FAT and "
     "exFAT undelete with names, and signature carving (JPEG, PNG, HEIC/MP4/MOV, RAW/TIFF, PDF, Office, WAV). "
     "Read-only; never scans a device directly.",
     _obj({"image": {"type": "string"}, "undelete": {"type": "boolean"}, "carve": {"type": "boolean"},
           "everything": {"type": "boolean", "description": "also carve files that weren't deleted"},
           "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 200}}, ("image",)),
     READ_ONLY, t_recover_scan_image),
    ("recover_save_files", "Deep recovery: write chosen items from the last recover_scan_image to a folder on the Mac "
     "(default ~/Downloads/Recovered <date>), never onto the card. ids: item ids, or [\"all\"].",
     _obj({"ids": {"type": "array", "items": {"type": "string"}}, "to": {"type": "string"},
           "confirm": {"type": "boolean", "description": "Must be true"}}, ("ids", "confirm")),
     {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_recover_save_files),
    ("recover_image_card", "Deep recovery: copy a whole memory card or USB stick (e.g. disk4, from recover_analyze) "
     "into an image file, read-only. Shows the user the macOS admin password dialog once. Refuses internal and "
     "encrypted disks. Only for cards the user owns.",
     _obj({"disk": {"type": "string"}, "to": {"type": "string", "description": "folder for the image (not the card)"},
           "confirm": {"type": "boolean", "description": "Must be true"}}, ("disk", "confirm")),
     {"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}, t_recover_image_card),
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
                  "instructions": "Disk cleanup, heavy processes, network history (network_history / network_alerts), security, apps and network checks for this Mac, "
                                  "plus a dev session security monitor (dev_session, live_connections, process_tree, persistence_changes, lulu_audit, scan_dependencies) and Tools (recover_search, recover_restore, recover_analyze, recover_image_card, recover_scan_image, recover_save_files, ai_check, photos_index, photos_summary, photos_plan, photos_apply, photos_undo, photos_find). Everything "
                                  "is read-only except apply_cleanup, kill_process and the confirm=true tools (recover_restore, "
                                  "recover_image_card, recover_save_files, photos_apply, photos_undo): show the user the plan, "
                                  "process or files first and act only after they agree."}
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
