"""Tests for macguard. Run: /usr/bin/python3 -m unittest discover -s tests -v

Unit tests use temp dirs and mocked system commands, so they never touch your real
caches, settings or launch agents. The `Live*` tests call real read-only macOS
commands (df, netstat, codesign...) and are skipped off macOS.
"""
import argparse
import io
import json
import os
import re
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import macguard as mg  # noqa: E402

ON_MAC = sys.platform == "darwin"


def quiet(fn, *a, **kw):
    with redirect_stdout(io.StringIO()):
        return fn(*a, **kw)


class TempHome(unittest.TestCase):
    """Points HOME, state dir, settings and launch-agent paths at a temp dir."""

    def setUp(self):
        self.tmp = os.path.realpath(tempfile.mkdtemp(prefix="macguard-test-"))
        self.home = os.path.join(self.tmp, "home")
        os.makedirs(self.home)
        state = os.path.join(self.home, ".macguard")
        self.patches = [
            mock.patch.object(mg, "HOME", self.home),
            mock.patch.object(mg, "STATE_DIR", state),
            mock.patch.object(mg, "BASELINE", os.path.join(state, "baseline.json")),
            mock.patch.object(mg, "EVENTS_LOG", os.path.join(state, "events.log")),
            mock.patch.object(mg, "SETTINGS", os.path.join(state, "settings.json")),
            mock.patch.object(mg, "AGENT_PLIST", os.path.join(self.home, "agent.plist")),
            mock.patch.object(mg, "notify", lambda *a: None),
            mock.patch.object(mg, "TRASH_BIN", None),  # never touch the real Trash from tests
            mock.patch.object(mg, "finder_trash", lambda paths: None),
        ]
        for p in self.patches:
            p.start()
        mg._artifact_cache.clear()
        mg._tracked_cache.clear()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def mk(self, rel, size=1024, age_days=0):
        path = os.path.join(self.home, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(b"x" * size)
        if age_days:
            t = time.time() - age_days * 86400
            os.utime(path, (t, t))
        return path


# ---------------------------------------------------------------- helpers

class TestHelpers(unittest.TestCase):
    def test_human(self):
        self.assertEqual(mg.human(500), "500B")
        self.assertEqual(mg.human(2048), "2K")
        self.assertEqual(mg.human(5 * 1024 ** 3), "5.0G")

    def test_split_addr(self):
        self.assertEqual(mg.split_addr("192.168.1.5.443"), ("192.168.1.5", 443))
        self.assertEqual(mg.split_addr("*.5000"), ("*", 5000))
        self.assertEqual(mg.split_addr("2001:db8:1c75:6.54386"), ("2001:db8:1c75:6", 54386))
        self.assertEqual(mg.split_addr("*.*"), ("*", None))

    def test_is_private(self):
        for h in ("127.0.0.1", "::1", "192.168.1.1", "10.0.0.4", "fe80::1876:d85d:", "fd00::1", "*"):
            self.assertTrue(mg.is_private(h), h)
        for h in ("8.8.8.8", "34.111.148.117", "2607:6bc0::10"):
            self.assertFalse(mg.is_private(h), h)

    def test_version_key_sorts_numerically(self):
        names = ["IntelliJIdea2025.10", "IntelliJIdea2025.3", "IntelliJIdea2026.2"]
        self.assertEqual(sorted(names, key=mg.version_key)[-1], "IntelliJIdea2026.2")
        self.assertEqual(sorted(names, key=mg.version_key)[0], "IntelliJIdea2025.3")


# ---------------------------------------------------------------- disk / cleanup

class TestCleanup(TempHome):
    def test_old_versions_keeps_newest_per_product(self):
        for d in ("IntelliJIdea2025.3", "IntelliJIdea2026.2", "PyCharm2025.1"):
            os.makedirs(os.path.join(self.home, "jb", d))
        old = mg.old_versions(os.path.join(self.home, "jb", "*"), r"([A-Za-z]+)\d{4}\.\d+")
        self.assertEqual([os.path.basename(p) for p in old], ["IntelliJIdea2025.3"])

    def test_du_and_resolve_glob(self):
        self.mk("cache/a/f1", 4096)
        self.mk("cache/b/f2", 4096)
        item = dict(id="t", name="t", risk="safe", paths=[os.path.join(self.home, "cache", "*")])
        entries = mg.resolve(item)
        self.assertEqual(len(entries), 2)
        self.assertTrue(all(size >= 4096 for _, size, _ in entries))
        self.assertEqual(mg.du(os.path.join(self.home, "nope")), 0)

    def test_project_artifacts_only_stale_and_guarded(self):
        root = os.path.join(self.home, "DEV")
        # stale node project
        self.mk("DEV/old/package.json", 10, age_days=100)
        self.mk("DEV/old/node_modules/x/index.js", 2 * 1024 * 1024)
        # active cargo project
        self.mk("DEV/fresh/Cargo.toml", 10)
        self.mk("DEV/fresh/target/debug/bin", 1024)
        # "build" folder without a build file must NOT count
        self.mk("DEV/docs/build/readme.txt", 10, age_days=100)
        # "target" without Cargo.toml/pom.xml must NOT count
        self.mk("DEV/notrust/target/thing", 10, age_days=100)
        with mock.patch.object(mg, "project_roots", lambda: [root]):
            found = {os.path.relpath(a["path"], root): a for a in mg.find_project_artifacts(30)}
        self.assertIn("old/node_modules", found)
        self.assertTrue(found["old/node_modules"]["stale"])
        self.assertIn("fresh/target", found)
        self.assertFalse(found["fresh/target"]["stale"])
        self.assertNotIn("docs/build", found)
        self.assertNotIn("notrust/target", found)
        with mock.patch.object(mg, "project_roots", lambda: [root]):
            entries = mg.resolve({"special": "projects"}, 30)
        self.assertEqual([os.path.relpath(p, root) for p, _, _ in entries], ["old/node_modules"])

    def git(self, cwd, *args):
        import subprocess
        subprocess.run(["git", "-C", cwd, *args], check=True, capture_output=True,
                       env=dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
                                GIT_COMMITTER_EMAIL="t@t"))

    def test_build_outputs_active_only_and_never_dependencies(self):
        root = os.path.join(self.home, "DEV")
        self.mk("DEV/rust/Cargo.toml", 10)
        self.mk("DEV/rust/target/release/app", 2 * 1024 * 1024)
        self.mk("DEV/web/package.json", 10)
        self.mk("DEV/web/.next/cache/x", 2 * 1024 * 1024)
        self.mk("DEV/web/node_modules/react/index.js", 2 * 1024 * 1024)  # dependency: not a build output
        self.mk("DEV/cpp/CMakeLists.txt", 10)
        self.mk("DEV/cpp/cmake-build-debug/obj.o", 2 * 1024 * 1024)
        self.mk("DEV/old/package.json", 10, age_days=100)
        self.mk("DEV/old/dist/bundle.js", 2 * 1024 * 1024, age_days=100)
        with mock.patch.object(mg, "project_roots", lambda: [root]):
            builds = sorted(os.path.relpath(p, root) for p, _, _ in mg.resolve({"special": "builds"}))
            stale = sorted(os.path.relpath(p, root) for p, _, _ in mg.resolve({"special": "projects"}))
        self.assertEqual(builds, ["cpp/cmake-build-debug", "rust/target", "web/.next"])
        self.assertEqual(stale, ["old/dist"])  # stale project: in the stale check, not duplicated in builds

    def test_git_tracked_output_is_never_offered(self):
        root = os.path.join(self.home, "DEV")
        repo = os.path.join(root, "lib")
        self.mk("DEV/lib/package.json", 10)
        self.mk("DEV/lib/dist/published.js", 2 * 1024 * 1024)      # committed: source
        self.mk("DEV/lib/build/out.js", 2 * 1024 * 1024)           # not committed: build output
        self.git(repo, "init", "-q")
        self.git(repo, "add", "package.json", "dist/published.js")
        self.git(repo, "commit", "-qm", "init")
        with mock.patch.object(mg, "project_roots", lambda: [root]):
            builds = [os.path.relpath(p, root) for p, _, _ in mg.resolve({"special": "builds"})]
        self.assertEqual(builds, ["lib/build"])

    def test_is_artifact_rules(self):
        self.assertTrue(mg.is_artifact("target", ["Cargo.toml"]))
        self.assertFalse(mg.is_artifact("target", ["notes.txt"]))
        self.assertTrue(mg.is_artifact("cmake-build-release", ["CMakeLists.txt"]))
        self.assertFalse(mg.is_artifact("build", ["README.md"]))
        self.assertTrue(mg.is_artifact("build", ["build.gradle"]))
        self.assertTrue(mg.is_artifact("__pycache__", []))
        self.assertIn("node_modules", mg.DEPENDENCY_DIRS)
        self.assertNotIn("node_modules", mg.BUILD_DIRS)

    def test_builds_flag_selects_build_outputs(self):
        target = os.path.dirname(self.mk("DEV/rust/target/x", 100))
        results = [dict(id="build-outputs", name="b", risk="review", entries=[(target, 100, "")], size=100),
                   dict(id="s", name="safe", risk="safe", entries=[], size=0)]
        with mock.patch.object(mg, "scan_junk", lambda *a, **k: results):
            quiet(mg.cmd_clean, argparse.Namespace(apply=True, yes=True, only=None, builds=True, stale_days=30))
        self.assertFalse(os.path.exists(target))
        self.assertTrue(os.path.exists(os.path.dirname(target)))  # project itself kept

    def test_old_downloads(self):
        self.mk("Downloads/old.zip", 100, age_days=120)
        self.mk("Downloads/new.zip", 100)
        names = [os.path.basename(p) for p, _, _ in mg.resolve({"special": "downloads"})]
        self.assertEqual(names, ["old.zip"])

    def test_clean_item_deletes_files_and_dirs(self):
        d = os.path.dirname(self.mk("cache/dir/f", 100))
        f = self.mk("cache/file", 100)
        r = dict(id="t", name="t", risk="safe", entries=[(d, 100, ""), (f, 100, "")])
        freed = quiet(mg.clean_item, r)
        self.assertEqual(freed, 200)
        self.assertFalse(os.path.exists(d))
        self.assertFalse(os.path.exists(f))

    def test_clean_item_refuses_paths_outside_home(self):
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        r = dict(id="t", name="t", risk="safe", entries=[(outside, 1, ""), ("/", 1, "")])
        freed = quiet(mg.clean_item, r)
        self.assertEqual(freed, 0)
        self.assertTrue(os.path.exists(outside))

    def _fake_scan(self):
        safe = os.path.dirname(self.mk("cache/safe/f", 100))
        review = os.path.dirname(self.mk("cache/review/f", 100))
        return [dict(id="s", name="safe", risk="safe", entries=[(safe, 100, "")], size=100),
                dict(id="r", name="review", risk="review", entries=[(review, 100, "")], size=100)], safe, review

    def args(self, **kw):
        base = dict(apply=False, yes=False, only=None, stale_days=30)
        base.update(kw)
        return argparse.Namespace(**base)

    def test_clean_dry_run_deletes_nothing(self):
        results, safe, review = self._fake_scan()
        with mock.patch.object(mg, "scan_junk", lambda *a, **k: results):
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_clean(self.args())
        self.assertIn("Dry run", out.getvalue())
        self.assertTrue(os.path.exists(safe) and os.path.exists(review))

    def test_clean_apply_only_safe_by_default(self):
        results, safe, review = self._fake_scan()
        with mock.patch.object(mg, "scan_junk", lambda *a, **k: results):
            quiet(mg.cmd_clean, self.args(apply=True, yes=True))
        self.assertFalse(os.path.exists(safe))
        self.assertTrue(os.path.exists(review))
        self.assertIn("[clean]", mg.read_text(mg.EVENTS_LOG))

    def test_clean_only_selects_review_items(self):
        results, safe, review = self._fake_scan()
        with mock.patch.object(mg, "scan_junk", lambda *a, **k: results):
            quiet(mg.cmd_clean, self.args(apply=True, yes=True, only="r"))
        self.assertTrue(os.path.exists(safe))
        self.assertFalse(os.path.exists(review))

    def test_clean_apply_aborts_without_yes(self):
        results, safe, _ = self._fake_scan()
        with mock.patch.object(mg, "scan_junk", lambda *a, **k: results), mock.patch("builtins.input", return_value="no"):
            quiet(mg.cmd_clean, self.args(apply=True))
        self.assertTrue(os.path.exists(safe))

    def test_every_junk_category_is_well_formed(self):
        ids = [j["id"] for j in mg.JUNK]
        self.assertEqual(len(ids), len(set(ids)), "duplicate ids")
        for j in mg.JUNK:
            self.assertIn(j["risk"], ("safe", "review"))
            self.assertTrue(j.get("paths") or j.get("special"), j["id"])


# ---------------------------------------------------------------- network

NETSTAT_TCP = """Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs
tcp4       0      0  127.0.0.1.6379         *.*                    LISTEN                 0            0  131072  131072 com.docker.backe:3740   00100 00000006 000000000005b84a 00000000 00000800      1      0 000000
tcp4       0      0  *.5000                 *.*                    LISTEN                 0            0  131072  131072    ControlCenter:673    00100 00000006 000000000000172d 00000001 00000800      1      0 000000
tcp6       0      0  2001:db8:1c75:6.54386 2607:6bc0::10.443      ESTABLISHED        31670        34393  131072  131072           claude:50195  00102 00000008 000000000008d602 20000081 04000900      3      0 000004
tcp4       0    148  192.168.1.10.54416     192.168.1.13.5900      ESTABLISHED    281388138       226100 1943968  131072   Screen Sharing:52243  00002 00000000 000000000008deae 20000080 04000900      4      0 000004
"""
ARP = """? (192.168.1.1) at 02:00:5e:00:00:01 on en0 ifscope [ethernet]
? (192.168.1.10) at 02:00:5e:00:00:0a on en0 ifscope permanent [ethernet]
? (192.168.1.13) at 2:0:5e:0:0:d on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]
"""


def fake_run(mapping):
    def _run(cmd, timeout=60):
        key = cmd if isinstance(cmd, str) else " ".join(cmd)
        for k, v in mapping.items():
            if key.startswith(k):
                return 0, v, ""
        return 0, "", ""
    return _run


def L(port, host="*", exe="/bin/x", proc="x", pid=1):
    return dict(proto="tcp4", lhost=host, lport=port, rhost="*", rport=None, state="LISTEN", proc=proc, pid=pid, exe=exe)


def CONN(rhost, rport, lport=50000, exe="/bin/x", proc="x", state="ESTABLISHED"):
    return dict(proto="tcp4", lhost="192.168.1.10", lport=lport, rhost=rhost, rport=rport, state=state, proc=proc, pid=2, exe=exe)


def SNAP(listeners=(), conns=(), arp=(), gateway="192.168.1.1", gw_mac="aa:aa:aa:aa:aa:aa", dns=("1.1.1.1",), hosts=()):
    return dict(listeners=list(listeners), conns=list(conns), arp=list(arp), gateway=gateway, iface="en0",
                gateway_mac=gw_mac, dns=list(dns), hosts=list(hosts), time=0)


class TestNetworkParsing(unittest.TestCase):
    def test_sockets_parses_netstat(self):
        with mock.patch.object(mg, "run", fake_run({"netstat -anv -p tcp": NETSTAT_TCP})):
            rows = mg.sockets()
        self.assertEqual(len(rows), 4)
        redis = rows[0]
        self.assertEqual((redis["lhost"], redis["lport"], redis["state"], redis["pid"]), ("127.0.0.1", 6379, "LISTEN", 3740))
        self.assertEqual(rows[1]["lhost"], "*")
        claude = rows[2]
        self.assertEqual((claude["rhost"], claude["rport"], claude["proc"], claude["pid"]), ("2607:6bc0::10", 443, "claude", 50195))
        self.assertEqual(rows[3]["pid"], 52243)  # process name containing a space

    def test_arp_table_normalizes_and_filters(self):
        with mock.patch.object(mg, "run", fake_run({"arp -an": ARP})):
            rows = mg.arp_table()
        ips = [r["ip"] for r in rows]
        self.assertEqual(ips, ["192.168.1.1", "192.168.1.10", "192.168.1.13"])
        self.assertEqual(rows[2]["mac"], "02:00:5e:00:00:0d")
        self.assertTrue(rows[1]["permanent"])

    def test_gateway_and_dns(self):
        with mock.patch.object(mg, "run", fake_run({
                "route -n get default": "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n",
                "scutil --dns": "  nameserver[0] : 1.1.1.1\n  nameserver[1] : 8.8.8.8\n  nameserver[0] : 1.1.1.1\n"})):
            self.assertEqual(mg.gateway(), ("192.168.1.1", "en0"))
            self.assertEqual(mg.dns_servers(), ["1.1.1.1", "8.8.8.8"])

    def test_hosts_overrides(self):
        content = "127.0.0.1 localhost\n255.255.255.255 broadcasthost\n::1 localhost\n# comment\n1.2.3.4 evil.example\n"
        with mock.patch("builtins.open", mock.mock_open(read_data=content)):
            self.assertEqual(mg.hosts_overrides(), ["1.2.3.4 evil.example"])


class TestThreatAnalysis(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(mg, "signature", lambda path: "unsigned" if "evil" in path else "apple")
        p.start()
        self.addCleanup(p.stop)

    def titles(self, snap):
        return {(s, t) for s, t, _ in mg.analyze_net(snap)}

    def test_clean_snapshot_has_no_findings(self):
        self.assertEqual(mg.analyze_net(SNAP(listeners=[L(6379, host="127.0.0.1")], conns=[CONN("8.8.8.8", 443)])), [])

    def test_exposed_database_is_high(self):
        self.assertIn(("high", "Redis exposed to the network"), self.titles(SNAP(listeners=[L(6379)])))

    def test_exposed_remote_access_is_medium(self):
        self.assertIn(("medium", "Screen Sharing (VNC) exposed to the network"), self.titles(SNAP(listeners=[L(5900)])))

    def test_unsigned_listener(self):
        t = self.titles(SNAP(listeners=[L(8000, exe="/opt/evil/bin")]))
        self.assertIn(("high", "Unsigned program accepting network connections"), t)

    def test_listener_from_temp_dir(self):
        t = self.titles(SNAP(listeners=[L(8001, exe="/tmp/x/payload")]))
        self.assertIn(("high", "Listener running from a temp/download folder"), t)

    def test_suspicious_port(self):
        t = self.titles(SNAP(conns=[CONN("45.1.2.3", 4444)]))
        self.assertIn(("high", "Connection to suspicious port (metasploit default)"), t)

    def test_unsigned_program_to_internet(self):
        t = self.titles(SNAP(conns=[CONN("45.1.2.3", 443, exe="/opt/evil/bin")]))
        self.assertIn(("medium", "Unsigned program talking to the internet"), t)

    def test_port_scan(self):
        conns = [CONN("45.1.2.3", 40000 + i, lport=p) for i, p in enumerate([22, 80, 443, 5000, 5900, 8080])]
        listeners = [L(p) for p in (22, 80, 443, 5000, 5900, 8080)]
        t = self.titles(SNAP(listeners=listeners, conns=conns))
        self.assertIn(("high", "Possible port scan / flood from remote host"), t)

    def test_single_inbound_internet_connection(self):
        t = self.titles(SNAP(listeners=[L(8080)], conns=[CONN("45.1.2.3", 51000, lport=8080)]))
        self.assertIn(("medium", "Inbound connection from the internet"), t)

    def test_arp_spoofing(self):
        arp = [{"ip": "192.168.1.1", "mac": "de:ad:be:ef:00:01"}, {"ip": "192.168.1.66", "mac": "de:ad:be:ef:00:01"}]
        self.assertIn(("high", "Possible ARP spoofing (gateway MAC shared with another IP)"), self.titles(SNAP(arp=arp)))

    def test_hosts_entries_reported(self):
        self.assertIn(("info", "/etc/hosts has custom entries"), self.titles(SNAP(hosts=["1.2.3.4 x"])))


# ---------------------------------------------------------------- security

class TestSecurity(TempHome):
    def run_security(self, mapping):
        # only plists inside the temp HOME resolve to a program; system ones are ignored
        prog = lambda p: "/nonexistent/prog" if p.startswith(self.home) else None  # noqa: E731
        with mock.patch.object(mg, "run", fake_run(mapping)), mock.patch.object(mg, "plist_program", prog):
            return {(s, t) for s, t, _ in mg.cmd_security(None, quiet=True)}

    def test_firewall_off_and_sharing_on(self):
        res = self.run_security({
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": "Firewall is disabled. (State = 0)",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode": "Firewall stealth mode is off",
            "csrutil status": "System Integrity Protection status: enabled.",
            "spctl --status": "assessments enabled",
            "fdesetup status": "FileVault is On.",
            "launchctl print-disabled system": '"com.apple.screensharing" => enabled\n"com.openssh.sshd" => enabled',
        })
        self.assertIn(("high", "macOS firewall is OFF"), res)
        self.assertIn(("low", "Firewall stealth mode is off"), res)
        self.assertIn(("medium", "Screen Sharing is enabled"), res)
        self.assertIn(("medium", "Remote Login (SSH) is enabled"), res)
        self.assertIn(("ok", "FileVault on"), res)

    def test_all_good(self):
        res = self.run_security({
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate": "Firewall is enabled. (State = 1)",
            "/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode": "Firewall stealth mode is on",
            "csrutil status": "enabled.", "spctl --status": "assessments enabled", "fdesetup status": "FileVault is On.",
        })
        self.assertFalse([r for r in res if r[0] in ("high", "medium")], res)

    def test_orphaned_launch_item(self):
        self.mk("Library/LaunchAgents/a.plist", 10)
        res = self.run_security({})
        self.assertIn(("low", "Orphaned launch item (program no longer exists)"), res)

    def test_private_key_in_downloads(self):
        self.mk("Downloads/server.key", 0)
        with open(os.path.join(self.home, "Downloads/server.key"), "w") as fh:
            fh.write("-----BEGIN RSA PRIVATE KEY-----\nabc\n")
        self.mk("Downloads/notes.key", 10)  # Keynote-ish file without a key header: ignored
        res = self.run_security({})
        self.assertIn(("medium", "Private key / secret file in ~/Downloads"), res)
        findings = mg.cmd_security(None, quiet=True)
        details = " ".join(d for _, t, d in findings if "Private key" in t)
        self.assertIn("server.key", details)
        self.assertNotIn("notes.key", details)


# ---------------------------------------------------------------- applications

def APP(name="Thing", sig="developer:Acme (ABCDE12345)", seal_ok=True, archs=("arm64",), bundle_id="com.acme.thing",
        path=None, updated=None, version="1.0"):
    return dict(name=name, sig=sig, seal_ok=seal_ok, archs=list(archs), bundle_id=bundle_id, version=version,
                path=path or f"/Applications/{name}.app", exe=f"/Applications/{name}.app/Contents/MacOS/{name}",
                updated=updated if updated is not None else time.time())


class TestApps(TempHome):
    def titles(self, apps=(), casks=(), formulae=(), helpers=(), exts=(), updates=None, machine="arm64"):
        return {(s, t) for s, t, _ in mg.analyze_apps(list(apps), list(casks), list(formulae), list(helpers), list(exts),
                                                      updates, machine=machine)}

    def test_inventory_reads_info_plist(self):
        import plistlib
        apps_dir = os.path.join(self.home, "Applications")
        for name, ver in (("Alpha", "2.1"), ("Beta", "0.9")):
            contents = os.path.join(apps_dir, f"{name}.app", "Contents")
            os.makedirs(os.path.join(contents, "MacOS"))
            with open(os.path.join(contents, "Info.plist"), "wb") as fh:
                plistlib.dump({"CFBundleName": name, "CFBundleShortVersionString": ver,
                               "CFBundleIdentifier": f"com.test.{name.lower()}", "CFBundleExecutable": name}, fh)
        with mock.patch.object(mg, "app_dirs", lambda: [apps_dir]):
            apps = mg.app_inventory()
        self.assertEqual([(a["name"], a["version"], a["bundle_id"]) for a in apps],
                         [("Alpha", "2.1", "com.test.alpha"), ("Beta", "0.9", "com.test.beta")])
        self.assertTrue(apps[0]["exe"].endswith("Alpha.app/Contents/MacOS/Alpha"))

    def test_clean_app_has_no_findings(self):
        self.assertEqual(self.titles([APP()]), set())

    def test_broken_seal_unsigned_adhoc(self):
        t = self.titles([APP("A", seal_ok=False), APP("B", sig="unsigned", seal_ok=None), APP("C", sig="adhoc")])
        self.assertIn(("high", "App signature broken (modified after signing)"), t)
        self.assertIn(("medium", "Unsigned app"), t)
        self.assertIn(("low", "Ad-hoc signed app (no developer identity)"), t)

    def test_risky_and_eol_apps(self):
        t = self.titles([APP("TeamViewer", bundle_id="com.teamviewer.TeamViewer"), APP("Adobe Flash Player")])
        self.assertIn(("medium", "Remote-access tool - a common attack vector; remove it if you don't use it"), t)
        self.assertIn(("high", "End-of-life software - no security updates any more"), t)

    def test_intel_only_flag_respects_arm64e_and_machine(self):
        self.assertIn(("low", "Intel-only app (likely unmaintained; needs Rosetta)"), self.titles([APP(archs=("x86_64",))]))
        self.assertEqual(self.titles([APP(archs=("x86_64", "arm64e"))]), set())
        self.assertEqual(self.titles([APP(archs=("x86_64",))], machine="x86_64"), set())

    def test_browser_app_shims_are_ignored(self):
        shim = APP("Chrome Remote Desktop", sig="adhoc", bundle_id="com.google.Chrome.app.abc",
                   path=f"{self.home}/Applications/Chrome Apps.localized/Chrome Remote Desktop.app")
        self.assertEqual(self.titles([shim]), set())

    def test_stale_app(self):
        t = self.titles([APP(updated=time.time() - 4 * 365 * 86400)])
        self.assertIn(("info", "Not updated in 3+ years"), t)

    def test_outdated_helpers_extensions_updates(self):
        t = self.titles(casks=[("ollama-app", "0.24.0", "0.40.13")], formulae=[("openssl@3", "3.0.1", "3.4.0")],
                        helpers=["/Library/PrivilegedHelperTools/com.old.helper"],
                        exts=[dict(kind="network", name="VPN", team="X", version="1")],
                        updates=["macOS Security Update 27.0.2-27.0.2"])
        self.assertIn(("medium", "Outdated app (Homebrew cask)"), t)
        self.assertIn(("low", "1 outdated Homebrew packages"), t)
        self.assertIn(("medium", "Orphaned root helper (its app is gone, it still runs as root if loaded)"), t)
        self.assertIn(("info", "Network extension can see all traffic"), t)
        self.assertIn(("high", "macOS update available"), t)

    def test_brew_outdated_parsing(self):
        out = json.dumps({"formulae": [{"name": "git", "installed_versions": ["2.40"], "current_version": "2.47"}],
                          "casks": [{"name": "zoom", "installed_versions": ["5.0"], "current_version": "6.2"}]})
        with mock.patch.object(mg.shutil, "which", return_value="/opt/homebrew/bin/brew"), \
                mock.patch.object(mg.subprocess, "run", return_value=mock.Mock(stdout=out)):
            casks, formulae = mg.brew_outdated()
        self.assertEqual(casks, [("zoom", "5.0", "6.2")])
        self.assertEqual(formulae, [("git", "2.40", "2.47")])

    def test_system_extensions_parsing(self):
        out = ("3 extension(s)\n--- com.apple.system_extension.network_extension (Go to ...)\n"
               "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]\n"
               "*\t*\tVBG97UB4TA\tcom.objective-see.lulu.extension (4.5.1/4.5.1)\tLuLu\t[activated enabled]\n"
               "--- com.apple.system_extension.driver_extension (Go to ...)\n"
               "*\t*\t5JZGQTGU4W\tcn.wch.CH34xVCPDriver (1.0/1)\tcn.wch.CH34xVCPDriver\t[activated enabled]\n")
        with mock.patch.object(mg, "run", return_value=(0, out, "")):
            exts = mg.system_extensions()
        self.assertEqual([(e["kind"], e["name"], e["team"]) for e in exts],
                         [("network", "LuLu", "VBG97UB4TA"), ("driver", "cn.wch.CH34xVCPDriver", "5JZGQTGU4W")])


# ---------------------------------------------------------------- uninstall / leftovers

class TestUninstall(TempHome):
    def setUp(self):
        super().setUp()
        self.app = self.make_app("Widgetly", "io.acme.widgetly")
        p = mock.patch.object(mg, "app_running", return_value=False)
        p.start()
        self.addCleanup(p.stop)

    def make_app(self, name, bid):
        path = os.path.join(self.home, "Applications", f"{name}.app")
        self.mk(f"Applications/{name}.app/Contents/MacOS/{name}", 1000)
        return dict(name=name, bundle_id=bid, path=path, version="1.0", exe="", updated=0)

    def test_leftovers_match_exact_id_and_name_only(self):
        for rel in ("Library/Application Support/io.acme.widgetly/db", "Library/Application Support/Widgetly/x",
                    "Library/Caches/io.acme.widgetly/c", "Library/Preferences/io.acme.widgetly.plist",
                    "Library/Preferences/io.acme.widgetly.update.plist",
                    "Library/Containers/io.acme.widgetly/Data/x", "Library/Saved Application State/io.acme.widgetly.savedState/s",
                    "Library/Group Containers/ABCDE12345.io.acme.widgetly/g", "Library/LaunchAgents/io.acme.widgetly.helper.plist",
                    # must NOT match:
                    "Library/Application Support/io.acme.widgetlyPro/x", "Library/Caches/io.acme.other/c",
                    "Library/Application Support/Widget/x"):
            self.mk(rel, 10)
        got = sorted(os.path.relpath(p, self.home) for p, _ in mg.app_leftovers(self.app))
        self.assertEqual(got, sorted([
            "Library/Application Support/io.acme.widgetly", "Library/Application Support/Widgetly",
            "Library/Caches/io.acme.widgetly", "Library/Preferences/io.acme.widgetly.plist",
            "Library/Preferences/io.acme.widgetly.update.plist",
            "Library/Containers/io.acme.widgetly", "Library/Saved Application State/io.acme.widgetly.savedState",
            "Library/Group Containers/ABCDE12345.io.acme.widgetly", "Library/LaunchAgents/io.acme.widgetly.helper.plist"]))

    def test_generic_names_are_not_used_for_matching(self):
        app = self.make_app("Data", "io.acme.data")
        self.mk("Library/Application Support/Data/important", 10)
        self.assertEqual(mg.app_leftovers(app), [])

    def test_protected_apps(self):
        self.assertEqual(mg.protected_app(dict(self.app, bundle_id="com.apple.Safari")), "Apple/system app")
        self.assertEqual(mg.protected_app(dict(self.app, path="/opt/tools/Thing.app")), "not in an Applications folder")
        self.assertIsNone(mg.protected_app(self.app))

    def test_trash_is_recoverable_and_never_overwrites(self):
        a = self.mk("Library/Caches/x/one", 10)
        b = self.mk("other/x/one", 10)
        self.assertTrue(mg.trash(os.path.dirname(a))[0])
        self.assertTrue(mg.trash(os.path.dirname(b))[0])  # same basename: gets a time suffix
        trashed = os.listdir(os.path.join(self.home, ".Trash"))
        self.assertEqual(len(trashed), 2)
        self.assertIn("x", trashed)

    def test_uninstall_moves_app_and_data_to_trash(self):
        self.mk("Library/Application Support/io.acme.widgetly/db", 10)
        plan = mg.uninstall_plan(self.app)
        moved, failed = quiet(mg.do_uninstall, plan)
        self.assertEqual((len(moved), failed), (2, []))
        self.assertFalse(os.path.exists(self.app["path"]))
        self.assertEqual(sorted(os.listdir(os.path.join(self.home, ".Trash"))), ["Widgetly.app", "io.acme.widgetly"])
        self.assertIn("[uninstall]", mg.read_text(mg.EVENTS_LOG))

    def test_root_owned_items_share_one_finder_request(self):
        sys_items = [os.path.dirname(self.mk(f"Library/LaunchAgents/io.acme.widgetly.{i}.plist/x", 10)) for i in range(3)]
        plan = dict(app=self.app, items=[(p, 10) for p in sys_items], size=30, blocked=None, running=False)
        batches = []

        def finder(paths):  # simulate the user typing their password: Finder trashes them all
            batches.append(list(paths))
            for p in paths:
                shutil.rmtree(p)
        with mock.patch.object(mg.os, "rename", side_effect=PermissionError(1, "Operation not permitted")), \
                mock.patch.object(mg, "finder_trash", finder), mock.patch.object(mg, "run", return_value=(0, "", "")):
            moved, failed = quiet(mg.do_uninstall, plan)
        self.assertEqual(len(batches), 1)  # one password prompt, not three
        self.assertEqual(len(batches[0]), 3)
        self.assertEqual((len(moved), failed), (3, []))

    def test_never_reports_moved_when_still_there(self):
        """Regression: Finder said OK but nothing moved - success must be verified on disk."""
        d = os.path.dirname(self.mk("Library/Caches/io.acme.widgetly/c", 10))
        plan = dict(app=self.app, items=[(d, 10)], size=10, blocked=None, running=False)
        with mock.patch.object(mg.os, "rename", side_effect=PermissionError(1, "denied")), \
                mock.patch.object(mg, "run", return_value=(0, "", "")):
            moved, failed = quiet(mg.do_uninstall, plan)
        self.assertEqual(moved, [])
        self.assertEqual(failed[0][0], d)
        self.assertTrue(os.path.exists(d))

    def test_same_basename_items_do_not_collide(self):
        """Regression: three folders named io.acme.widgetly moved in the same second."""
        dirs = [os.path.dirname(self.mk(f"Library/{f}/io.acme.widgetly/x", 10))
                for f in ("Application Support", "Caches", "HTTPStorages")]
        result = mg.trash_paths(dirs)
        self.assertEqual(set(result.values()), {""})
        self.assertEqual(len(os.listdir(os.path.join(self.home, ".Trash"))), 3)

    def test_apps_in_root_applications_folder_are_allowed(self):
        """Regression: /Applications/X.app was rejected as an 'unsafe path'."""
        app = dict(self.app, path="/Applications/Widgetly.app")
        plan = dict(app=app, items=[("/Applications/Widgetly.app", 10), ("/etc", 1)], size=11, blocked=None, running=False)
        with mock.patch.object(mg, "trash_paths", return_value={"/Applications/Widgetly.app": ""}) as tp, \
                mock.patch.object(mg.os.path, "lexists", return_value=False), mock.patch.object(mg, "run", return_value=(0, "", "")):
            moved, failed = quiet(mg.do_uninstall, plan)
        tp.assert_called_once_with(["/Applications/Widgetly.app"])
        self.assertEqual(moved, [("/Applications/Widgetly.app", 10)])
        self.assertEqual(failed, [("/etc", "unsafe path")])

    def test_launch_agents_are_unloaded_before_trashing(self):
        agent = self.mk("Library/LaunchAgents/io.acme.widgetly.plist", 10)
        calls = []
        with mock.patch.object(mg, "run", side_effect=lambda cmd, timeout=60: calls.append(cmd) or (0, "", "")):
            quiet(mg.do_uninstall, dict(app=self.app, items=[(agent, 10)], size=10, blocked=None, running=False))
        self.assertEqual(calls[0][:2], ["launchctl", "bootout"])
        self.assertEqual(calls[0][-1], agent)

    def test_reset_keeps_the_app(self):
        self.mk("Library/Caches/io.acme.widgetly/c", 10)
        quiet(mg.do_uninstall, mg.uninstall_plan(self.app, leftovers_only=True))
        self.assertTrue(os.path.exists(self.app["path"]))
        self.assertFalse(os.path.exists(os.path.join(self.home, "Library/Caches/io.acme.widgetly")))

    def test_refuses_protected_and_running(self):
        with self.assertRaises(ValueError):
            mg.do_uninstall(mg.uninstall_plan(dict(self.app, bundle_id="com.apple.Notes")))
        with mock.patch.object(mg, "app_running", return_value=True), self.assertRaises(ValueError):
            mg.do_uninstall(mg.uninstall_plan(self.app))
        self.assertTrue(os.path.exists(self.app["path"]))

    def test_cli_dry_run_and_ambiguity(self):
        other = self.make_app("Widgetly Pro", "io.acme.widgetlypro")
        with mock.patch.object(mg, "app_inventory", return_value=[self.app, other]):
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_uninstall(argparse.Namespace(app="widgetly", apply=False, yes=False, leftovers_only=False))
            self.assertIn("Dry run", out.getvalue())
            self.assertTrue(os.path.exists(self.app["path"]))
            with self.assertRaises(SystemExit):
                quiet(mg.cmd_uninstall, argparse.Namespace(app="widg", apply=False, yes=False, leftovers_only=False))

    def test_orphan_leftovers(self):
        self.mk("Library/Application Support/io.gone.app/big", 2 * 1024 * 1024)          # orphan
        self.mk("Library/Caches/io.acme.widgetly.helper/x", 2 * 1024 * 1024)              # helper of installed app
        self.mk("Library/Caches/com.apple.Safari/x", 2 * 1024 * 1024)                     # Apple
        self.mk("Library/Application Support/Plain Folder/x", 2 * 1024 * 1024)            # not attributable
        self.mk("Library/Preferences/io.acme.other.plist", 2 * 1024 * 1024)               # orphan, vendor installed
        with mock.patch.object(mg, "app_inventory", return_value=[self.app]), \
                mock.patch.object(mg, "running_commands", return_value="/usr/sbin/cfprefsd\n"):
            got = {os.path.relpath(p, self.home): label for p, _, label in mg.orphan_leftovers()}
        self.assertEqual(set(got), {"Library/Application Support/io.gone.app", "Library/Preferences/io.acme.other.plist"})
        self.assertIn("same vendor still installed", got["Library/Preferences/io.acme.other.plist"])
        self.assertEqual({j["id"]: j["risk"] for j in mg.JUNK}["app-leftovers"], "review")

    def test_leftover_already_listed_elsewhere_is_counted_once(self):
        """Regression: com.docker.install showed as both 'stuck Docker installer' and an app leftover."""
        inst = os.path.join(self.home, "Library/Application Support/com.docker.install")
        junk = [dict(id="docker-install-tmp", name="d", risk="review", paths=[]),
                dict(id="app-leftovers", name="l", risk="review", special="orphans")]
        fake = {"docker-install-tmp": [(inst + "/in_progress", 2 * GB, "")],
                "app-leftovers": [(inst, 2 * GB, ""), (os.path.join(self.home, "Library/Caches/io.gone.app"), 5, "")]}
        with mock.patch.object(mg, "JUNK", junk), mock.patch.object(mg, "resolve", lambda item, sd=30: fake[item["id"]]):
            res = {r["id"]: r for r in mg.scan_junk()}
        self.assertEqual([os.path.basename(p) for p, _, _ in res["app-leftovers"]["entries"]], ["io.gone.app"])
        self.assertEqual(res["app-leftovers"]["size"], 5)

    def test_cleaning_orphans_uses_trash(self):
        p = os.path.dirname(self.mk("Library/Application Support/io.gone.app/big", 100))
        freed = quiet(mg.clean_item, dict(id="app-leftovers", name="x", special="orphans", entries=[(p, 100, "")]))
        self.assertEqual(freed, 100)
        self.assertEqual(os.listdir(os.path.join(self.home, ".Trash")), ["io.gone.app"])


# ---------------------------------------------------------------- quit app + process tree

class TestKill(TempHome):
    APP = dict(name="Widgetly", bundle_id="io.acme.widgetly", path="/Applications/Widgetly.app", version="1", exe="", updated=0)

    def table(self):
        me, parent = os.getpid(), os.getppid()
        return [dict(pid=1, ppid=0, uid=0, exe="/sbin/launchd"),
                dict(pid=parent, ppid=1, uid=501, exe="/Applications/Widgetly.app/Contents/MacOS/Widgetly"),  # launched us
                dict(pid=me, ppid=parent, uid=501, exe="/usr/bin/python3"),
                dict(pid=100, ppid=1, uid=501, exe="/Applications/Widgetly.app/Contents/MacOS/Widgetly"),
                dict(pid=101, ppid=100, uid=501, exe="/Applications/Widgetly.app/Contents/Frameworks/Widgetly Helper.app/Contents/MacOS/Widgetly Helper"),
                dict(pid=102, ppid=101, uid=501, exe="/usr/bin/python3"),               # child spawned by the helper
                dict(pid=200, ppid=1, uid=0, exe="/Library/PrivilegedHelperTools/io.acme.widgetly.daemon"),
                dict(pid=300, ppid=1, uid=501, exe="/Applications/Widgetly Pro.app/Contents/MacOS/Widgetly Pro"),  # other app
                dict(pid=301, ppid=1, uid=501, exe="/Applications/Safari.app/Contents/MacOS/Safari")]

    def test_process_table_parses_paths_with_spaces(self):
        out = "    1     0     0 /sbin/launchd\n  612   600   501 /Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop\n"
        with mock.patch.object(mg, "run", return_value=(0, out, "")):
            rows = mg.process_table()
        self.assertEqual(rows[1], dict(pid=612, ppid=600, uid=501,
                                       exe="/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop"))

    def test_tree_includes_helpers_children_and_root_helper_but_not_others_or_ourselves(self):
        pids = [p["pid"] for p in mg.app_process_tree(self.APP, self.table())]
        self.assertEqual(pids, [100, 101, 102, 200])

    def test_launch_labels(self):
        out = "PID\tStatus\tLabel\n-\t0\tio.acme.widgetly.update\n812\t0\tio.acme.widgetlypro\n-\t0\tcom.apple.x\n"
        with mock.patch.object(mg, "run", return_value=(0, out, "")):
            self.assertEqual(mg.app_launch_labels(self.APP), ["io.acme.widgetly.update"])

    def test_kill_unloads_agents_then_term_then_kill(self):
        state = {"alive": {100, 101, 102}}
        sent, calls = [], []

        def fake_kill(pid, sig):
            if pid == 200:
                raise PermissionError(1, "not permitted")
            sent.append((pid, sig))
            if sig == 9 or pid != 101:  # the helper ignores TERM, everything dies on KILL
                state["alive"].discard(pid)

        tree = lambda app, table=None: [p for p in self.table() if p["pid"] in state["alive"] | {200}]  # noqa: E731
        with mock.patch.object(mg, "app_process_tree", tree), mock.patch.object(mg.os, "kill", fake_kill), \
                mock.patch.object(mg, "app_launch_labels", return_value=["io.acme.widgetly.update"]), \
                mock.patch.object(mg, "run", side_effect=lambda cmd, timeout=60: calls.append(cmd) or (0, "", "")):
            r = mg.kill_app(self.APP, grace=0.3)
        self.assertEqual(calls[0], ["launchctl", "bootout", f"gui/{os.getuid()}/io.acme.widgetly.update"])
        self.assertIn((101, 9), sent)  # escalated after the grace period
        self.assertNotIn((100, 9), sent)  # exited on TERM, no KILL needed
        self.assertEqual(sorted(p["pid"] for p in r["stopped"]), [100, 101, 102])
        self.assertEqual([p["pid"] for p in r["needs_admin"]], [200])
        self.assertEqual(r["survivors"], [])
        self.assertIn("[kill]", mg.read_text(mg.EVENTS_LOG))

    def test_protected_processes(self):
        with self.assertRaises(ValueError):
            mg.kill_app(dict(self.APP, bundle_id="com.apple.finder", path="/System/Library/CoreServices/Finder.app"))

    def test_kill_real_process_tree(self):
        """End to end: a fake .app whose main process spawns a child; both must be gone afterwards."""
        import subprocess
        import shutil
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("needs a C compiler (Xcode Command Line Tools)")
        bundle = os.path.join(self.tmp, "Sleepy.app")
        exe = os.path.join(bundle, "Contents", "MacOS", "Sleepy")
        os.makedirs(os.path.dirname(exe))
        src = os.path.join(self.tmp, "sleepy.c")
        with open(src, "w") as fh:  # main process inside the bundle forks a child outside it, then waits
            fh.write('#include <unistd.h>\n#include <sys/wait.h>\n'
                     'int main(void){ if (fork()==0) { execl("/bin/sleep","sleep","300",(char*)0); _exit(1);} '
                     'pause(); return 0; }\n')
        subprocess.run([cc, "-o", exe, src], check=True, capture_output=True)
        proc = subprocess.Popen([exe])
        app = dict(name="Sleepy", bundle_id="io.test.sleepy", path=bundle, version="1", exe=exe, updated=0)
        try:
            for _ in range(40):
                if mg.app_process_tree(app):
                    break
                time.sleep(0.05)
            before = mg.app_process_tree(app)
            self.assertTrue(before, "fake app not visible in the process table")
            with mock.patch.object(mg, "app_launch_labels", return_value=[]):
                r = mg.kill_app(app, grace=2)
            self.assertEqual(r["survivors"], [])
            self.assertEqual(mg.app_process_tree(app), [])
        finally:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------- performance

def P(pid, exe, ppid=1, uid=None, cpu=0.0, mem=0, args=None):
    return dict(pid=pid, ppid=ppid, uid=os.getuid() if uid is None else uid, cpu=cpu, mem=mem, exe=exe, args=args or exe)


CHS = "/Users/me/proj/node_modules/.remotion/chrome-headless-shell/mac-arm64/chrome-headless-shell"
PERF_RUN = {  # longer prefixes first: fake_run takes the first prefix that matches
    "docker ps -q": "",
    "ollama ps": "NAME    ID    SIZE    PROCESSOR    UNTIL\n",
    "xcrun simctl list devices booted -j": json.dumps({"devices": {"iOS-26": [{"name": "iPhone 17 Pro", "state": "Booted"}]}}),
    "sysctl -n vm.loadavg": "{ 12.50 8.00 6.00 }",
    "sysctl -n hw.memsize": "17179869184",
    "sysctl -n kern.memorystatus_vm_pressure_level": "2",
    "memory_pressure -Q": "The system has 17179869184 (1048576 pages).\nSystem-wide memory free percentage: 12%\n",
    "sysctl -n vm.swapusage": "total = 8192.00M  used = 6144.00M  free = 2048.00M  (encrypted)",
    "pmset -g therm": "CPU_Scheduler_Limit \t= 100\nCPU_Available_CPUs \t= 10\nCPU_Speed_Limit \t= 70\n",
    "pmset -g batt": "Now drawing from 'Battery Power'\n -InternalBattery-0 (id=1)\t80%; discharging\n",
    "pmset -g": "System-wide power settings:\n lowpowermode         1\n",
}


class TestPerf(TempHome):
    def table(self):
        me, parent = os.getpid(), os.getppid()
        java = "/Library/Java/JavaVirtualMachines/zulu-17.jdk/Contents/Home/bin/java"
        return [P(1, "/sbin/launchd", ppid=0, uid=0),
                P(parent, "/bin/zsh"), P(me, "/usr/bin/python3", ppid=parent),
                P(100, "/Applications/Docker.app/Contents/MacOS/com.docker.backend", cpu=2, mem=500 << 20),
                P(101, "/Applications/Docker.app/Contents/MacOS/Docker Desktop.app/Contents/MacOS/Docker Desktop", ppid=100),
                P(102, "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization."
                       "VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine", cpu=20, mem=2 * GB),
                P(200, "/opt/homebrew/bin/ollama", args="/opt/homebrew/bin/ollama serve", mem=100 << 20),
                P(300, java, cpu=0.5, mem=1536 << 20, args=f"{java} -Xmx2g org.gradle.launcher.daemon.bootstrap.GradleDaemon 8.10"),
                P(310, java, cpu=40, args=f"{java} org.jetbrains.kotlin.daemon.KotlinCompileDaemon --daemon-runFilesPath x"),
                P(400, "/Library/Developer/PrivateFrameworks/CoreSimulator.framework/Resources/bin/launchd_sim"),
                P(401, "/Library/Developer/CoreSimulator/Volumes/iOS_23F77/RuntimeRoot/SpringBoard.app/SpringBoard", ppid=400),
                P(500, "/Applications/Unity Hub.app/Contents/MacOS/Unity Hub", cpu=6),
                P(510, "/Users/me/Library/Android/sdk/emulator/qemu/darwin-aarch64/qemu-system-aarch64", cpu=30),
                # a live MCP server that renders: the server itself is not a render, its render is (and is busy)
                P(650, "node", ppid=parent, args="node /Users/me/proj/apps/remotion-engine/src/mcp/stdio.ts"),
                P(600, "node", ppid=650, args="node /Users/me/proj/node_modules/@remotion/cli/remotion-cli.js render src/index.ts"),
                P(601, CHS, ppid=600, cpu=120),
                # leftovers from a finished render: parent is launchd now
                P(700, CHS, cpu=90, mem=800 << 20), P(701, CHS, ppid=700, cpu=10), P(710, "/opt/homebrew/bin/ffmpeg", cpu=60),
                P(720, "/opt/homebrew/bin/ffmpeg", uid=0, cpu=5),  # someone else's: never ours to stop
                P(799, "/bin/zsh", ppid=parent),
                P(800, "node", ppid=799, args="node /Users/me/web/node_modules/.bin/vite --port 5173"),
                P(801, "/Users/me/web/node_modules/@esbuild/darwin-arm64/bin/esbuild", ppid=800, args="esbuild --service=0.21.5 --ping"),
                P(900, "/Users/me/bin/stray-worker", cpu=3), P(901, "/Users/me/bin/stray-child", ppid=900),
                P(910, "/Users/me/bin/my-agent"),  # started by launchd on purpose
                P(930, "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Support/mds_stores",
                  uid=0, cpu=50, mem=300 << 20),
                P(950, "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", cpu=10, mem=3 * GB)]

    JOBS = {200: "homebrew.mxcl.ollama", 910: "com.me.agent"}

    def items(self, extra=None, which=("docker", "ollama")):
        runs = dict(extra or {}, **{k: v for k, v in PERF_RUN.items() if k not in (extra or {})})
        with mock.patch.object(mg, "run", fake_run(runs)), \
                mock.patch.object(mg.shutil, "which", lambda n: f"/usr/local/bin/{n}" if n in which else None):
            return {it["id"]: it for it in mg.dev_items(self.table(), dict(self.JOBS))}

    @staticmethod
    def pids(it):
        return sorted(p["pid"] for p in it["procs"])

    @staticmethod
    def targets(it):
        return sorted(pid for kind, what in it["stop"] if kind == "term" for pid in what)

    def test_perf_table_parses_ps_and_args(self):
        ps = ("  456     1    88  45.6  58032 /System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer\n"
              " 1025   947   501  25.7 1259776 /Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/"
              "Contents/MacOS/Google Chrome Helper\n 1177  1080   501   0.0  9000 node\ngarbage\n")
        args = "  456 WindowServer -daemon\n 1177 node /x/node_modules/.bin/vite --port 5173\n"
        out = lambda cmd, timeout=60: (0, args if "args=" in " ".join(cmd) else ps, "")  # noqa: E731
        with mock.patch.object(mg, "run", out):
            rows = mg.perf_table()
        self.assertEqual([r["pid"] for r in rows], [456, 1025, 1177])
        self.assertEqual((rows[1]["cpu"], rows[1]["mem"]), (25.7, 1259776 * 1024))
        self.assertTrue(rows[1]["exe"].endswith("Google Chrome Helper"))
        self.assertEqual(rows[1]["args"], rows[1]["exe"])  # no args row -> falls back to the path
        self.assertEqual(rows[2]["args"], "node /x/node_modules/.bin/vite --port 5173")

    def test_parse_therm(self):
        self.assertEqual(mg.parse_therm("Note: No thermal warning level has been recorded\n"
                                        "Note: No performance warning level has been recorded\n")["state"], "nominal")
        self.assertEqual(mg.parse_therm(PERF_RUN["pmset -g therm"])["state"], "throttled")
        self.assertEqual(mg.parse_therm(PERF_RUN["pmset -g therm"])["speed_limit"], 70)
        self.assertEqual(mg.parse_therm("CPU_Speed_Limit = 100\nThermal warning level set to 2.\n")["state"], "warning")

    def test_system_load(self):
        with mock.patch.object(mg, "run", fake_run(PERF_RUN)):
            s = mg.system_load()
        self.assertEqual(s["load"], [12.5, 8.0, 6.0])
        self.assertEqual((s["pressure"], s["mem_free_pct"], s["mem_total"]), ("warning", 12, 16 * GB))
        self.assertEqual((s["swap_used"], s["swap_total"]), (6 * GB, 8 * GB))
        self.assertEqual(s["thermal"]["state"], "throttled")
        self.assertTrue(s["low_power"] and s["on_battery"])

    def test_groups_known_dev_daemons(self):
        items = self.items()
        self.assertEqual(self.pids(items["docker"]), [100, 101, 102])  # the Linux VM counts as Docker's
        self.assertEqual(self.pids(items["ollama"]), [200])
        self.assertEqual(self.pids(items["gradle"]), [300])
        self.assertEqual(self.pids(items["kotlin"]), [310])
        self.assertEqual(self.pids(items["simulators"]), [400, 401])
        self.assertEqual(self.pids(items["unity"]), [500])
        self.assertEqual(self.pids(items["android-emulator"]), [510])
        self.assertEqual(self.pids(items["spotlight"]), [930])
        self.assertEqual(self.pids(items["render"]), [600, 601, 720])  # the MCP server (650) is not a render
        self.assertEqual(self.pids(items["leftover-renders"]), [700, 701, 710])
        self.assertEqual(self.pids(items["node-dev"]), [800, 801])  # esbuild joins the vite server that started it
        self.assertEqual(self.pids(items["orphans"]), [900, 901])  # 910 is a launchd job, not an orphan
        self.assertEqual(items["docker"]["mem"], 500 * 2 ** 20 + 2 * GB)

    def test_safe_or_review(self):
        items = self.items()
        risk = {k: v["risk"] for k, v in items.items()}
        self.assertEqual(risk, {"docker": "safe", "ollama": "safe", "gradle": "safe", "kotlin": "review", "simulators": "safe",
                                "unity": "review", "android-emulator": "review", "spotlight": "system", "render": "review",
                                "leftover-renders": "safe", "node-dev": "review", "orphans": "review"})
        self.assertIn("idle", items["docker"]["why"])
        self.assertIn("iPhone 17 Pro", items["simulators"]["why"])
        self.assertTrue(items["leftover-renders"]["orphan"])
        self.assertFalse(items["docker"]["orphan"])
        busy = self.items({"docker ps -q": "abc\ndef\n", "ollama ps": "NAME ID SIZE\nllama3:8b 1 5GB\n"})
        self.assertEqual((busy["docker"]["risk"], busy["ollama"]["risk"]), ("review", "review"))
        self.assertIn("2 container", busy["docker"]["why"])
        self.assertIn("llama3:8b", busy["ollama"]["why"])
        unknown = self.items(which=())  # no docker/ollama CLI: can't tell if idle -> review
        self.assertEqual((unknown["docker"]["risk"], unknown["ollama"]["risk"]), ("review", "review"))

    def test_spotlight_only_while_busy(self):
        table = [P(930, "/System/Library/Metadata.framework/Support/mds_stores", uid=0, cpu=1)]
        with mock.patch.object(mg, "run", fake_run(PERF_RUN)):
            self.assertEqual(mg.dev_items(table, {}), [])

    def test_stop_steps_and_restart_hints(self):
        items = self.items(which=("docker", "ollama", "gradle"))
        self.assertEqual(items["docker"]["stop"], [("quit", "Docker")])
        self.assertEqual(items["docker"]["start"], "open -a Docker")
        self.assertEqual(items["ollama"]["stop"], [("cmd", ["launchctl", "bootout", f"gui/{os.getuid()}/homebrew.mxcl.ollama"])])
        self.assertEqual(items["ollama"]["start"], "brew services start ollama")
        self.assertEqual(items["gradle"]["stop"], [("cmd", ["gradle", "--stop"]), ("term", [300])])
        self.assertEqual(items["simulators"]["stop"], [("cmd", ["xcrun", "simctl", "shutdown", "all"])])
        self.assertEqual(items["spotlight"]["stop"], [])
        for it in items.values():
            self.assertTrue(it["start"] or it["risk"] == "system", it["id"])

    def test_never_targets_system_root_or_session(self):
        items = self.items()
        targets = {pid for it in items.values() for pid in self.targets(it)}
        for pid in (1, os.getpid(), os.getppid(), 102, 401, 720, 930):
            self.assertNotIn(pid, targets)
        self.assertEqual(self.targets(items["leftover-renders"]), [700, 701, 710])
        self.assertEqual(self.targets(items["render"]), [600, 601])
        steps = [what for it in items.values() for kind, what in it["stop"] if kind == "cmd"]
        self.assertFalse(any("sudo" in cmd for cmd in steps))

    def test_findings(self):
        state = dict(cores=10, load=[12.5, 8, 6], pressure="critical", mem_free_pct=4, mem_total=16 * GB, swap_used=6 * GB,
                     swap_total=8 * GB, thermal=dict(state="throttled", speed_limit=70, detail="CPU speed limited to 70%"),
                     low_power=True, on_battery=True)
        items = list(self.items().values())
        disk = dict(free=100 * GB, total=1000 * GB)
        titles = {t: s for s, t, _ in mg.perf_findings(state, items, disk)}
        self.assertEqual(titles["The Mac is hot and throttling the CPU"], "high")
        self.assertEqual(titles["Memory pressure is critical"], "high")
        self.assertEqual(titles["Heavy swap use"], "medium")
        self.assertEqual(titles["CPU is saturated"], "medium")
        self.assertEqual(titles["Leftover render helpers still running"], "medium")
        self.assertEqual(titles["Orphaned processes (their parent has exited)"], "low")
        self.assertEqual(titles["Spotlight is indexing"], "info")
        self.assertEqual(titles["Low Power Mode is on"], "low")
        self.assertEqual(titles[f"Stopping Docker Desktop frees {mg.human(500 * 2 ** 20 + 2 * GB)}"], "low")
        self.assertNotIn("Running on battery", titles)  # only in --before heavy
        calm = dict(state, load=[1, 1, 1], pressure="normal", swap_used=0, low_power=False,
                    thermal=dict(state="nominal", speed_limit=None, detail=""))
        self.assertEqual(mg.perf_findings(calm, [], disk), [])

    def test_before_heavy(self):
        state = dict(cores=10, load=[1, 1, 1], pressure="normal", mem_free_pct=50, mem_total=16 * GB, swap_used=0, swap_total=0,
                     thermal=dict(state="nominal", speed_limit=None, detail=""), low_power=True, on_battery=True)
        f = {t: s for s, t, _ in mg.perf_findings(state, [], dict(free=20 * GB, total=500 * GB), before="heavy")}
        self.assertEqual(f["Not much free space for a big build"], "medium")
        self.assertEqual(f["Low Power Mode is on"], "medium")
        self.assertEqual(f["Running on battery"], "low")
        f = {t: s for s, t, _ in mg.perf_findings(state, [], dict(free=10 * GB, total=500 * GB), before="heavy")}
        self.assertEqual(f["Not much free space for a big build"], "high")
        f = {t for _, t, _ in mg.perf_findings(state, [], dict(free=200 * GB, total=500 * GB), before="heavy")}
        self.assertNotIn("Not much free space for a big build", f)

    def test_heavy_suggestions(self):
        items = self.items()
        with mock.patch.object(mg, "session_pids", return_value={1, 960}):
            owners = mg.top_owners(self.table() + [P(960, "/Applications/Claude.app/Contents/MacOS/Claude", mem=4 * GB)],
                                   list(items.values()))
        s = "\n".join(mg.heavy_suggestions(list(items.values()), owners))
        self.assertIn("Stop Docker Desktop", s)
        self.assertIn("Close Android emulator", s)
        self.assertIn("Quit Google Chrome", s)
        self.assertNotIn("Unity", s)  # the build you are about to run
        self.assertNotIn("Claude", s)  # runs this session
        self.assertIn("Spotlight", s)

    def test_top_owners(self):
        owners = {o["name"]: o for o in mg.top_owners(self.table(), list(self.items().values()))}
        self.assertEqual(owners["Spotlight indexing"]["kind"], "system")
        self.assertEqual(owners["Google Chrome"]["kind"], "app")
        self.assertEqual(owners["Video renders (Remotion, headless Chrome, ffmpeg)"]["cpu"], 125)
        self.assertEqual(owners["Leftover render helpers (parent gone)"]["count"], 3)

    def test_plan(self):
        items = list(self.items().values())
        self.assertEqual(sorted(it["id"] for it in mg.perf_plan(items)),
                         ["docker", "gradle", "leftover-renders", "ollama", "simulators"])
        self.assertEqual([it["id"] for it in mg.perf_plan(items, {"unity", "spotlight", "nope"})], ["unity"])

    def test_apply_runs_steps_logs_and_never_sudo(self):
        calls = []
        plan = mg.perf_plan(list(self.items(which=("docker", "ollama", "gradle")).values()))
        with mock.patch.object(mg, "run", side_effect=lambda cmd, timeout=60: calls.append(cmd) or (0, "", "")), \
                mock.patch.object(mg, "stop_pids", return_value=3) as sp:
            res = {r["id"]: r for r in mg.apply_perf(plan)}
        self.assertIn(["osascript", "-e", 'quit app "Docker"'], calls)
        self.assertIn(["xcrun", "simctl", "shutdown", "all"], calls)
        self.assertIn(["gradle", "--stop"], calls)
        self.assertFalse(any("sudo" in c for c in calls))
        self.assertEqual(sorted(c.args[0] for c in sp.call_args_list), [[300], [700, 701, 710]])
        self.assertTrue(all(r["ok"] for r in res.values()))
        self.assertEqual(res["docker"]["start"], "open -a Docker")
        self.assertIn("ended 3 process(es)", res["leftover-renders"]["detail"])
        self.assertIn("[perf] stopped docker", mg.read_text(mg.EVENTS_LOG))

    def test_stop_pids_rechecks_before_signalling(self):
        before = [P(700, CHS), P(701, CHS, ppid=700), P(702, CHS), P(720, "/opt/homebrew/bin/ffmpeg", uid=0)]
        now = [P(700, "/Users/me/other-program"),  # pid reused since the snapshot
               P(701, CHS, ppid=700), P(702, CHS), P(720, "/opt/homebrew/bin/ffmpeg", uid=0)]
        alive, sent = {701, 702}, []

        def fake_kill(pid, sig):
            if sig == 0:
                if pid not in alive:
                    raise ProcessLookupError
                return
            sent.append((pid, sig))
            if sig == 9 or pid == 701:  # 702 ignores TERM
                alive.discard(pid)
        with mock.patch.object(mg, "perf_table", return_value=now), mock.patch.object(mg.os, "kill", fake_kill):
            n = mg.stop_pids([700, 701, 702, 720], before, grace=0.3)
        self.assertEqual(n, 2)
        self.assertNotIn(700, {p for p, _ in sent})
        self.assertNotIn(720, {p for p, _ in sent})
        self.assertIn((702, 9), sent)
        self.assertNotIn((701, 9), sent)

    def report(self):
        items = list(self.items().values())
        state = dict(cores=10, load=[1, 1, 1], pressure="normal", mem_free_pct=50, mem_total=16 * GB, swap_used=0, swap_total=0,
                     thermal=dict(state="nominal", speed_limit=None, detail=""), low_power=False, on_battery=False)
        return dict(state=state, items=items, owners=mg.top_owners(self.table(), items), disk=dict(free=100 * GB, total=500 * GB),
                    before=None, findings=[("medium", "Leftover render helpers still running", "x")], suggestions=[])

    def test_cmd_perf_dry_run_and_confirm(self):
        args = argparse.Namespace(focus=False, resume=False, before=None, apply=False, only=None, yes=False)
        with mock.patch.object(mg, "perf_report", return_value=self.report()), mock.patch.object(mg, "apply_perf") as ap:
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_perf(args)
            self.assertIn("macguard perf --apply", out.getvalue())
            self.assertIn("review items need --only", out.getvalue())
            with mock.patch("builtins.input", return_value="no"):
                quiet(mg.cmd_perf, argparse.Namespace(focus=False, resume=False, before=None, apply=True, only=None, yes=False))
            ap.assert_not_called()
            ap.return_value = [dict(id="docker", name="Docker Desktop", ok=True, detail="asked Docker to quit", start="open -a Docker")]
            out = io.StringIO()
            with mock.patch("builtins.input", return_value="yes"), redirect_stdout(out):
                mg.cmd_perf(argparse.Namespace(focus=False, resume=False, before=None, apply=True, only="docker,unity", yes=False))
        self.assertEqual([it["id"] for it in ap.call_args.args[0]], ["docker", "unity"])
        self.assertIn("start again: open -a Docker", out.getvalue())


class TestFocus(TempHome):
    def table(self):
        me, parent = os.getpid(), os.getppid()
        A = "/Applications/{0}.app/Contents/MacOS/{0}".format
        return [P(1, "/sbin/launchd", ppid=0, uid=0),
                P(parent, A("Launcher"), cpu=5), P(me, "/usr/bin/python3", ppid=parent),  # runs this tool
                P(120, "/Applications/Launcher.app/Contents/MacOS/Launcher Helper", ppid=parent, cpu=1),
                P(100, A("Google Chrome"), cpu=5, mem=GB),
                P(101, "/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Helper.app/Contents/MacOS/"
                       "Google Chrome Helper", ppid=100, cpu=2),
                P(200, A("Slack"), cpu=1),
                P(210, A("Spotify"), cpu=3),                    # in focus_allow
                P(220, A("Dropbox"), cpu=0.1, mem=10 << 20),    # too small to bother
                P(300, A("Unity Hub"), cpu=10),                 # dev tool
                P(310, A("Terminal")), P(311, "/bin/zsh", ppid=310),
                P(320, A("Raycast"), cpu=2),                    # never paused
                P(330, A("Widgetly"), cpu=2), P(331, "/opt/homebrew/bin/node", ppid=330),  # starts a dev process
                P(340, A("Ollama"), cpu=1),
                P(350, A("Safari"), cpu=4),                     # frontmost
                P(370, A("Root Thing"), uid=0, cpu=50),         # someone else's
                P(380, "/System/Applications/Music.app/Contents/MacOS/Music", cpu=5)]  # macOS

    def plan(self, **kw):
        kw = dict(dict(front=350, allow=("spotify",), ollama_idle=False), **kw)
        return mg.focus_plan(self.table(), **kw)

    def test_plan_pauses_only_non_dev_apps(self):
        plan = self.plan()
        self.assertEqual([g["name"] for g in plan["pause"]], ["Google Chrome", "Slack"])
        self.assertEqual(sorted(p["pid"] for p in plan["pause"][0]["procs"]), [100, 101])  # helpers go with their app
        kept = {k["name"]: k["reason"] for k in plan["kept"]}
        self.assertEqual(kept["Unity Hub"], "development tool")
        self.assertEqual(kept["Terminal"], "development tool")
        self.assertIn("input", kept["Raycast"])
        self.assertEqual(kept["Spotify"], "in your focus_allow setting")
        self.assertEqual(kept["Widgetly"], "runs node")
        self.assertEqual(kept["Safari"], "the app in front")
        self.assertEqual(kept["Launcher"], "runs this tool")
        self.assertEqual(kept["Ollama"], "serving a model")
        names = {g["name"] for g in plan["pause"]} | set(kept)
        for n in ("Dropbox", "Root Thing", "Music"):
            self.assertNotIn(n, names)
        self.assertIn("Ollama", [g["name"] for g in self.plan(ollama_idle=True)["pause"]])
        self.assertIn("Safari", [g["name"] for g in self.plan(front=None)["pause"]])

    def test_pause_records_and_resume_rechecks(self):
        sent = []
        with mock.patch.object(mg, "perf_table", return_value=self.table()), mock.patch.object(mg, "start_focus_timer") as timer, \
                mock.patch.object(mg.os, "kill", lambda pid, sig: sent.append((pid, sig))):
            paused, until = mg.focus_pause(self.plan()["pause"], 4)
            self.assertEqual(sorted((p, s) for p, s in sent), [(100, mg.signal.SIGSTOP), (101, mg.signal.SIGSTOP), (200, mg.signal.SIGSTOP)])
            timer.assert_called_once()
            state = mg.load_focus()
            self.assertEqual((len(state["paused"]), state["source"]), (3, "cli"))
            self.assertAlmostEqual(until, time.time() + 4 * 3600, delta=5)
            self.assertNotIn("Google Chrome", [g["name"] for g in self.plan()["pause"]])  # already paused: not again
            self.assertTrue(mg.focus_status()["active"])
        sent.clear()
        reused = [P(200, "/Users/me/other")] + [p for p in self.table() if p["pid"] != 200]
        with mock.patch.object(mg, "perf_table", return_value=reused), \
                mock.patch.object(mg.os, "kill", lambda pid, sig: sent.append((pid, sig))):
            resumed = mg.focus_resume()
        self.assertEqual(sorted(sent), [(100, mg.signal.SIGCONT), (101, mg.signal.SIGCONT)])  # 200 is someone else now
        self.assertEqual(len(resumed), 2)
        self.assertIsNone(mg.load_focus())
        self.assertIn("[focus] resumed 2", mg.read_text(mg.EVENTS_LOG))

    def test_pause_skips_reused_or_protected_pids(self):
        now = [P(100, "/Users/me/other")] + [p for p in self.table() if p["pid"] != 100]
        sent = []
        with mock.patch.object(mg, "perf_table", return_value=now), mock.patch.object(mg, "start_focus_timer"), \
                mock.patch.object(mg.os, "kill", lambda pid, sig: sent.append(pid)):
            mg.focus_pause(self.plan()["pause"] + [dict(name="Launcher", procs=[P(os.getppid(), "/Applications/Launcher.app/"
                                                                                   "Contents/MacOS/Launcher")])], 4)
        self.assertEqual(sorted(sent), [101, 200])

    def test_auto_resume_after_timeout(self):
        mg.ensure_state()
        mg.write_json(mg.focus_file(), dict(paused=[dict(pid=200, exe="/Applications/Slack.app/Contents/MacOS/Slack", name="Slack")],
                                            until=time.time() + 3600, source="cli"))
        sent = []
        with mock.patch.object(mg, "perf_table", return_value=self.table()), \
                mock.patch.object(mg.os, "kill", lambda pid, sig: sent.append((pid, sig))):
            self.assertIsNone(mg.focus_check_expired())
            self.assertEqual(sent, [])
            state = mg.load_focus()
            mg.write_json(mg.focus_file(), dict(state, until=time.time() - 1))
            mg.focus_check_expired()
        self.assertEqual(sent, [(200, mg.signal.SIGCONT)])
        self.assertIsNone(mg.load_focus())

    def test_focus_timer_resumes_at_deadline(self):
        mg.ensure_state()
        mg.write_json(mg.focus_file(), dict(paused=[dict(pid=200, exe="/Applications/Slack.app/Contents/MacOS/Slack", name="Slack")],
                                            until=time.time() + 0.2, source="ui"))
        sent = []
        with mock.patch.object(mg, "perf_table", return_value=self.table()), \
                mock.patch.object(mg.os, "kill", lambda pid, sig: sent.append((pid, sig))):
            mg.cmd_focus_timer(None)
        self.assertEqual(sent, [(200, mg.signal.SIGCONT)])
        mg.cmd_focus_timer(None)  # nothing paused: returns straight away

    def test_frontmost_pid(self):
        runs = {"lsappinfo front": "ASN:0x0-0x1a01a:\n", "lsappinfo info": '"LSDisplayName"="Claude"\n pid = 947 !cgsConnection\n'}
        with mock.patch.object(mg, "run", fake_run(runs)):
            self.assertEqual(mg.frontmost_pid(), 947)
        with mock.patch.object(mg, "run", fake_run({})):
            self.assertIsNone(mg.frontmost_pid())

    def test_settings_focus_allow_and_hours(self):
        with mock.patch.object(mg, "install_agent") as inst, mock.patch.object(mg, "remove_agent") as rem:
            quiet(mg.cmd_settings, argparse.Namespace(key="focus_allow", value="Spotify, Figma ,"))
            quiet(mg.cmd_settings, argparse.Namespace(key="focus_hours", value="2"))
            inst.assert_not_called()
            rem.assert_not_called()
        s = mg.load_settings()
        self.assertEqual((s["focus_allow"], s["focus_hours"]), (["spotify", "figma"], 2))
        self.assertEqual(mg.focus_status()["hours"], 2)

    def test_cmd_focus_dry_run_confirm_and_resume(self):
        plan = self.plan()
        args = lambda **kw: argparse.Namespace(**dict(dict(focus=True, resume=False, apply=False, yes=False, before=None, only=None), **kw))  # noqa: E731
        with mock.patch.object(mg, "focus_snapshot", return_value=(self.table(), plan)), \
                mock.patch.object(mg, "focus_pause", return_value=([dict(pid=100, exe="x", name="Google Chrome")], time.time())) as fp:
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_perf(args())
            self.assertIn("Dry run", out.getvalue())
            self.assertIn("Unity Hub (development tool)", out.getvalue())
            with mock.patch("builtins.input", return_value="no"):
                quiet(mg.cmd_perf, args(apply=True))
            fp.assert_not_called()
            out = io.StringIO()
            with mock.patch("builtins.input", return_value="yes"), redirect_stdout(out):
                mg.cmd_perf(args(apply=True))
            fp.assert_called_once()
            self.assertIn("Not Responding", out.getvalue())
            self.assertIn("macguard perf --resume", out.getvalue())
        with mock.patch.object(mg, "focus_resume", return_value=[dict(pid=1, exe="x", name="Slack")]) as fr:
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_perf(args(focus=False, resume=True))
        fr.assert_called_once()
        self.assertIn("Resumed 1 process(es): Slack", out.getvalue())

    def test_pause_and_resume_real_process(self):
        """End to end: a tiny app binary is really stopped (ps state T) and continues on resume."""
        import subprocess
        cc = shutil.which("cc")
        if not cc:
            self.skipTest("needs a C compiler (Xcode Command Line Tools)")
        exe = os.path.join(self.tmp, "Busy.app", "Contents", "MacOS", "Busy")
        os.makedirs(os.path.dirname(exe))
        src = os.path.join(self.tmp, "busy.c")
        with open(src, "w") as fh:
            fh.write("#include <unistd.h>\nint main(void){ sleep(120); return 0; }\n")
        subprocess.run([cc, "-o", exe, src], check=True, capture_output=True)
        proc = subprocess.Popen([exe])
        state = lambda: subprocess.run(["ps", "-o", "state=", "-p", str(proc.pid)], capture_output=True, text=True).stdout.strip()  # noqa: E731
        try:
            for _ in range(40):
                procs = [p for p in mg.perf_table() if p["pid"] == proc.pid and p["exe"].endswith("/Busy")]
                if procs:
                    break
                time.sleep(0.05)
            self.assertTrue(procs, "test app not visible in the process table")
            with mock.patch.object(mg, "start_focus_timer"):
                paused, _ = mg.focus_pause([dict(name="Busy", procs=procs)], 1)
            self.assertEqual(len(paused), 1)
            self.assertTrue(state().startswith("T"), state())
            self.assertEqual(len(mg.focus_resume()), 1)
            time.sleep(0.1)
            self.assertFalse(state().startswith("T"), state())
        finally:
            proc.kill()
            proc.wait()


# ---------------------------------------------------------------- traffic

def SOCK(pid, proc, rhost, rport, rx, tx, state="ESTABLISHED", lport=50000):
    return dict(proto="tcp4", lhost="192.168.1.10", lport=lport, rhost=rhost, rport=rport, state=state, proc=proc, pid=pid,
                rx=rx, tx=tx)


class TestTraffic(unittest.TestCase):
    def setUp(self):
        for p in (mock.patch.object(mg, "signature", lambda path: "unsigned" if "evil" in path else "apple"),
                  mock.patch.object(mg, "exe_path", lambda pid: {1: "/Applications/Up.app/Contents/MacOS/uploader",
                                                                 2: "/Applications/Dropbox.app/Contents/MacOS/Dropbox",
                                                                 3: "/tmp/x/evil",
                                                                 4: "/opt/evil/scanner",
                                                                 5: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}.get(pid, "")),
                  mock.patch.object(mg.time, "sleep", lambda s: None)):
            p.start()
            self.addCleanup(p.stop)

    def sample(self, before, after, seconds=5):
        with mock.patch.object(mg, "sockets", side_effect=[before, after]):
            return mg.traffic_sample(seconds)

    def test_sample_computes_rates_and_hosts(self):
        procs = self.sample([SOCK(1, "uploader", "34.1.1.1", 443, 1000, 1000)],
                            [SOCK(1, "uploader", "34.1.1.1", 443, 6000, 51000), SOCK(1, "uploader", "34.1.1.2", 443, 0, 5000, lport=50001)])
        p = procs[0]
        self.assertEqual((p["rx"], p["tx"], p["new"]), (5000, 55000, 1))
        self.assertEqual(p["tx_rate"], 11000)
        self.assertEqual(p["hosts"], {"34.1.1.1", "34.1.1.2"})
        self.assertEqual(p["proc"], "uploader")
        self.assertEqual(mg.traffic_json(procs)[0]["hosts"], 2)

    def titles(self, after, seconds=5):
        return {(s, t) for s, t, _ in mg.analyze_traffic(self.sample([], after, seconds), seconds)}

    def test_heavy_upload_flagged_but_not_for_backup_apps(self):
        big = 20 * 1024 ** 2
        t = self.titles([SOCK(1, "uploader", "34.1.1.1", 443, 1000, big)])
        self.assertIn(("medium", "Heavy upload (possible data exfiltration)"), t)
        self.assertEqual(self.titles([SOCK(2, "Dropbox", "34.1.1.1", 443, 1000, big)]), set())

    def test_temp_dir_program_online(self):
        self.assertIn(("high", "Program in a temp/download folder is using the internet"),
                      self.titles([SOCK(3, "evil", "45.1.1.1", 443, 10, 10)]))

    def test_outbound_scan(self):
        conns = [SOCK(4, "scanner", f"45.1.1.{i}", 22, 0, 60, state="SYN_SENT", lport=50000 + i) for i in range(12)]
        t = self.titles(conns)
        self.assertIn(("high", "Outbound scanning: port 22 on 12 hosts"), t)
        self.assertIn(("medium", "Many connection attempts not answered (scanner or C2 retry)"), t)
        self.assertIn(("medium", "Unsigned program is using the internet"), t)

    def test_suspicious_and_uncommon_ports(self):
        self.assertIn(("high", "Traffic to suspicious port 4444 (metasploit default)"),
                      self.titles([SOCK(1, "uploader", "45.1.1.1", 4444, 10, 10)]))
        self.assertIn(("low", "Traffic on uncommon ports"), self.titles([SOCK(1, "uploader", "45.1.1.1", 7777, 10, 10)]))

    def test_browser_many_hosts_is_normal(self):
        conns = [SOCK(5, "Google Chrome", f"34.1.{i // 250}.{i % 250}", 443, 100, 100, lport=40000 + i) for i in range(60)]
        self.assertEqual(self.titles(conns), set())

    def test_private_traffic_ignored(self):
        self.assertEqual(self.titles([SOCK(1, "uploader", "192.168.1.20", 7777, 10, 10)]), set())


# ---------------------------------------------------------------- docker / space insights

DOCKER = {
    "system df": [{"Type": "Images", "Reclaimable": "1GB"}, {"Type": "Build Cache", "Reclaimable": "8.231GB", "TotalCount": "136"}],
    "ps -a --filter status=exited --filter status=created --size": [
        {"ID": "62ddaa677671aa", "Names": "shop-local-migrate-1", "Image": "shop-api:local", "Status": "Exited (0) 9 hours ago",
         "Size": "201kB (virtual 3.6GB)"}],
    "ps -a": [{"ID": "1", "Image": "shop-api:local", "ImageID": "sha256:aaaaaaaaaaaa", "Mounts": "dbdata"},
              {"ID": "2", "Image": "postgres:15-alpine", "ImageID": "sha256:bbbbbbbbbbbb", "Mounts": ""}],
    "images --no-trunc": [
        {"ID": "sha256:aaaaaaaaaaaa1", "Repository": "shop-api", "Tag": "local", "Size": "4.84GB", "CreatedSince": "9 hours ago"},
        {"ID": "sha256:bbbbbbbbbbbb2", "Repository": "postgres", "Tag": "15-alpine", "Size": "408MB", "CreatedSince": "10 days ago"},
        {"ID": "sha256:cccccccccccc3", "Repository": "browserbox", "Tag": "latest-browser", "Size": "4.3GB", "CreatedSince": "3 days ago"},
        {"ID": "sha256:dddddddddddd4", "Repository": "<none>", "Tag": "<none>", "Size": "552MB", "CreatedSince": "6 hours ago"}],
    "volume ls --filter dangling=true": [{"Name": "f6829d57d1b7229a555fbbe71e4e4c8d984e99ad6fd5063ed9daf107859b84c9", "Driver": "local"}],
    "system df -v": [{"Volumes": [{"Name": "f6829d57d1b7229a555fbbe71e4e4c8d984e99ad6fd5063ed9daf107859b84c9", "Size": "73.5MB"}]}],
}


def docker_run(calls):
    def _run(cmd, timeout=60):
        calls.append(cmd)
        if cmd[:1] == ["docker"] and cmd[-2:] == ["--format", "{{json .}}"]:
            rows = DOCKER.get(" ".join(cmd[1:-2]), [])
            return 0, "\n".join(json.dumps(r) for r in rows), ""
        return 0, "", ""
    return _run


class TestDocker(unittest.TestCase):
    def setUp(self):
        self.calls = []
        for p in (mock.patch.object(mg, "run", docker_run(self.calls)),
                  mock.patch.object(mg.shutil, "which", return_value="/usr/local/bin/docker")):
            p.start()
            self.addCleanup(p.stop)

    def test_docker_size(self):
        self.assertEqual(mg.docker_size("1.01GB"), 1010000000)
        self.assertEqual(mg.docker_size("201kB (virtual 3.6GB)"), 201000)
        self.assertEqual(mg.docker_size(""), 0)

    def test_categories(self):
        e = {k: mg.docker_entries(k) for k in ("docker-build-cache", "docker-dangling", "docker-stopped",
                                               "docker-unused-images", "docker-unused-volumes")}
        self.assertEqual(e["docker-build-cache"], [("build cache", 8231000000, "136 entries")])
        self.assertEqual([x[0] for x in e["docker-dangling"]], ["<none> (dddddddddddd)"])
        self.assertEqual([x[0] for x in e["docker-stopped"]], ["shop-local-migrate-1 (62ddaa677671)"])
        # in-use images (by name or id) are never offered; only browserbox is unused
        self.assertEqual([x[0] for x in e["docker-unused-images"]], ["browserbox:latest-browser (cccccccccccc)"])
        self.assertEqual(e["docker-unused-volumes"][0][1], 73500000)

    def test_categories_have_correct_risk(self):
        risk = {j["id"]: j["risk"] for j in mg.JUNK}
        self.assertEqual(risk["docker-build-cache"], "safe")
        self.assertEqual(risk["docker-dangling"], "safe")
        for k in ("docker-stopped", "docker-unused-images", "docker-unused-volumes"):
            self.assertEqual(risk[k], "review", k)

    def test_clean_removes_exactly_listed_ids_without_force(self):
        entries = mg.docker_entries("docker-unused-images")
        quiet(mg.docker_clean, "docker-unused-images", entries)
        rm = [c for c in self.calls if c[:2] == ["docker", "rmi"]]
        self.assertEqual(rm, [["docker", "rmi", "cccccccccccc"]])
        self.assertFalse(any("-f" in c or "--force" in c for c in rm))

    def test_clean_volume_uses_full_name(self):
        entries = mg.docker_entries("docker-unused-volumes")
        freed = quiet(mg.docker_clean, "docker-unused-volumes", entries)
        self.assertIn(["docker", "volume", "rm", DOCKER["volume ls --filter dangling=true"][0]["Name"]], self.calls)
        self.assertEqual(freed, 73500000)

    def test_clean_stopped_and_build_cache(self):
        quiet(mg.docker_clean, "docker-stopped", mg.docker_entries("docker-stopped"))
        quiet(mg.docker_clean, "docker-build-cache", mg.docker_entries("docker-build-cache"))
        self.assertIn(["docker", "rm", "62ddaa677671"], self.calls)
        self.assertIn(["docker", "builder", "prune", "-a", "-f"], self.calls)

    def test_no_docker_engine_means_nothing_listed(self):
        with mock.patch.object(mg, "run", return_value=(1, "", "Cannot connect to the Docker daemon")):
            self.assertEqual(mg.docker_entries("docker-unused-images"), [])


GB = 1024 ** 3


class TestSpaceInsights(TempHome):
    def test_disk_health_thresholds(self):
        h = lambda free, total=228 * GB: mg.disk_health({"total": total, "used": total - free, "free": free})  # noqa: E731
        self.assertFalse(h(65 * GB)["low"])
        self.assertTrue(h(9 * GB, total=100 * GB)["low"])
        self.assertFalse(h(9 * GB, total=100 * GB)["critical"])
        self.assertTrue(h(3.9 * GB)["critical"])
        self.assertTrue(h(40 * GB, total=1000 * GB)["low"])  # under 10% even with plenty of GB

    def test_growth_compares_with_snapshot_an_hour_old(self):
        with mock.patch.object(mg.time, "time", return_value=1000.0):
            self.assertEqual(mg.record_sizes({"~/Library/Containers/com.docker.docker": GB // 5, "~/DEV": 8 * GB}), [])
        now = {"~/Library/Containers/com.docker.docker": 40 * GB, "~/DEV": 17 * GB, "~/DEV/creator-studio": 6 * GB}
        with mock.patch.object(mg.time, "time", return_value=1000.0 + 600):  # 10 minutes later: too soon
            self.assertEqual(mg.growth(now, mg.record_sizes(now)), (None, []))
        with mock.patch.object(mg.time, "time", return_value=1000.0 + 7200):
            since, rows = mg.growth(now, mg.record_sizes(now))
        self.assertEqual(since, 1000.0 + 600)  # newest snapshot that's at least an hour old
        self.assertEqual(rows, [])  # nothing changed since that one
        hist = [{"t": 0, "sizes": {"~/Library/Containers/com.docker.docker": GB // 5, "~/DEV": 8 * GB}}]
        with mock.patch.object(mg.time, "time", return_value=7200.0):
            since, rows = mg.growth(now, hist)
        self.assertEqual(rows[0][0], "~/Library/Containers/com.docker.docker")
        # ~/DEV is dropped because its child ~/DEV/creator-studio explains the growth
        self.assertEqual([r[0] for r in rows], ["~/Library/Containers/com.docker.docker", "~/DEV/creator-studio"])

    def test_history_is_capped(self):
        for i in range(35):
            mg.record_sizes({"~/x": i})
        self.assertEqual(len(json.loads(mg.read_text(mg.sizes_file()))), 30)

    def test_managed_storage_reports_and_never_offers_deletion(self):
        os.makedirs(os.path.join(self.home, "Library/Application Support/Claude/vm_bundles"))
        sizes = {os.path.join(self.home, "Library/Application Support/Claude/vm_bundles"): 11 * GB}
        with mock.patch.object(mg, "du", lambda p: sizes.get(p, 0)), \
                mock.patch.object(mg, "run", return_value=(0, "com.apple.TimeMachine.2026-11-03-010101.local\n", "")):
            m = mg.managed_storage()
        self.assertEqual(m[0]["name"], "Claude Cowork workspace image")
        self.assertIn("Settings > Storage", m[0]["how"])
        self.assertTrue(any("Time Machine" in x["name"] for x in m))
        self.assertNotIn("managed", {j["id"] for j in mg.JUNK})  # not a cleanable category

    def test_scan_cli_shows_low_disk_growth_and_managed(self):
        rep = dict(disk=mg.disk_health({"total": 228 * GB, "used": 224 * GB, "free": 4 * GB}), results=[], big=[("~/DEV", GB)],
                   since=0.0, grew=[("~/Library/Containers/com.docker.docker", GB // 5, 40 * GB)],
                   managed=[dict(name="Claude Cowork workspace image", path="~/x", size=11 * GB, how="Claude app > Settings > Storage")])
        out = io.StringIO()
        with mock.patch.object(mg, "space_report", return_value=rep), redirect_stdout(out):
            mg.cmd_scan(argparse.Namespace(stale_days=30))
        text = out.getvalue()
        for want in ("CRITICAL", "Grew since", "com.docker.docker", "Managed by apps", "Claude Cowork workspace image"):
            self.assertIn(want, text)


# ---------------------------------------------------------------- deep scan

def F(area, sev, title, detail, fix=""):
    return dict(area=area, sev=sev, title=title, detail=detail, fix=fix)


class TestDeepScan(TempHome):
    def test_fixes(self):
        self.assertIn("Remote Login (SSH)", mg.fix_for("network", "SSH exposed to the network", "launchd (pid 1) on *:22"))
        self.assertIn("AirPlay Receiver", mg.fix_for("network", "AirPlay Receiver exposed", "ControlCenter (pid 6) on *:7000"))
        self.assertEqual(mg.fix_for("apps", "Outdated app (Homebrew cask)", "zoom 5 -> 6  (brew upgrade --cask zoom)"),
                         "brew upgrade --cask zoom")
        key = mg.fix_for("security", "Private key / secret file in ~/Downloads", "~/Downloads/a b.key - move")
        self.assertIn('"$HOME/Downloads/a b.key"', key)  # regression: a quoted ~ doesn't expand
        self.assertIn("Firewall: on", mg.fix_for("security", "macOS firewall is OFF", ""))

    def test_merge_and_dedupe(self):
        fs = [F("network", "medium", "AirPlay Receiver exposed to the network", "x on *:5000", "fix A"),
              F("network", "medium", "AirPlay Receiver exposed to the network", "x on *:7000", "fix A"),
              F("network", "medium", "SSH exposed to the network", "launchd on *:22", "ssh fix"),
              F("security", "medium", "Remote Login (SSH) is enabled", "", ""),
              F("security", "medium", "Screen Sharing is enabled", "", ""),  # not exposed on :5900 here: kept
              F("apps", "medium", "Outdated app (Homebrew cask)", "a", "brew upgrade --cask a"),
              F("apps", "medium", "Outdated app (Homebrew cask)", "b", "brew upgrade --cask b")]
        m = {(f["area"], f["title"]): f for f in mg.merge_findings(fs)}
        self.assertEqual(m[("network", "AirPlay Receiver exposed to the network")]["detail"], "x on *:5000; x on *:7000")
        self.assertNotIn(("security", "Remote Login (SSH) is enabled"), m)
        self.assertIn(("security", "Screen Sharing is enabled"), m)
        self.assertEqual(m[("apps", "2 outdated apps (Homebrew casks)")]["fix"], "brew upgrade --cask a b")

    def test_score_is_capped_per_severity(self):
        many = [F("x", "medium", f"t{i}", "") for i in range(13)] + [F("x", "high", "h1", ""), F("x", "high", "h2", "")]
        self.assertEqual(mg.health_score(many, {"low": False, "critical": False}), 100 - 24 - 28)
        self.assertEqual(mg.health_score([], {"low": True, "critical": True}), 80)
        self.assertEqual(mg.health_score([], {}), 100)

    def deep(self, sec):
        space = dict(disk=mg.disk_health({"total": 228 * GB, "used": 200 * GB, "free": 28 * GB}),
                     results=[dict(id="npm", name="npm", risk="safe", size=5, entries=[("x", 5, "")])],
                     big=[], since=None, grew=[], managed=[])
        with mock.patch.object(mg, "space_report", return_value=space), \
                mock.patch.object(mg, "cmd_security", return_value=sec), \
                mock.patch.object(mg, "net_snapshot", return_value=SNAP(listeners=[L(22)])), \
                mock.patch.object(mg, "signature", return_value="apple"), \
                mock.patch.object(mg, "apps_report", return_value=([], [])):
            return mg.deep_scan()

    def test_new_since_last_deep_scan(self):
        first = self.deep([("high", "macOS firewall is OFF", "")])
        self.assertIsNone(first["since"])
        self.assertFalse(any(f["new"] for f in first["findings"]))  # nothing to compare with yet
        second = self.deep([("high", "macOS firewall is OFF", ""), ("medium", "Private key / secret file in ~/Downloads", "~/Downloads/k.key - move")])
        new = {f["title"]: f["new"] for f in second["findings"]}
        self.assertEqual(new, {"macOS firewall is OFF": False, "SSH exposed to the network": False,
                               "Private key / secret file in ~/Downloads": True})
        self.assertEqual(second["findings"][0]["title"], "macOS firewall is OFF")  # high first
        self.assertEqual(second["space"]["safe"], 5)

    def test_cli_deepscan_clean(self):
        rep = dict(score=72, since=None, disk=mg.disk_health({"total": 228 * GB, "used": 200 * GB, "free": 28 * GB}),
                   findings=[dict(F("security", "high", "macOS firewall is OFF", "", "System Settings > Network > Firewall: on"), new=True)],
                   apps=3, listeners=2, results=[dict(id="npm", name="npm", risk="safe", size=5, entries=[])],
                   space=dict(safe=5, review=0, managed=0, managed_items=[], safe_items=[], review_items=[]))
        out = io.StringIO()
        with mock.patch.object(mg, "deep_scan", return_value=rep), mock.patch.object(mg, "clean_item", return_value=5) as ci, \
                redirect_stdout(out):
            mg.cmd_deepscan(argparse.Namespace(traffic=False, stale_days=30, clean=True, yes=True))
        text = out.getvalue()
        for want in ("Health", "72/100", "Act now", "NEW", "-> System Settings > Network > Firewall: on", "Freed"):
            self.assertIn(want, text)
        ci.assert_called_once()

    def test_security_lists_every_key_and_orders_temp_folder_first(self):
        for name in ("a.key", "b.key"):
            with open(self.mk(f"Downloads/{name}", 0), "w") as fh:
                fh.write("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        agent = self.mk("Library/LaunchAgents/evil.plist", 10)
        own = self.mk("Library/LaunchAgents/mine.plist", 10)
        progs = {agent: "/tmp/x/payload", own: f"{self.home}/.automation/run.sh"}
        with mock.patch.object(mg, "run", return_value=(0, "", "")), mock.patch.object(mg, "plist_program", lambda p: progs.get(p)), \
                mock.patch.object(mg, "signature", return_value="unsigned"), \
                mock.patch.object(mg, "SUSPICIOUS_EXE_DIRS", ("/tmp/",)):  # the test HOME itself lives in a temp dir
            res = mg.cmd_security(None, quiet=True)
        keys = [d for _, t, d in res if t.startswith("Private key")]
        self.assertEqual(len(keys), 2)  # regression: the second key was dropped by a title-only dedupe
        self.assertIn(("high", "Auto-start program in temp/download folder"), {(sv, t) for sv, t, _ in res})  # regression: ordering
        self.assertIn(("low", "Your own unsigned script starts automatically (confirm it's yours)"), {(sv, t) for sv, t, _ in res})

    def test_simulator_runtimes_from_simctl(self):
        out = ("== Disk Images ==\n-- watchOS --\nwatchOS 26.2 (23S303) - 00A89AB1-FBF9-40EA-A769-56D12799B117 (Ready)\n"
               "Total Disk Images: 1 (3.6G)\n")
        with mock.patch.object(mg.shutil, "which", return_value="/usr/bin/xcrun"), mock.patch.object(mg, "run", return_value=(0, out, "")):
            r = mg.simulator_runtimes()
        self.assertEqual(r["runtimes"], [dict(name="watchOS 26.2 (23S303)", id="00A89AB1-FBF9-40EA-A769-56D12799B117")])
        self.assertEqual(r["size"], int(3.6 * GB))

    def test_own_ipv6_prefix_is_local(self):
        with mock.patch.object(mg, "_local_v6", {"2001:db8:1c74:"}):
            self.assertTrue(mg.is_private("2001:db8:1c74:7"))   # truncated peer on our own network
            self.assertFalse(mg.is_private("2001:db9:1:2"))


# ---------------------------------------------------------------- watch / settings

class TestWatchAndSettings(TempHome):
    def setUp(self):
        super().setUp()
        self.disk = {"total": 1000 * GB, "used": 500 * GB, "free": 500 * GB}
        for p in (mock.patch.object(mg, "signature", lambda path: "apple"),
                  mock.patch.object(mg, "disk_info", lambda: dict(self.disk))):
            p.start()
            self.addCleanup(p.stop)

    def test_low_disk_alert_once_then_rearms(self):
        self.watch(SNAP())
        self.disk.update(free=3 * GB)
        self.assertIn("Low disk space", self.watch(SNAP()))
        self.assertNotIn("Low disk space", self.watch(SNAP()))  # no repeat while still low
        self.disk.update(free=400 * GB)
        self.watch(SNAP())
        self.disk.update(free=3 * GB)
        self.assertIn("Low disk space", self.watch(SNAP()))

    def watch(self, snap, **kw):
        a = dict(agent=False, reset=False, once=True, interval=1)
        a.update(kw)
        with mock.patch.object(mg, "net_snapshot", lambda: snap):
            out = io.StringIO()
            with redirect_stdout(out):
                mg.cmd_watch(argparse.Namespace(**a))
        return out.getvalue()

    def test_fingerprint_collapses_ephemeral_ports(self):
        fp = mg.fingerprint(SNAP(listeners=[L(63467, exe="/usr/libexec/rapportd"), L(5000, host="127.0.0.1")]))
        self.assertIn("/usr/libexec/rapportd|dyn|net", fp["listeners"])
        self.assertIn("/bin/x|5000|lo", fp["listeners"])

    def test_learns_baseline_then_detects_changes(self):
        out = self.watch(SNAP(listeners=[L(5000)]))
        self.assertIn("Baseline learned", out)
        self.assertTrue(os.path.exists(mg.BASELINE))
        self.assertEqual(self.watch(SNAP(listeners=[L(5000)])).count("New network listener"), 0)
        changed = SNAP(listeners=[L(5000), L(8765, exe="/bin/server")], gw_mac="bb:bb:bb:bb:bb:bb",
                       dns=("6.6.6.6",), hosts=("1.2.3.4 bank.example",), conns=[CONN("8.8.8.8", 443, exe="/bin/newapp")])
        out = self.watch(changed)
        for msg in ("New network listener", "Gateway MAC changed", "DNS servers changed", "/etc/hosts changed",
                    "New program connecting to internet"):
            self.assertIn(msg, out)
        log = mg.read_text(mg.EVENTS_LOG)
        self.assertIn("/bin/server on port 8765", log)
        # baseline updated -> no repeat alerts
        self.assertNotIn("New network listener", self.watch(changed))

    def test_local_only_listener_not_alerted(self):
        self.watch(SNAP())
        self.assertNotIn("New network listener", self.watch(SNAP(listeners=[L(3000, host="127.0.0.1")])))

    def test_settings_default_off(self):
        self.assertFalse(mg.load_settings()["background_watcher"])

    def test_settings_on_off_installs_and_removes_agent(self):
        with mock.patch.object(mg, "install_agent", return_value=(True, "")) as inst, \
                mock.patch.object(mg, "remove_agent") as rem:
            quiet(mg.cmd_settings, argparse.Namespace(key="background_watcher", value="on"))
            inst.assert_called_once_with(60)
            self.assertTrue(json.loads(mg.read_text(mg.SETTINGS))["background_watcher"])
            quiet(mg.cmd_settings, argparse.Namespace(key="background_watcher", value="off"))
            rem.assert_called_once()
            self.assertFalse(mg.load_settings()["background_watcher"])

    def test_settings_rejects_bad_input(self):
        with self.assertRaises(SystemExit):
            quiet(mg.cmd_settings, argparse.Namespace(key="nope", value="1"))
        with self.assertRaises(SystemExit):
            quiet(mg.cmd_settings, argparse.Namespace(key="background_watcher", value="maybe"))

    def test_agent_exits_when_setting_off(self):
        with mock.patch.object(mg, "remove_agent") as rem, mock.patch.object(mg, "net_snapshot") as snap:
            mg.cmd_watch(argparse.Namespace(agent=True, reset=False, once=True, interval=1))
            rem.assert_called_once()
            snap.assert_not_called()

    def test_install_agent_writes_opt_in_plist(self):
        with mock.patch.object(mg, "run", return_value=(0, "", "")):
            ok, _ = mg.install_agent(90)
        plist = mg.read_text(mg.AGENT_PLIST)
        self.assertTrue(ok)
        self.assertIn("<string>--agent</string>", plist)
        self.assertIn("<string>90</string>", plist)
        self.assertIn("<key>SuccessfulExit</key><false/>", plist)
        with mock.patch.object(mg, "run", return_value=(0, "", "")):
            mg.remove_agent()
        self.assertFalse(os.path.exists(mg.AGENT_PLIST))


# ---------------------------------------------------------------- web UI

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class TestWebUI(TempHome):
    def setUp(self):
        super().setUp()
        self.target = os.path.dirname(self.mk("cache/junk/f", 100))
        scan = [dict(id="junk", name="Junk", risk="safe", note="", entries=[(self.target, 100, "")], size=100)]
        for p in (mock.patch.object(mg, "scan_junk", lambda *a, **k: [dict(r) for r in scan]),
                  mock.patch.object(mg, "disk_info", lambda: {"total": 100, "used": 40, "free": 60}),
                  mock.patch.object(mg, "measure_dirs", lambda: {"~/DEV/big": 5 * GB}),
                  mock.patch.object(mg, "managed_storage", lambda: [dict(name="Claude Cowork workspace image", path="~/x",
                                                                        size=11 * GB, how="Claude app > Settings > Storage")]),
                  mock.patch.object(mg, "install_agent", return_value=(True, "")),
                  mock.patch.object(mg, "remove_agent")):
            p.start()
            self.addCleanup(p.stop)
        self.port = free_port()
        args = argparse.Namespace(port=self.port, no_open=True, stale_days=30, parent_pid=None)
        threading.Thread(target=quiet, args=(mg.cmd_ui, args), daemon=True).start()
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.1).close()
                break
            except OSError:
                time.sleep(0.05)
        page = self.req("/", token=None)[1]
        self.token = re.search(r'const TOKEN = "([^"]+)"', page).group(1)

    def req(self, path, body=None, token="use", host=None):
        url = f"http://127.0.0.1:{self.port}{path}"
        data = json.dumps(body).encode() if body is not None else None
        r = urllib.request.Request(url, data=data, method="POST" if data is not None else "GET")
        if token:
            r.add_header("X-Token", self.token if token == "use" else token)
        if host:
            r.add_header("Host", host)
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                text = resp.read().decode()
                return resp.status, text
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode()

    def test_page_served_with_token(self):
        code, page = self.req("/", token=None)
        self.assertEqual(code, 200)
        self.assertNotIn("__TOKEN__", page)

    def test_api_requires_token(self):
        self.assertEqual(self.req("/api/disk", token=None)[0], 403)
        self.assertEqual(self.req("/api/disk", token="wrong")[0], 403)
        self.assertEqual(self.req("/api/clean", body={"ids": ["junk"]}, token=None)[0], 403)
        self.assertTrue(os.path.exists(self.target))

    def test_rejects_foreign_host_header(self):
        self.assertEqual(self.req("/", token=None, host="evil.example")[0], 403)
        self.assertEqual(self.req("/api/disk", host="evil.example")[0], 403)

    def test_clean_requires_scan_first(self):
        self.assertEqual(self.req("/api/clean", body={"ids": ["junk"]})[0], 409)
        self.assertTrue(os.path.exists(self.target))

    def test_scan_then_clean(self):
        code, body = self.req("/api/scan")
        self.assertEqual(code, 200)
        data = json.loads(body)
        self.assertEqual(data["items"][0]["id"], "junk")
        self.assertEqual(data["disk"]["free"], 60)
        self.assertTrue(data["disk"]["critical"])  # 60 of 100 bytes free is still < 5 GB
        self.assertEqual(data["managed"][0]["name"], "Claude Cowork workspace image")
        self.assertIsNone(data["since"])  # first scan only records sizes
        code, body = self.req("/api/clean", body={"ids": ["junk"]})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body)["cleaned"], ["junk"])
        self.assertFalse(os.path.exists(self.target))

    def test_clean_ignores_unknown_ids(self):
        self.req("/api/scan")
        code, body = self.req("/api/clean", body={"ids": ["../../etc"]})
        self.assertEqual(json.loads(body)["cleaned"], [])
        self.assertTrue(os.path.exists(self.target))

    def test_settings_toggle(self):
        with mock.patch.object(mg, "run", return_value=(1, "", "")):
            s = json.loads(self.req("/api/settings")[1])
            self.assertFalse(s["background_watcher"])
            self.assertFalse(s["running"])
        s = json.loads(self.req("/api/settings", body={"background_watcher": True})[1])
        self.assertTrue(s["background_watcher"])
        mg.install_agent.assert_called()
        s = json.loads(self.req("/api/settings", body={"background_watcher": False})[1])
        self.assertFalse(s["background_watcher"])
        mg.remove_agent.assert_called()

    def test_uninstall_endpoints_replan_server_side(self):
        app_path = os.path.join(self.home, "Applications", "Widgetly.app")
        self.mk("Applications/Widgetly.app/Contents/MacOS/Widgetly", 10)
        self.mk("Library/Caches/io.acme.widgetly/c", 10)
        app = dict(name="Widgetly", bundle_id="io.acme.widgetly", path=app_path, version="1", exe="", updated=0)
        with mock.patch.object(mg, "app_inventory", return_value=[app]), mock.patch.object(mg, "app_running", return_value=False):
            listed = json.loads(self.req("/api/installed")[1])
            self.assertEqual((listed[0]["name"], listed[0]["protected"]), ("Widgetly", None))
            plan = json.loads(self.req("/api/uninstall/plan", body={"path": app_path})[1])
            self.assertEqual(len(plan["items"]), 2)
            self.assertTrue(os.path.exists(app_path))  # plan never deletes
            self.assertEqual(self.req("/api/uninstall", body={"path": "/etc"})[0], 404)  # unknown path refused
            r = json.loads(self.req("/api/uninstall", body={"path": app_path, "items": ["/etc/hosts"]})[1])
        self.assertEqual(r["moved"], 2)
        self.assertFalse(os.path.exists(app_path))
        self.assertTrue(os.path.exists("/etc/hosts"))

    def test_kill_endpoints(self):
        app = dict(name="Widgetly", bundle_id="io.acme.widgetly", path="/Applications/Widgetly.app", version="1", exe="", updated=0)
        procs = [dict(pid=100, ppid=1, uid=os.getuid(), exe="/Applications/Widgetly.app/Contents/MacOS/Widgetly")]
        with mock.patch.object(mg, "app_inventory", return_value=[app]), \
                mock.patch.object(mg, "app_process_tree", return_value=procs), \
                mock.patch.object(mg, "app_launch_labels", return_value=["io.acme.widgetly.update"]), \
                mock.patch.object(mg, "kill_app", return_value=dict(stopped=procs, unloaded=["io.acme.widgetly.update"],
                                                                     needs_admin=[], survivors=[])) as k:
            plan = json.loads(self.req("/api/kill/plan", body={"path": app["path"]})[1])
            self.assertEqual((plan["processes"][0]["exe"], plan["agents"]), ("<app>/Contents/MacOS/Widgetly", ["io.acme.widgetly.update"]))
            k.assert_not_called()  # plan never kills
            r = json.loads(self.req("/api/kill", body={"path": app["path"]})[1])
            self.assertEqual((r["stopped"], r["survivors"]), (1, []))
            self.assertEqual(self.req("/api/kill", body={"path": "/Applications/Other.app"})[0], 404)

    def test_deepscan_endpoint_enables_clean(self):
        rep = dict(score=88, since=None, disk={"total": 100, "used": 40, "free": 60, "low": True, "critical": True},
                   findings=[dict(F("security", "high", "macOS firewall is OFF", "", "fix"), new=False)], apps=1, listeners=0,
                   results=[dict(id="junk", name="Junk", risk="safe", note="", entries=[(self.target, 100, "")], size=100)],
                   space=dict(safe=100, review=0, managed=0, managed_items=[], safe_items=[], review_items=[]))
        with mock.patch.object(mg, "deep_scan", return_value=rep):
            r = json.loads(self.req("/api/deepscan")[1])
        self.assertEqual((r["score"], r["findings"][0]["fix"], r["items"][0]["id"]), (88, "fix", "junk"))
        self.assertEqual(json.loads(self.req("/api/clean", body={"ids": ["junk"]})[1])["cleaned"], ["junk"])  # no separate scan needed

    def test_security_and_net_endpoints(self):
        with mock.patch.object(mg, "cmd_security", return_value=[("high", "Firewall off", "x")]), \
                mock.patch.object(mg, "net_snapshot", return_value=SNAP(listeners=[L(6379)])), \
                mock.patch.object(mg, "signature", return_value="apple"):
            sec = json.loads(self.req("/api/security")[1])
            net = json.loads(self.req("/api/net")[1])
        self.assertEqual(sec[0]["title"], "Firewall off")
        with mock.patch.object(mg, "apps_report", return_value=([APP()], [("high", "Unsigned app", "x")])), \
                mock.patch.object(mg, "traffic_sample", return_value=[]), \
                mock.patch.object(mg, "analyze_traffic", return_value=[("high", "Heavy upload", "y")]):
            apps = json.loads(self.req("/api/apps")[1])
            traffic = json.loads(self.req("/api/traffic")[1])
        self.assertEqual((apps["count"], apps["findings"][0]["title"]), (1, "Unsigned app"))
        self.assertEqual((traffic["seconds"], traffic["findings"][0]["title"]), (6, "Heavy upload"))
        self.assertTrue(net["listeners"][0]["exposed"])
        self.assertEqual(net["findings"][0]["sev"], "high")

    def test_perf_endpoints(self):
        def it(i, risk):
            return dict(id=i, name=i.title(), risk=risk, why="w", cpu=1.0, mem=1, count=1, orphan=False, procs=[],
                        stop=[] if risk == "system" else [("term", [1])], stop_text="s", start="st")
        rep = dict(state=dict(load=[1, 1, 1]), disk={"free": 1}, owners=[], findings=[("low", "x", "y")], suggestions=[],
                   items=[it("docker", "safe"), it("unity", "review"), it("spotlight", "system")])
        with mock.patch.object(mg, "perf_report", side_effect=lambda before=None: dict(rep, before=before)), \
                mock.patch.object(mg, "apply_perf", side_effect=lambda plan: [dict(id=x["id"]) for x in plan]):
            r = json.loads(self.req("/api/perf?before=heavy")[1])
            self.assertEqual((r["before"], r["findings"][0]["sev"]), ("heavy", "low"))
            self.assertNotIn("procs", r["items"][0])  # the page never sees pids or commands
            self.assertNotIn("stop", r["items"][0])
            self.assertIsNone(json.loads(self.req("/api/perf")[1])["before"])
            stop = lambda ids: json.loads(self.req("/api/perf/stop", body={"ids": ids})[1])["stopped"]  # noqa: E731
            self.assertEqual(stop(["unity", "spotlight", "../x"]), [{"id": "unity"}])  # system items never stop
            self.assertEqual(stop([]), [])  # no ids means nothing, not "the safe ones"
            self.assertEqual(self.req("/api/perf/stop", body={"ids": ["docker"]}, token=None)[0], 403)
            self.assertIn("focus", json.loads(self.req("/api/perf")[1]))

    def test_focus_endpoints(self):
        group = dict(name="Slack", cpu=1.0, mem=5, count=1, procs=[dict(pid=200, exe="/x")])
        plan = dict(pause=[group], kept=[dict(name="Xcode", reason="development tool")])
        with mock.patch.object(mg, "focus_snapshot", return_value=([], plan)), \
                mock.patch.object(mg, "focus_pause", return_value=([dict(pid=200, exe="/x", name="Slack")], 123.0)) as fp, \
                mock.patch.object(mg, "focus_resume", return_value=[1, 2]):
            view = json.loads(self.req("/api/perf/focus/plan", body={})[1])
            self.assertEqual((view["pause"][0]["name"], view["kept"][0]["name"]), ("Slack", "Xcode"))
            self.assertNotIn("procs", view["pause"][0])  # the page never sees pids
            fp.assert_not_called()
            r = json.loads(self.req("/api/perf/focus", body={"pids": [1]})[1])  # anything the page sends is ignored
            self.assertEqual((r["paused"], r["until"]), (1, 123.0))
            self.assertEqual(fp.call_args.kwargs["source"], "ui")
            self.assertEqual(json.loads(self.req("/api/perf/resume", body={})[1])["resumed"], 2)
            self.assertEqual(self.req("/api/perf/focus", body={}, token=None)[0], 403)


# ---------------------------------------------------------------- doctor / report

class TestDoctorAndReport(TempHome):
    def test_doctor_bundle(self):
        with self.assertRaises(SystemExit) as cm:
            quiet(mg.cmd_doctor, argparse.Namespace(bundle=True))
        bundles = [f for f in os.listdir(mg.STATE_DIR) if f.startswith("support-")]
        self.assertEqual(len(bundles), 1)
        text = mg.read_text(os.path.join(mg.STATE_DIR, bundles[0]))
        self.assertIn("settings:", text)
        if ON_MAC:
            self.assertEqual(cm.exception.code, 0, text)

    def test_report_writes_html(self):
        out = os.path.join(self.tmp, "r.html")
        with mock.patch.object(mg, "scan_junk", return_value=[]), \
                mock.patch.object(mg, "big_dirs", return_value=[("~/x", 10)]), \
                mock.patch.object(mg, "net_snapshot", return_value=SNAP(listeners=[L(5900)])), \
                mock.patch.object(mg, "cmd_security", return_value=[("high", "Firewall <off>", "")]), \
                mock.patch.object(mg, "signature", return_value="apple"):
            quiet(mg.cmd_report, argparse.Namespace(stale_days=30, out=out, no_open=True))
        page = mg.read_text(out)
        self.assertIn("Firewall &lt;off&gt;", page)  # escaped
        self.assertIn("Screen Sharing (VNC) exposed", page)


# ---------------------------------------------------------------- live, read-only system checks

@unittest.skipUnless(ON_MAC, "macOS only")
class LiveSystem(unittest.TestCase):
    def test_disk_info(self):
        d = mg.disk_info()
        self.assertGreater(d["total"], d["free"])

    def test_net_snapshot(self):
        snap = mg.net_snapshot()
        self.assertTrue(snap["listeners"] or snap["conns"],
                        "no sockets visible - run tests with /usr/bin/python3 (see `macguard doctor`)")
        mg.analyze_net(snap)

    def test_security_audit_runs(self):
        findings = mg.cmd_security(None, quiet=True)
        titles = " ".join(t for _, t, _ in findings)
        self.assertRegex(titles, "Firewall|firewall")

    def test_signature_of_system_binary(self):
        self.assertEqual(mg.signature("/bin/ls"), "apple")
        self.assertEqual(mg.signature("/does/not/exist"), "missing")

    def test_ui_port_zero_and_parent_watchdog(self):
        """The app starts the engine with --port 0 --parent-pid; it must report its port and exit when the parent dies."""
        import subprocess
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "macguard.py")
        parent = subprocess.Popen(["sleep", "3"])
        eng = subprocess.Popen(["/usr/bin/python3", "-u", script, "ui", "--port", "0", "--no-open", "--parent-pid", str(parent.pid)],
                               stdout=subprocess.PIPE, text=True)
        try:
            line = eng.stdout.readline()
            port = int(re.search(r"127\.0\.0\.1:(\d+)/", line).group(1))
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as r:
                self.assertEqual(r.status, 200)
            parent.wait()
            self.assertEqual(eng.wait(timeout=10), 0)
        finally:
            for p in (eng, parent):
                if p.poll() is None:
                    p.kill()
            eng.stdout.close()

    def test_perf_report_read_only(self):
        r = mg.perf_report("heavy")
        self.assertGreater(r["state"]["cores"], 0)
        self.assertIn(r["state"]["thermal"]["state"], ("nominal", "warning", "throttled"))
        self.assertIn(r["state"]["pressure"], ("normal", "warning", "critical", "unknown"))
        self.assertTrue(r["owners"])
        json.dumps(mg.perf_json(r))

    def test_cli_help(self):
        import subprocess
        script = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "macguard.py")
        out = subprocess.run(["/usr/bin/python3", script, "--help"], capture_output=True, text=True).stdout
        for cmd in ("scan", "clean", "net", "security", "apps", "traffic", "uninstall", "kill", "perf", "deepscan", "watch", "report", "settings", "ui", "doctor"):
            self.assertIn(cmd, out)


if __name__ == "__main__":
    unittest.main()
