"""Tests for the MCP server (macguard_mcp). Run: /usr/bin/python3 -m unittest discover -s tests -v

The protocol is driven in-process with mocked macguard functions, plus one live check
that `macguard mcp` answers over real stdio.
"""
import io
import json
import os
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import macguard_mcp as mcp  # noqa: E402
from test_macguard import TempHome, PROC, SK  # noqa: E402

mg = mcp.mg
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def rpc(method, params=None, mid=1):
    msg = {"jsonrpc": "2.0", "method": method}
    if mid is not None:
        msg["id"] = mid
    if params is not None:
        msg["params"] = params
    return msg


def call(name, args=None):
    r = mcp.handle(rpc("tools/call", {"name": name, "arguments": args or {}}))
    return r["result"]


class TestProtocol(unittest.TestCase):
    def test_initialize_and_list(self):
        init = mcp.handle(rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t"}}))
        self.assertEqual(init["result"]["protocolVersion"], "2025-03-26")
        self.assertIn("tools", init["result"]["capabilities"])
        odd = mcp.handle(rpc("initialize", {"protocolVersion": "1999-01-01"}))
        self.assertEqual(odd["result"]["protocolVersion"], mcp.PROTOCOL_VERSIONS[0])
        tools = {t["name"]: t for t in mcp.handle(rpc("tools/list"))["result"]["tools"]}
        self.assertTrue({"scan_junk", "plan_cleanup", "apply_cleanup", "process_check", "kill_process", "network_history",
                         "network_alerts", "network_record", "network_monitor_status",
                         "security_audit", "network_snapshot", "apps_audit", "traffic_sample"} <= set(tools))
        destructive = {n for n, t in tools.items() if t["annotations"].get("destructiveHint")}
        self.assertEqual(destructive, {"apply_cleanup", "kill_process"})
        self.assertIn("confirm", tools["kill_process"]["inputSchema"]["required"])

    def test_notifications_and_errors(self):
        self.assertIsNone(mcp.handle(rpc("notifications/initialized", mid=None)))
        self.assertEqual(mcp.handle(rpc("nope"))["error"]["code"], -32601)
        self.assertEqual(mcp.handle(rpc("tools/call", {"name": "rm_rf"}))["error"]["code"], -32602)
        self.assertEqual(mcp.handle(rpc("ping"))["result"], {})

    def test_serve_keeps_stdout_clean(self):
        # tools print progress; only JSON-RPC lines may reach stdout
        def noisy(a):
            print("progress chatter")
            return {"ok": 1}
        inp = io.StringIO("\n".join(json.dumps(m) for m in (
            rpc("initialize", {"protocolVersion": "2025-06-18"}, 1), rpc("notifications/initialized", mid=None),
            rpc("tools/call", {"name": "disk_info"}, 2))) + "\nnot json\n")
        out = io.StringIO()
        with mock.patch.dict(mcp.BY_NAME, {"disk_info": ("disk_info", "", {}, {}, noisy)}), \
                mock.patch("sys.stderr", io.StringIO()):
            mcp.serve(inp, out)
        lines = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual([l.get("id") for l in lines], [1, 2, None])
        self.assertEqual(lines[1]["result"]["structuredContent"], {"ok": 1})
        self.assertEqual(lines[2]["error"]["code"], -32700)

    def test_tool_exception_is_tool_error(self):
        def boom(a):
            raise RuntimeError("bad")
        with mock.patch.dict(mcp.BY_NAME, {"doctor": ("doctor", "", {}, {}, boom)}), mock.patch("sys.stderr", io.StringIO()):
            r = call("doctor")
        self.assertTrue(r["isError"])
        self.assertIn("bad", r["content"][0]["text"])


class Quiet(TempHome):
    """Tool errors log a traceback to stderr; keep test output readable."""

    def setUp(self):
        super().setUp()
        p = mock.patch("sys.stderr", io.StringIO())
        p.start()
        self.addCleanup(p.stop)


class TestCleanupTools(Quiet):
    def setUp(self):
        super().setUp()
        mcp._plans.clear()
        self.safe1 = os.path.dirname(self.mk("cache/a/f", 100))
        self.review1 = os.path.dirname(self.mk("avd/x/f", 100))
        self.scan = [dict(id="npm", name="npm", risk="safe", entries=[(self.safe1, 100, "")], size=100),
                     dict(id="android-avd", name="AVD", risk="review", entries=[(self.review1, 100, "")], size=100)]
        p = mock.patch.object(mg, "scan_junk", side_effect=lambda *a, **k: [dict(r) for r in self.scan])
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(mg, "disk_info", return_value={"total": 100, "used": 40, "free": 60})
        p.start()
        self.addCleanup(p.stop)

    def test_plan_is_dry_and_safe_only_by_default(self):
        plan = call("plan_cleanup")["structuredContent"]
        self.assertEqual([i["id"] for i in plan["items"]], ["npm"])
        self.assertTrue(os.path.exists(self.safe1))
        self.assertIn("unknown category", call("plan_cleanup", {"ids": ["bogus"]})["content"][0]["text"])

    def test_apply_needs_confirm_and_runs_once(self):
        pid = call("plan_cleanup", {"ids": ["android-avd"]})["structuredContent"]["plan_id"]
        self.assertTrue(call("apply_cleanup", {"plan_id": pid, "confirm": False})["isError"])
        res = call("apply_cleanup", {"plan_id": pid, "confirm": True})["structuredContent"]
        self.assertEqual(res["cleaned"], ["android-avd"])
        self.assertFalse(os.path.exists(self.review1))
        self.assertTrue(os.path.exists(self.safe1))  # not in the plan
        self.assertTrue(call("apply_cleanup", {"plan_id": pid, "confirm": True})["isError"])
        self.assertIn("[mcp]", mg.read_text(mg.EVENTS_LOG))

    def test_apply_skips_paths_added_after_the_plan(self):
        pid = call("plan_cleanup")["structuredContent"]["plan_id"]
        newer = os.path.dirname(self.mk("cache/b/f", 100))
        self.scan[0]["entries"].append((newer, 100, ""))
        call("apply_cleanup", {"plan_id": pid, "confirm": True})
        self.assertFalse(os.path.exists(self.safe1))
        self.assertTrue(os.path.exists(newer))


class TestProcessTools(Quiet):
    def test_process_check_and_kill_guard(self):
        table = [PROC(456, "/usr/sbin/coreaudiod", uid=202, cpu=90), PROC(2000, "/Users/me/node", cpu=50)]
        with mock.patch.object(mg, "process_table", return_value=table), mock.patch.object(mg.os, "kill") as k:
            procs = call("process_check")["structuredContent"]["processes"]
            self.assertEqual([(p["pid"], p["killable"]) for p in procs], [(456, False), (2000, True)])
            self.assertTrue(call("kill_process", {"pid": 2000, "exe": "/Users/me/node"})["isError"])  # no confirm
            r = call("kill_process", {"pid": 456, "exe": "/usr/sbin/coreaudiod", "confirm": True})["structuredContent"]
            self.assertFalse(r["ok"])
            k.assert_not_called()


class TestNetworkTools(Quiet):
    def test_history_alerts_and_record(self):
        empty = call("network_history", {"resolve": False})["structuredContent"]
        self.assertIn("hint", empty)
        socks = [SK("5.5.5.5", 4444, pid=10, tx=100)]
        with mock.patch.object(mg, "sockets", return_value=socks), \
                mock.patch.object(mg, "process_table", return_value=[PROC(10, "/opt/tool")]):
            rec = call("network_record", {"seconds": 1, "interval": 1})["structuredContent"]
        self.assertEqual(rec["samples"], 1)
        self.assertEqual(rec["status"]["days_with_data"], 1)
        hist = call("network_history", {"resolve": False})["structuredContent"]
        self.assertEqual(hist["destinations"][0]["ip"], "5.5.5.5")
        self.assertEqual(hist["totals"]["connections"], 1)
        with mock.patch.object(mg, "signature", return_value="developer:Acme"):
            alerts = call("network_alerts", {"resolve": False})["structuredContent"]["findings"]
        self.assertEqual(alerts[0]["sev"], "high")
        self.assertIn("4444", alerts[0]["title"])
        self.assertEqual(call("network_history", {"process": "nothing-like-this", "resolve": False})
                         ["structuredContent"]["totals"]["connections"], 0)


@unittest.skipUnless(sys.platform == "darwin", "macOS only")
class LiveStdio(unittest.TestCase):
    def test_macguard_mcp_over_stdio(self):
        msgs = [rpc("initialize", {"protocolVersion": "2025-06-18"}, 1), rpc("notifications/initialized", mid=None),
                rpc("tools/list", mid=2), rpc("tools/call", {"name": "doctor"}, 3)]
        p = subprocess.run(["/usr/bin/python3", os.path.join(ROOT, "macguard.py"), "mcp"],
                           input="".join(json.dumps(m) + "\n" for m in msgs), capture_output=True, text=True, timeout=120)
        lines = [json.loads(l) for l in p.stdout.splitlines()]
        self.assertEqual([l["id"] for l in lines], [1, 2, 3], p.stderr)
        self.assertEqual(lines[0]["result"]["serverInfo"]["name"], "mac-cleanup")
        self.assertTrue(lines[2]["result"]["structuredContent"]["checks"])


if __name__ == "__main__":
    unittest.main()
