"""Tests for the Tools section and Recover files R1 (macguard_tools, macguard_recover).

  /usr/bin/python3 -m unittest discover -s tests -v

Everything runs in a temp HOME with synthetic files, a throwaway git repo and mocked diskutil/tmutil/osascript.
Nothing touches the real Trash, real disks or Finder.
"""
import json
import os
import plistlib
import subprocess
import sys
import unittest
import urllib.parse
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import macguard_mcp as mcp  # noqa: E402
import macguard_recover as rec  # noqa: E402
import macguard_tools as mtools  # noqa: E402
import test_macguard  # noqa: E402
from test_macguard import TempHome  # noqa: E402

mg = rec.mg


def plist(d):
    return plistlib.dumps(d).decode()


def fake_run(table, calls=None):
    """mg.run stand-in: the first key that is a prefix of the command wins."""
    def run(cmd, timeout=60):
        if calls is not None:
            calls.append(cmd)
        for key, val in table.items():
            if tuple(cmd[:len(key)]) == key:
                return val(cmd) if callable(val) else val
        return 1, "", "not mocked"
    return run


class TestToolsRegistry(unittest.TestCase):
    def test_tools_and_result_shape(self):
        ids = [t["id"] for t in mtools.TOOLS]
        self.assertEqual(ids, ["recover", "ai-image", "ai-voice"])
        self.assertEqual([t["status"] for t in mtools.TOOLS], ["ready", "planned", "planned"])
        r = mtools.result("recover", "found", "x", "strong", evidence=[{"kind": "trash"}])
        self.assertEqual(set(r), {"tool", "verdict", "headline", "confidence", "evidence", "limits", "next"})
        with self.assertRaises(AssertionError):
            mtools.result("recover", "real", "never a verdict")
        self.assertEqual({h["name"] for h in mtools.helpers()},
                         {"photorec", "ddrescue", "tsk_recover", "c2patool", "exiftool"})


class TestTrash(TempHome):
    def test_direct_listing_and_query(self):
        self.mk(".Trash/holiday.jpg", 10)
        self.mk(".Trash/report.docx", 20)
        self.mk(".Trash/old project/a.txt", 5)
        with mock.patch.object(rec, "trash_dirs", lambda: [os.path.join(self.home, ".Trash")]):
            items, notes = rec.search_trash(None)
            self.assertEqual(sorted(i["name"] for i in items), ["holiday.jpg", "old project", "report.docx"])
            self.assertEqual(next(i for i in items if i["name"] == "old project")["size"], 5)
            self.assertEqual([i["name"] for i in rec.search_trash("*.jpg")[0]], ["holiday.jpg"])
            self.assertEqual([i["name"] for i in rec.search_trash("REPORT")[0]], ["report.docx"])
        self.assertEqual(notes, [])

    def test_protected_trash_never_calls_finder_unless_asked(self):
        calls = []
        with mock.patch("os.listdir", side_effect=PermissionError), mock.patch.object(mg, "run", fake_run({}, calls)), \
                mock.patch.object(rec, "trash_dirs", lambda: ["/x/.Trash"]):
            items, notes = rec.search_trash(None)
        self.assertEqual(items, [])
        self.assertEqual(calls, [])
        self.assertIn("protects the Trash", notes[0])

    def test_finder_route(self):
        p = self.mk(".Trash/thesis.pdf", 30)
        runs = {("osascript", "-e"): lambda cmd: (0, "1\n", "") if "count items" in cmd[2] else (0, p + "\n", "")}
        with mock.patch("os.listdir", side_effect=PermissionError), mock.patch.object(mg, "run", fake_run(runs)), \
                mock.patch.object(rec, "trash_dirs", lambda: ["/x/.Trash"]):
            items, notes = rec.search_trash("thesis", finder=True)
        self.assertEqual([(i["name"], i["via"], i["size"]) for i in items], [("thesis.pdf", "finder", 30)])
        self.assertIn("through Finder", notes[0])

    def test_finder_errors_explain_what_to_do(self):
        for err, want in (("execution error: Not authorized to send Apple events to Finder. (-1743)", "Automation"),
                          ("execution error: Finder got an error: AppleEvent timed out. (-1712)", "permission prompt")):
            with mock.patch.object(mg, "run", fake_run({("osascript",): (1, "", err)})):
                rows, msg = rec.finder_trash()
            self.assertIsNone(rows)
            self.assertIn(want, msg)
        with mock.patch.object(mg, "run", fake_run({("osascript",): (0, "99999\n", "")})):
            self.assertIn("too many", rec.finder_trash()[1])


class TestHistory(TempHome):
    def test_editor_versions(self):
        root = os.path.join(self.home, "Library/Application Support/Cursor/User/History/abc123")
        os.makedirs(root)
        for i, ts in enumerate((1700000000000, 1700000600000)):
            with open(os.path.join(root, f"v{i}.py"), "w") as fh:
                fh.write(f"version {i}\n")
        with open(os.path.join(root, "entries.json"), "w") as fh:
            json.dump({"version": 1, "resource": "file:///Users/you/code/my%20app/main.py",
                       "entries": [{"id": "v0.py", "timestamp": 1700000000000}, {"id": "v1.py", "timestamp": 1700000600000},
                                   {"id": "gone.py", "timestamp": 1}]}, fh)
        items = rec.search_history("main.py")
        self.assertEqual([i["path"].endswith("v1.py") for i in items], [True, False])  # newest first, missing skipped
        self.assertEqual(items[0]["original"], "/Users/you/code/my app/main.py")
        self.assertEqual(items[0]["app"], "Cursor")
        self.assertEqual(rec.search_history("other.py"), [])


def git(repo, *args):
    subprocess.run(["git", "-C", repo, "-c", "user.email=t@t", "-c", "user.name=t", *args], check=True,
                   capture_output=True)


class TestGit(TempHome):
    def setUp(self):
        super().setUp()
        self.repo = os.path.join(self.home, "code/app")
        os.makedirs(self.repo)
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "commit", "-q", "--allow-empty", "-m", "first")
        with open(os.path.join(self.repo, "notes.txt"), "w") as fh:
            fh.write("important work\n")
        git(self.repo, "add", "notes.txt")
        git(self.repo, "commit", "-q", "-m", "Add my important notes")
        git(self.repo, "reset", "-q", "--hard", "HEAD~1")
        with open(os.path.join(self.repo, "draft.md"), "w") as fh:
            fh.write("staged but lost draft\n")
        git(self.repo, "add", "draft.md")
        git(self.repo, "rm", "-q", "--cached", "draft.md")
        os.remove(os.path.join(self.repo, "draft.md"))

    def test_finds_lost_commit_and_staged_file(self):
        items, notes = rec.search_git(self.repo)
        self.assertEqual(notes, [])
        self.assertIn("Add my important notes", [i["name"] for i in items if i["kind"] == "commit"])
        self.assertIn("staged but lost draft", [i["name"] for i in items if i["kind"] == "blob"])
        self.assertEqual([i["name"] for i in rec.search_git(self.repo, "draft")[0]], ["staged but lost draft"])
        self.assertIn("isn't inside a git repository", rec.search_git(self.home)[1][0])

    def test_restore_blob_to_file_and_commit_to_branch(self):
        items, _ = rec.search_git(self.repo)
        blob = next(i for i in items if i["name"] == "staged but lost draft")
        dest = os.path.join(self.home, "out")
        r = rec.restore(blob, dest)
        self.assertTrue(r["ok"], r)
        with open(r["path"]) as fh:
            self.assertEqual(fh.read(), "staged but lost draft\n")
        commit = next(i for i in items if i["kind"] == "commit")
        r = rec.restore(commit, dest)
        self.assertTrue(r["ok"], r)
        out = subprocess.run(["git", "-C", self.repo, "log", "-1", "--format=%s", f"recovered/{commit['sha'][:10]}"],
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "Add my important notes")
        self.assertEqual(subprocess.run(["git", "-C", self.repo, "branch", "--show-current"], capture_output=True,
                                        text=True).stdout.strip(), "main")  # the current branch is untouched


class TestRestore(TempHome):
    def item(self, rel, size=10, source="trash"):
        p = self.mk(rel, size)
        return {"id": "x", "source": source, "name": os.path.basename(p), "path": p, "modified": "2026-11-13T10:00:00",
                "kind": "file", "via": "direct"}

    def test_copies_never_moves_never_overwrites(self):
        it = self.item(".Trash/photo.jpg")
        dest = os.path.join(self.home, "Recovered")
        a, b = rec.restore(it, dest), rec.restore(it, dest)
        self.assertTrue(os.path.exists(it["path"]))                       # source untouched
        self.assertEqual([os.path.basename(a["path"]), os.path.basename(b["path"])], ["photo.jpg", "photo (2).jpg"])

    def test_folders_and_history_names(self):
        self.mk(".Trash/proj/src/a.py", 3)
        folder = {"id": "x", "source": "trash", "name": "proj", "path": os.path.join(self.home, ".Trash/proj"),
                  "kind": "folder", "via": "direct", "modified": ""}
        r = rec.restore(folder, os.path.join(self.home, "out"))
        self.assertTrue(os.path.exists(os.path.join(r["path"], "src/a.py")))
        h = {**self.item("hist/x.py", source="history"), "name": "main.py"}
        self.assertEqual(os.path.basename(rec.restore(h, os.path.join(self.home, "out"))["path"]),
                         "main (2026-11-13T10.00.00).py")

    def test_refuses_bad_destinations(self):
        it = self.item(".Trash/a.txt")
        for bad in (os.path.join(self.home, ".Trash"), os.path.join(self.home, ".Trash/sub"), "/System/x"):
            with self.assertRaises(ValueError):
                rec.restore(it, bad)

    def test_default_destination(self):
        self.assertTrue(rec.default_dest().startswith(os.path.join(self.home, "Downloads", "Recovered ")))


class TestTimeMachine(TempHome):
    def test_state_and_versions(self):
        with mock.patch.object(mg, "run", fake_run({("tmutil", "destinationinfo"): (0, "tmutil: No destinations configured.\n", "")})):
            self.assertFalse(rec.timemachine_state()["configured"])
        b = os.path.join(self.tmp, "Backups.backupdb/Mac/2026-11-01-120000.backup")
        target = os.path.join(self.home, "Documents/plan.txt")
        self.mk("Documents/plan.txt")
        os.makedirs(os.path.join(b, "Macintosh HD - Data", os.path.dirname(target).lstrip("/")))
        with open(os.path.join(b, "Macintosh HD - Data", target.lstrip("/")), "w") as fh:
            fh.write("old plan")
        runs = {("tmutil", "destinationinfo"): (0, "Name : Backup\n", ""), ("tmutil", "listbackups"): (0, b + "\n", "")}
        with mock.patch.object(mg, "run", fake_run(runs)):
            st = rec.timemachine_state()
        self.assertEqual(st["backups"], [b])
        v = rec.timemachine_versions(target, st["backups"])
        self.assertEqual(len(v), 1)
        self.assertEqual(v[0]["modified"], "2026-11-01-120000")

    def test_local_snapshots_only_time_machine(self):
        out = ("Snapshots for volume group containing disk /:\ncom.apple.os.update-ABC\n"
               "com.apple.TimeMachine.2026-11-13-101500.local\n")
        with mock.patch.object(mg, "run", fake_run({("tmutil", "listlocalsnapshots"): (0, out, "")})):
            self.assertEqual(rec.local_snapshots(), [{"name": "com.apple.TimeMachine.2026-11-13-101500.local",
                                                       "date": "2026-11-13-101500"}])

    def test_search_puts_it_together(self):
        self.mk(".Trash/cv.pdf", 4)
        runs = {("tmutil", "destinationinfo"): (0, "No destinations configured", ""), ("tmutil", "listlocalsnapshots"): (0, "", "")}
        with mock.patch.object(rec, "trash_dirs", lambda: [os.path.join(self.home, ".Trash")]), \
                mock.patch.object(mg, "run", fake_run(runs)):
            r = rec.search("cv")
        self.assertEqual((r["verdict"], len(r["items"])), ("found", 1))
        self.assertTrue(any("Time Machine isn't set up" in n for n in r["notes"]))
        self.assertTrue(any(g["source"] == "Photos" for g in r["guidance"]))
        self.assertTrue(any("internal SSD" in x for x in r["limits"]))


def DISK(ident, **kw):
    return {"DeviceIdentifier": ident, **kw}


class TestAnalyze(TempHome):
    def runs(self, infos, lists):
        def run(cmd, timeout=60):
            if cmd[:3] == ["diskutil", "info", "-plist"]:
                d = infos.get(cmd[3])
                return (0, plist(d), "") if d else (1, "", "no disk")
            if cmd[:3] == ["diskutil", "list", "-plist"]:
                key = cmd[3] if len(cmd) == 4 else "external"
                return 0, plist(lists.get(key, {"AllDisksAndPartitions": []})), ""
            return 1, "", ""
        return run

    def test_memory_card_exfat_is_good(self):
        infos = {"disk4": DISK("disk4", MediaName="SD Card Reader", RemovableMedia=True, BusProtocol="USB", TotalSize=64 << 30,
                               SMARTStatus="Not Supported"),
                 "disk4s1": DISK("disk4s1", FilesystemType="exfat", VolumeName="CANON", TotalSize=64 << 30, FreeSpace=10 << 30,
                                 MountPoint="/Volumes/CANON")}
        lists = {"disk4": {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk4", "Partitions": [{"DeviceIdentifier": "disk4s1"}]}]},
                 "external": {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk4"}]}}
        with mock.patch.object(mg, "run", self.runs(infos, lists)), mock.patch("shutil.which", return_value=None):
            r = rec.analyze("/dev/rdisk4")
            devs = rec.devices()
        self.assertEqual((r["disk"]["chance"], r["confidence"]), ("good", "strong"))
        self.assertEqual(r["disk"]["volumes"][0]["fs"], "exFAT")
        self.assertTrue(any("Stop using the card" in s for s in r["next"]))
        self.assertTrue(any("brew install testdisk" in s for s in r["next"]))
        self.assertEqual([d["id"] for d in devs], ["disk4"])

    def test_internal_ssd_is_honest(self):
        infos = {"disk3": DISK("disk3", Internal=True, SolidState=True, BusProtocol="Apple Fabric"),
                 "disk3s1": DISK("disk3s1", FilesystemType="apfs", VolumeName="Data", Encryption=True, Internal=True, SolidState=True)}
        lists = {"disk3": {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk3", "APFSVolumes": [{"DeviceIdentifier": "disk3s1"}]}]}}
        with mock.patch.object(mg, "run", self.runs(infos, lists)):
            r = rec.analyze("disk3")
        self.assertEqual((r["disk"]["chance"], r["confidence"]), ("none", "none"))
        self.assertIn("TRIM", r["disk"]["why"])

    def test_apfs_container_on_external_ssd_and_failing_smart(self):
        infos = {"disk10": DISK("disk10", MediaName="T7", SolidState=True, BusProtocol="USB", SMARTStatus="Failing"),
                 "disk10s2": DISK("disk10s2", Content="Apple_APFS", APFSContainerReference="disk11"),
                 "disk11s1": DISK("disk11s1", FilesystemType="apfs", VolumeName="T7", Encryption=True, SolidState=True)}
        lists = {"disk10": {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk10", "Partitions": [{"DeviceIdentifier": "disk10s2"}]}]},
                 "disk11": {"AllDisksAndPartitions": [{"DeviceIdentifier": "disk11", "APFSVolumes": [{"DeviceIdentifier": "disk11s1"}]}]}}
        with mock.patch.object(mg, "run", self.runs(infos, lists)):
            r = rec.analyze("disk10")
        self.assertEqual([v["name"] for v in r["disk"]["volumes"]], ["T7"])
        self.assertEqual(r["disk"]["chance"], "very low")
        self.assertIn("may be failing", r["next"][0])

    def test_rejects_bad_identifiers(self):
        for bad in ("disk4; rm -rf ~", "../etc", "sda1"):
            with self.assertRaises(ValueError):
                rec.analyze(bad)


class TestMcp(TempHome):
    def test_restore_needs_confirm_and_a_known_id(self):
        r = mcp.call_tool("recover_restore", {"id": "abc"})
        self.assertTrue(r["isError"])
        self.assertIn("confirm", r["content"][0]["text"])
        with mock.patch.object(rec, "search", lambda *a, **k: {"items": []}):
            r = mcp.call_tool("recover_restore", {"id": "abc", "confirm": True})
        self.assertIn("no item with that id", r["content"][0]["text"])

    def test_tools_list_and_schema(self):
        names = {t[0] for t in mcp.TOOLS}
        self.assertTrue({"tools_list", "recover_search", "recover_restore", "recover_analyze"} <= names)
        self.assertEqual(mcp.call_tool("tools_list", {})["structuredContent"]["tools"][0]["id"], "recover")


class TestRecoverWebRoutes(test_macguard.TestWebUI):
    def test_recover_routes(self):
        self.mk(".Trash/lost.txt", 7)
        runs = {("tmutil",): (1, "", "")}
        with mock.patch.object(rec, "trash_dirs", lambda: [os.path.join(self.home, ".Trash")]), \
                mock.patch.object(mg, "run", fake_run(runs)):
            self.assertEqual(self.req("/api/recover/restore", body={"id": "nope"})[0], 409)  # no search yet
            r = json.loads(self.req("/api/recover/search?" + urllib.parse.urlencode({"q": "lost", "sources": "trash"}))[1])
            self.assertEqual([i["name"] for i in r["items"]], ["lost.txt"])
            dest = os.path.join(self.home, "Recovered")
            out = json.loads(self.req("/api/recover/restore", body={"id": r["items"][0]["id"], "to": dest})[1])
            self.assertTrue(out["ok"], out)
            self.assertTrue(os.path.exists(os.path.join(dest, "lost.txt")))
            self.assertEqual(self.req("/api/recover/restore", body={"id": r["items"][0]["id"],
                                                                   "to": os.path.join(self.home, ".Trash")})[0], 400)
            self.assertEqual(self.req("/api/recover/analyze?disk=bad%3Bdisk")[0], 400)
            self.assertEqual(json.loads(self.req("/api/tools")[1])["tools"][0]["id"], "recover")
            self.assertEqual(self.req("/api/recover/search", token=None)[0], 403)


for _name in dir(test_macguard.TestWebUI):
    if _name.startswith("test_"):
        setattr(TestRecoverWebRoutes, _name, None)


if __name__ == "__main__":
    unittest.main()
