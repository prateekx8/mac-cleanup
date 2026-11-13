"""Tests for the Photo sorter (macguard_photos). Synthetic files only; the Vision helper is a stub script,
except one smoke test that compiles and runs the real Swift helper on a generated picture."""
import json
import os
import shutil
import stat
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macguard_mcp as mcp  # noqa: E402
import macguard_photos as ph  # noqa: E402
import macguard_tools as mtools  # noqa: E402
import media_fixtures as mf  # noqa: E402
import test_macguard  # noqa: E402
from test_macguard import TempHome  # noqa: E402

# The stub "Vision": answers per file name, so tests decide what each picture shows.
STUB = r'''#!/usr/bin/python3
import json, os, sys, base64, struct
FP = {"burst": [1.0] + [0.0] * 7, "burst2": [0.99, 0.05] + [0.0] * 6, "other": [0.0, 1.0] + [0.0] * 6}
for line in sys.stdin:
    p = line.strip()
    if not p:
        continue
    n = os.path.basename(p).lower()
    out = {"path": p, "kind": "video" if n.endswith((".mov", ".mp4")) else "image"}
    if out["kind"] == "image":
        lab = [["beach", 0.9], ["people", 0.8]] if "beach" in n or "img_" in n else [["dog", 0.9]]
        if "receipt" in n:
            lab, out["utility"], out["text"] = [["receipt", 0.8], ["document", 0.7]], True, 14
        else:
            out["utility"], out["text"] = False, 0
        out["labels"], out["faces"], out["quality"] = lab, 1 if "beach" in n else 0, 0.5
        key = "burst2" if "burst2" in n else "burst" if "burst" in n else "other"
        out["fp"] = base64.b64encode(struct.pack("8f", *FP[key])).decode()
    print(json.dumps(out))
'''


def jpg(taken=None, make="Apple", gps=None):
    return mf.jpeg(exif=mf.exif_tiff(make=make, model="iPhone", taken=taken, gps=gps) if (taken or make) else None)


class PhotoCase(TempHome):
    def setUp(self):
        super().setUp()
        self.src = os.path.join(self.home, "Pictures", "Inbox")
        os.makedirs(self.src)
        stub = os.path.join(self.tmp, "photo_sense_stub")
        with open(stub, "w") as fh:
            fh.write(STUB)
        os.chmod(stub, 0o755)
        self.env = mock.patch.dict(os.environ, {"MACGUARD_PHOTO_SENSE": stub})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        super().tearDown()

    def put(self, rel, data, mtime=None):
        p = os.path.join(self.src, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
        if mtime:
            os.utime(p, (mtime, mtime))
        return p

    def library(self):
        """A small mixed folder: two trips, a burst, a screenshot, a receipt, a duplicate, a Live Photo, an undated file."""
        self.put("IMG_0001.JPG", jpg("2026:08:10 09:00:00", gps=(12.97, 77.59)))
        self.put("IMG_0002 burst.JPG", jpg("2026:08:10 09:00:03", gps=(12.97, 77.59)))
        self.put("IMG_0003 burst2.JPG", jpg("2026:08:10 09:00:05", gps=(12.97, 77.59)))
        self.put("IMG_0004.HEIC", jpg("2026:08:10 15:00:00", gps=(12.97, 77.59)))  # same day, same place
        self.put("IMG_0004.MOV", b"\x00\x00\x00\x14ftypqt  \x00\x00\x00\x00qt  ")
        self.put("IMG_0004.AAE", b"<plist/>")
        self.put("trip/IMG_0100.JPG", jpg("2026:09:02 17:00:00", gps=(19.07, 72.87)))
        self.put("trip/IMG_0100 copy.JPG", jpg("2026:09:02 17:00:00", gps=(19.07, 72.87)))
        self.put("Screenshot 2026-10-01 at 10.15.00.png", mf.png())
        self.put("receipt.jpg", jpg("2026:10:05 12:00:00"))
        self.put("random.jpg", jpg(None, make=None), mtime=time.time() - 86400)


class TestDates(unittest.TestCase):
    def test_name_dates(self):
        for name, want in (("IMG_20231105_143012.jpg", "2023-11-05T14:30:12"),
                           ("Screenshot 2026-11-13 at 10.15.00.png", "2026-11-13T10:15:00"),
                           ("WhatsApp Image 2024-01-02 at 20.01.02.jpeg", "2024-01-02T20:01:02"),
                           ("PXL_20250704_101112345.jpg", "2025-07-04T10:11:12"),
                           ("2022-12-25 party.jpg", "2022-12-25T12:00:00"), ("IMG_1234.JPG", None),
                           ("20231399.jpg", None)):
            self.assertEqual(ph.name_date(name), want, name)

    def test_date_order(self):
        self.assertEqual(ph.resolve_date({"taken": "2026:01:02 03:04:05"}, "/x/IMG_20200101_000000.jpg", 0),
                         ("2026-01-02T03:04:05", "exif"))
        self.assertEqual(ph.resolve_date({}, "/x/IMG_20200101_000000.jpg", 0)[1], "name")
        self.assertEqual(ph.resolve_date({}, "/x/a.jpg", 1700000000)[1], "file")
        self.assertEqual(ph.resolve_date({"created": "2026-05-01T10:00:00Z"}, "/x/a.mov", 0)[1], "video")


class TestSorter(PhotoCase):
    def test_index_summary_kinds_events(self):
        self.library()
        r = ph.index(self.src)
        self.assertEqual((r["files"], r["updated"], r["vision"]), (10, 10, True))
        self.assertEqual(ph.index(self.src)["updated"], 0)  # unchanged files are skipped
        items, events = ph.analyse(ph.rows(self.src))
        kinds = {os.path.basename(i["path"]): i["kind"] for i in items}
        self.assertEqual(kinds["Screenshot 2026-10-01 at 10.15.00.png"], "screenshot")
        self.assertEqual(kinds["receipt.jpg"], "document")
        self.assertEqual(kinds["IMG_0100 copy.JPG"], "duplicate")
        self.assertEqual(kinds["IMG_0100.JPG"], "photo")
        self.assertEqual(kinds["IMG_0004.MOV"], "video")
        by = {os.path.basename(i["path"]): i for i in items}
        self.assertTrue(by["IMG_0002 burst.JPG"].get("similar"))
        self.assertEqual(by["IMG_0002 burst.JPG"]["similar"], by["IMG_0003 burst2.JPG"]["similar"])
        self.assertFalse(by["IMG_0001.JPG"].get("similar"))
        names = [e["name"] for e in events]
        self.assertIn("2026-08-10 Beach", names[0])
        s = ph.summary(self.src)
        self.assertEqual((s["duplicates"], s["undated"], s["similar_groups"]), (1, 1, 1))
        self.assertEqual(s["kinds"]["screenshot"], 1)

    def test_gps_jump_splits_events(self):
        self.put("a.jpg", jpg("2026:08:10 09:00:00", gps=(12.97, 77.59)))
        self.put("b.jpg", jpg("2026:08:10 10:00:00", gps=(19.07, 72.87)))  # 1 h later, ~850 km away
        ph.index(self.src)
        self.assertEqual(len(ph.analyse(ph.rows(self.src))[1]), 2)

    def test_plan_copy_keeps_source_and_pairs(self):
        self.library()
        ph.index(self.src)
        before = {p: open(p, "rb").read() for p in ph.walk(self.src)[0] + ph.walk(self.src)[1]}
        dest = os.path.join(self.home, "Sorted")
        p = ph.plan(self.src, "event", dest)
        self.assertEqual(len(p["moves"]), 11)  # 10 pictures and videos + the Live Photo's edit sidecar
        r = ph.apply(p["id"], "copy")
        self.assertEqual((r["done"], r["failed"]), (11, []))
        for path, data in before.items():
            self.assertEqual(open(path, "rb").read(), data)  # source untouched
        got = sorted(os.path.relpath(os.path.join(d, f), dest) for d, _, fs in os.walk(dest) for f in fs)
        live = [g for g in got if "IMG_0004" in g]
        self.assertEqual(len({os.path.dirname(g) for g in live}), 1, live)  # photo, video and sidecar together
        self.assertIn("Duplicates/IMG_0100 copy.JPG", got)
        self.assertIn("Undated/random.jpg", got)
        self.assertTrue(any(g.startswith("Screenshots/2026-10/") for g in got))
        self.assertTrue(any(g.startswith("Documents and receipts/2026/") for g in got))

    def test_move_and_undo(self):
        self.library()
        ph.index(self.src)
        before = sorted(ph.walk(self.src)[0] + ph.walk(self.src)[1])
        p = ph.plan(self.src, "month", os.path.join(self.src, "Sorted"))
        r = ph.apply(p["id"], "move")
        self.assertEqual(r["done"], 11)
        self.assertFalse(any(os.path.exists(x) for x in before))
        u = ph.undo()
        self.assertEqual((u["restored"], u["left"]), (11, []))
        self.assertEqual(sorted(ph.walk(self.src)[0] + ph.walk(self.src)[1]), before)
        self.assertFalse(os.path.exists(os.path.join(self.src, "Sorted")))  # empty folders tidied
        with self.assertRaises(ValueError):
            ph.undo()  # nothing left to undo

    def test_name_clash_never_overwrites(self):
        self.put("IMG_0001.JPG", jpg("2026:08:10 09:00:00"))
        ph.index(self.src)
        dest = os.path.join(self.home, "Sorted")
        p = ph.plan(self.src, "month", dest)
        target = os.path.join(dest, p["moves"][0]["dir"], "IMG_0001.JPG")
        os.makedirs(os.path.dirname(target))
        with open(target, "wb") as fh:
            fh.write(b"mine")
        ph.apply(p["id"], "copy")
        self.assertEqual(open(target, "rb").read(), b"mine")
        self.assertTrue(os.path.exists(target.replace("IMG_0001.JPG", "IMG_0001 (2).JPG")))

    def test_trust_file_dates(self):
        self.put("random.jpg", jpg(None, make=None), mtime=1700000000)
        ph.index(self.src)
        self.assertEqual(ph.plan(self.src, "month", os.path.join(self.home, "S"))["moves"][0]["dir"], "Undated")
        p = ph.plan(self.src, "month", os.path.join(self.home, "S"), trust_file_dates=True)
        self.assertTrue(p["moves"][0]["dir"].startswith("2023/2023-11"))

    def test_tags(self):
        p = self.put("IMG_0001.JPG", jpg("2026:08:10 09:00:00"))
        ph.index(self.src)
        r = ph.apply(ph.plan(self.src, "event", os.path.join(self.home, "S"))["id"], "tag")
        self.assertEqual(r["done"], 1)
        tags = ph.read_tags(p)
        self.assertEqual(tags[0], "Photo")
        self.assertTrue(tags[1].startswith("2026-08-10"))
        ph.apply("last", "tag")
        self.assertEqual(len(ph.read_tags(p)), 2)  # tags aren't added twice

    def test_photos_library_refused(self):
        lib = os.path.join(self.home, "Pictures", "Photos Library.photoslibrary", "originals")
        os.makedirs(lib)
        with self.assertRaises(ValueError):
            ph.index(lib)
        self.put("a.jpg", jpg("2026:01:01 00:00:00"))
        ph.index(self.src)
        with self.assertRaises(ValueError):
            ph.plan(self.src, "event", lib)
        self.assertNotIn("Photos Library", json.dumps(ph.walk(os.path.join(self.home, "Pictures"))))

    def test_move_refused_across_disks_and_space_checked(self):
        self.put("a.jpg", jpg("2026:01:01 00:00:00"))
        ph.index(self.src)
        p = ph.plan(self.src, "event", os.path.join(self.home, "S"))
        real_stat = os.stat
        with mock.patch.object(ph.os, "stat", lambda x, *a, **k: os.stat_result(
                (0, 0, 99, 0, 0, 0, 0, 0, 0, 0)) if x == self.src else real_stat(x, *a, **k)):
            with self.assertRaises(ValueError):
                ph.apply(p["id"], "move")
        with mock.patch.object(ph.shutil, "disk_usage", lambda x: shutil._ntuple_diskusage(1, 1, 0)):
            with self.assertRaises(ValueError):
                ph.apply(p["id"], "copy")

    def test_find(self):
        self.library()
        ph.index(self.src)
        hits = [os.path.basename(h["path"]) for h in ph.find("beach august")]
        self.assertIn("IMG_0001.JPG", hits)
        self.assertNotIn("receipt.jpg", hits)
        self.assertEqual([os.path.basename(h["path"]) for h in ph.find("receipt")], ["receipt.jpg"])

    def test_no_helper_falls_back_to_python_exif(self):
        self.put("IMG_0001.JPG", jpg("2026:08:10 09:00:00"))
        with mock.patch.dict(os.environ, {"MACGUARD_PHOTO_SENSE": "/nonexistent"}):
            r = ph.index(self.src)
        self.assertFalse(r["vision"])
        row = ph.rows(self.src)[0]
        self.assertEqual((row["taken"], row["date_src"], row["make"]), ("2026-08-10T09:00:00", "exif", "Apple"))
        self.assertIn("without Swift", " ".join(ph.summary(self.src)["limits"]))

    def test_index_file_is_private(self):
        self.put("a.jpg", jpg("2026:01:01 00:00:00"))
        ph.index(self.src)
        self.assertEqual(stat.S_IMODE(os.stat(ph.db_path()).st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(os.stat(ph.photos_dir()).st_mode), 0o700)

    def test_mcp_tools(self):
        self.library()
        self.assertEqual(mcp.call_tool("photos_index", {"folder": self.src})["structuredContent"]["files"], 10)
        plan = mcp.call_tool("photos_plan", {"folder": self.src, "dest": os.path.join(self.home, "S")})["structuredContent"]
        self.assertEqual(plan["files"], 11)
        refused = mcp.call_tool("photos_apply", {"plan_id": plan["id"], "confirm": False})
        self.assertTrue(refused["isError"])
        done = mcp.call_tool("photos_apply", {"plan_id": plan["id"], "confirm": True})["structuredContent"]
        self.assertEqual(done["done"], 11)
        self.assertTrue(mcp.call_tool("photos_find", {"query": "dog"})["structuredContent"]["matches"])


@unittest.skipUnless(shutil.which("swiftc"), "needs swiftc (Command Line Tools)")
class TestRealHelper(TempHome):
    def test_compiles_and_reads_a_picture(self):
        with mock.patch.dict(os.environ, {"MACGUARD_PHOTO_SENSE": ""}), \
                mock.patch.object(ph, "BUNDLED_HELPER", os.path.join(self.tmp, "none")):
            binary = ph.helper()
            self.assertTrue(binary and binary.startswith(self.home), binary)
            self.assertEqual(ph.helper(), binary)  # cached by the source's hash
            pic = os.path.join(self.tmp, "red.png")
            with open(pic, "wb") as fh:
                fh.write(mf.png(64, 64))
            out = ph.sense([pic], binary)[pic]
        self.assertEqual((out["kind"], out["w"], out["h"]), ("image", 64, 64))
        self.assertIn("labels", out)
        self.assertTrue(out.get("fp"))


class TestPhotoWebRoutes(test_macguard.TestWebUI):
    def test_index_plan_apply(self):
        src = os.path.join(self.home, "P")
        os.makedirs(src)
        with open(os.path.join(src, "IMG_0001.JPG"), "wb") as fh:
            fh.write(jpg("2026:08:10 09:00:00"))
        stub = os.path.join(self.tmp, "stub")
        with open(stub, "w") as fh:
            fh.write(STUB)
        os.chmod(stub, 0o755)

        def wait():
            for _ in range(100):
                j = json.loads(self.req("/api/tools/job?name=photos")[1])
                if not j["running"]:
                    return j
                time.sleep(0.05)
        with mock.patch.dict(os.environ, {"MACGUARD_PHOTO_SENSE": stub}):
            self.assertEqual(self.req("/api/photos/index", body={"root": src})[0], 200)
            self.assertEqual(wait()["result"]["index"]["files"], 1)
            s = json.loads(self.req("/api/photos/summary?root=" + src)[1])
            self.assertEqual(s["files"], 1)
            code, p = self.req("/api/photos/plan", body={"root": src, "dest": os.path.join(self.home, "S")})
            p = json.loads(p)
            self.assertEqual((code, p["files"]), (200, 1))
            self.assertEqual(self.req("/api/photos/apply", body={"plan": p["id"], "mode": "copy"})[0], 200)
            self.assertEqual(wait()["result"]["apply"]["done"], 1)
            self.assertEqual(self.req("/api/photos/index", body={"root": "/nope"})[0], 400)
            self.assertEqual(self.req("/api/tools/job?name=evil")[0], 400)
            self.assertEqual(self.req("/api/photos/thumb?path=/etc/hosts")[0], 400)  # only indexed photos
            self.assertEqual(self.req("/api/photos/summary?root=" + src, token=None)[0], 403)


for _name in dir(test_macguard.TestWebUI):
    if _name.startswith("test_"):
        setattr(TestPhotoWebRoutes, _name, None)


if __name__ == "__main__":
    unittest.main()
