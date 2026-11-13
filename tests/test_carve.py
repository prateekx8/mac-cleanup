"""Tests for deep card recovery (macguard_carve): synthetic disk images only, never real cards or /dev.

FAT32, FAT16 and exFAT images come from hdiutil (no root): files are copied in, some deleted, then the image is
scanned and every recovered file is compared byte for byte. Carving runs on hand-built byte buffers.
"""
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
import zipfile
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macguard_carve as cv  # noqa: E402
import macguard_mcp as mcp  # noqa: E402
import media_fixtures as mf  # noqa: E402
import test_macguard  # noqa: E402
from test_macguard import TempHome  # noqa: E402

FILES = {"DCIM/100CANON/IMG_0001.JPG": mf.jpeg(exif=mf.exif_tiff(make="Canon"), body=bytes(range(256)) * 300),
         "DCIM/100CANON/Long holiday photo name.jpg": mf.jpeg(body=b"\x11" * 50000),
         "notes.png": mf.png(64, 64), "keep.jpg": mf.jpeg(body=b"\x22" * 9000)}
DELETE = ("DCIM/100CANON/IMG_0001.JPG", "DCIM/100CANON/Long holiday photo name.jpg", "notes.png")
IMAGES = {}


def make_image(folder, fs, layout):
    img = os.path.join(folder, f"{layout}-{fs.split()[-1]}.dmg")
    subprocess.run(["hdiutil", "create", "-quiet", "-size", "40m", "-fs", fs, "-layout", layout, "-volname", "CARD",
                    img], check=True, capture_output=True, timeout=120)
    mnt = tempfile.mkdtemp(dir=folder)
    out = subprocess.run(["hdiutil", "attach", "-nobrowse", "-mountroot", mnt, img], capture_output=True, text=True,
                         check=True, timeout=120).stdout.strip().splitlines()[-1].split("\t")
    dev, mp = out[0].strip(), out[-1].strip()
    try:
        for rel, data in FILES.items():
            p = os.path.join(mp, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "wb") as fh:
                fh.write(data)
        os.sync()
        for rel in DELETE:
            os.remove(os.path.join(mp, rel))
        os.sync()
    finally:
        subprocess.run(["hdiutil", "detach", "-force", dev], capture_output=True, timeout=120)
    return img


def setUpModule():
    if not shutil.which("hdiutil"):
        return
    IMAGES["dir"] = tempfile.mkdtemp(prefix="macguard-cards-")
    for fs, layout in (("MS-DOS FAT32", "MBRSPUD"), ("ExFAT", "GPTSPUD"), ("MS-DOS FAT16", "NONE")):
        try:
            IMAGES[fs] = make_image(IMAGES["dir"], fs, layout)
        except (subprocess.SubprocessError, OSError, IndexError):
            pass


def tearDownModule():
    if IMAGES.get("dir"):
        shutil.rmtree(IMAGES["dir"], ignore_errors=True)


class TestUndelete(TempHome):
    def scan(self, fs):
        if fs not in IMAGES:
            self.skipTest(f"hdiutil couldn't make a {fs} image here")
        return cv.scan(IMAGES[fs])

    def check_recovered(self, r, names):
        m = cv.open_ro(cv.last_scan()["image"])
        try:
            got = {i["path"]: hashlib.sha256(m[i["offset"]:i["offset"] + i["size"]]).hexdigest()
                   for i in r["items"] if i["source"] == "undelete" and i["state"] == "intact"}
        finally:
            m.close()
        want = {"/" + names(rel): hashlib.sha256(FILES[rel]).hexdigest() for rel in DELETE}
        self.assertEqual(got, want)
        self.assertFalse(any("keep.jpg" in (i["path"] or "") for i in r["items"]))  # live files aren't listed
        self.assertFalse([i for i in r["items"] if i["source"] == "carve"])  # carving skips live and undeleted data

    def test_fat32(self):
        # 8.3 names lose their first letter when deleted (no long name to rebuild it from)
        self.check_recovered(self.scan("MS-DOS FAT32"), lambda rel: rel.replace("IMG_0001", "_MG_0001")
                             .replace("notes.png", "_otes.png"))

    def test_fat16(self):
        self.check_recovered(self.scan("MS-DOS FAT16"), lambda rel: rel.replace("IMG_0001", "_MG_0001")
                             .replace("notes.png", "_otes.png"))

    def test_exfat_keeps_full_names(self):
        r = self.scan("ExFAT")
        self.check_recovered(r, lambda rel: rel)
        self.assertFalse([i for i in r["items"] if os.path.basename(i["path"]).startswith("._")])

    def test_everything_carves_live_files_too(self):
        if "ExFAT" not in IMAGES:
            self.skipTest("no exFAT image")
        r = cv.scan(IMAGES["ExFAT"], everything=True)
        carved = [i for i in r["items"] if i["source"] == "carve"]
        self.assertEqual([(c["size"], c["state"]) for c in carved], [(len(FILES["keep.jpg"]), "intact")])

    def test_save_writes_copies_with_names(self):
        r = self.scan("ExFAT")
        dest = os.path.join(self.home, "Recovered")
        s = cv.save([i["id"] for i in r["items"]], dest)
        self.assertEqual((s["saved"], s["failed"]), (3, []))
        with open(os.path.join(dest, "DCIM/100CANON/Long holiday photo name.jpg"), "rb") as fh:
            self.assertEqual(fh.read(), FILES["DCIM/100CANON/Long holiday photo name.jpg"])
        again = cv.save("all", dest)  # never overwrites: second copies get (2)
        self.assertEqual(again["saved"], 3)
        self.assertTrue(os.path.exists(os.path.join(dest, "notes (2).png")))


class TestCarving(unittest.TestCase):
    def blob(self):
        """A fake 'formatted card': zeros, with files at sector boundaries and junk between."""
        docx = io.BytesIO()
        with zipfile.ZipFile(docx, "w") as z:
            z.writestr("[Content_Types].xml", "<Types/>")
            z.writestr("word/document.xml", "<w:document/>")
        mp4 = mf.box(b"ftyp", b"isom\x00\x00\x02\x00isomiso2") + mf.box(b"moov", b"\x00" * 40) + mf.box(b"mdat", b"\x01" * 300)
        heic = mf.box(b"ftyp", b"heic\x00\x00\x00\x00mif1heic") + mf.box(b"meta", b"\x00" * 60) + mf.box(b"mdat", b"\x02" * 500)
        tif = mf.exif_tiff(make="NIKON CORPORATION", model="D850", software="NX Studio " + "x" * 81)  # even length: no pad byte the TIFF itself does not count
        pdf = b"%PDF-1.7\n1 0 obj<<>>endobj\nxref\n0 1\ntrailer<<>>\nstartxref\n9\n%%EOF\n"
        files = [("jpg", mf.jpeg(exif=mf.exif_tiff(make="Canon"), body=b"\xab" * 3000)), ("png", mf.png(20, 20)),
                 ("pdf", pdf), ("docx", docx.getvalue()), ("wav", mf.wav(samples=2000)), ("mp4", mp4),
                 ("heic", heic), ("nef", tif)]
        buf, at = bytearray(4096), []
        for ext, data in files:
            buf += b"\x00" * (-len(buf) % 512) + b"\x00" * 512
            at.append((ext, len(buf), data))
            buf += data
        buf += b"\x00" * 4096
        return bytes(buf), at

    def test_finds_each_format(self):
        buf, at = self.blob()
        got = {(c["offset"], c["ext"]): c for c in cv.carve(buf)}
        for ext, off, data in at:
            c = got.get((off, ext))
            self.assertIsNotNone(c, (ext, off, sorted(got)))
            self.assertEqual(buf[c["offset"]:c["offset"] + c["size"]], data, ext)
            self.assertNotEqual(c["intact"], False, ext)

    def test_truncated_jpeg_is_not_called_intact(self):
        j = mf.jpeg(body=b"\xab" * 3000)
        buf = b"\x00" * 512 + j[:-200] + b"\x00" * 1024
        self.assertEqual([c for c in cv.carve(buf) if c["ext"] == "jpg"], [])

    def test_unaligned_headers_are_ignored(self):
        buf = b"\x00" * 700 + mf.png(8, 8) + b"\x00" * 600
        self.assertEqual(cv.carve(buf), [])
        self.assertEqual(len(cv.carve(buf, aligned=0)), 1)

    def test_damaged_png_found_but_flagged(self):
        p = bytearray(mf.png(30, 30))
        p[-20] ^= 0xFF  # inside IDAT: checksum no longer matches
        c = cv.carve(b"\x00" * 512 + bytes(p) + b"\x00" * 512)
        self.assertEqual((c[0]["ext"], c[0]["intact"]), ("png", False))


class TestSafety(TempHome):
    def test_images_open_read_only(self):
        p = os.path.join(self.tmp, "x.img")
        with open(p, "wb") as fh:
            fh.write(b"\x00" * 4096)
        seen = []
        real = os.open
        with mock.patch.object(cv.os, "open", lambda path, flags, *a: seen.append(flags) or real(path, flags, *a)):
            cv.scan(p)
        self.assertEqual(seen, [os.O_RDONLY])

    def test_scan_refuses_devices(self):
        with self.assertRaises(ValueError):
            cv.scan("/dev/disk4")

    def info(self, **kw):
        d = {"id": "disk9", "name": "SD Card", "size": 1 << 20, "internal": False,
             "volumes": [{"id": "disk9s1", "mount": os.path.join(self.tmp, "CARD"), "encrypted": False}]}
        d.update(kw)
        return d

    def test_image_plan_refusals(self):
        import macguard_recover as rec
        with mock.patch.object(rec, "analyze", lambda ident, quick=False: self.info(internal=True)):
            with self.assertRaisesRegex(ValueError, "internal disk"):
                cv.image_plan("disk9")
        with mock.patch.object(rec, "analyze", lambda ident, quick=False: self.info(
                volumes=[{"id": "disk9s1", "mount": "", "encrypted": True}])):
            with self.assertRaisesRegex(ValueError, "encrypted"):
                cv.image_plan("disk9")
        with mock.patch.object(rec, "analyze", lambda ident, quick=False: self.info()):
            with self.assertRaisesRegex(ValueError, "isn't on the card"):
                cv.image_plan("disk9", os.path.join(self.tmp, "CARD", "out"))
            with mock.patch.object(cv.shutil, "disk_usage", lambda p: shutil._ntuple_diskusage(1, 1, 10)):
                with self.assertRaisesRegex(ValueError, "not enough space"):
                    cv.image_plan("disk9", os.path.join(self.home, "out"))
            p = cv.image_plan("disk9", os.path.join(self.home, "out"))
        script = cv.image_script(p, 501)
        self.assertIn("/dev/rdisk9", script)
        self.assertIn("-c", script)  # the worker runs inline: no file on disk that could be swapped
        self.assertNotIn("macguard_carve.py", script)
        self.assertIn("O_RDONLY", script)

    def test_image_device_flow(self):
        import macguard_recover as rec
        calls = []
        src = os.path.join(self.tmp, "fake-device")
        with open(src, "wb") as fh:
            fh.write(os.urandom(3 << 20))

        def admin(script, reason):
            calls.append(script)
            p = json.loads(json.dumps(plan_holder[0]))
            cv.image_worker(src, p["image"], p["map"], 3 << 20)
            return True, ""
        plan_holder = []
        real_plan = cv.image_plan
        with mock.patch.object(rec, "analyze", lambda ident, quick=False: self.info(size=3 << 20)), \
                mock.patch.object(cv, "image_plan", lambda *a: plan_holder.append(real_plan(*a)) or plan_holder[-1]):
            r = cv.image_device("disk9", os.path.join(self.home, "out"),
                                run=lambda cmd, **k: calls.append(cmd) or mock.Mock(returncode=0, stdout="", stderr=""),
                                run_admin=admin)
        self.assertEqual(calls[0], ["diskutil", "unmountDisk", "disk9"])
        self.assertEqual(calls[-1], ["diskutil", "mountDisk", "disk9"])
        self.assertTrue(r["complete"])
        with open(r["image"], "rb") as a, open(src, "rb") as b:
            self.assertEqual(a.read(), b.read())

    def test_worker_zero_fills_bad_sectors(self):
        src = os.path.join(self.tmp, "dev")
        with open(src, "wb") as fh:
            fh.write(b"\x07" * (2 << 20))
        img, mp = os.path.join(self.tmp, "o.img"), os.path.join(self.tmp, "o.map")
        real_read, real_lseek, pos = os.read, os.lseek, {}

        def lseek(fd, off, how):
            pos[fd] = off
            return real_lseek(fd, off, how)

        def read(fd, n):
            if pos.get(fd) is not None and pos[fd] <= 1048576 + 1024 < pos[fd] + n:
                raise OSError(5, "I/O error")
            return real_read(fd, n)
        with mock.patch("os.read", read), mock.patch("os.lseek", lseek):
            cv.image_worker(src, img, mp, 2 << 20)
        with open(mp) as fh:
            bad = json.load(fh)["bad"]
        self.assertEqual(bad, [[1048576 + 1024, 1048576 + 1536]])
        with open(img, "rb") as fh:
            data = fh.read()
        self.assertEqual(len(data), 2 << 20)
        self.assertEqual(data[1048576 + 1024:1048576 + 1536], bytes(512))
        self.assertEqual(data[1048576 + 1536:1048576 + 2048], b"\x07" * 512)

    def test_mcp_needs_confirm(self):
        for tool, args in (("recover_image_card", {"disk": "disk9"}), ("recover_save_files", {"ids": ["all"]})):
            r = mcp.call_tool(tool, dict(args, confirm=False))
            self.assertTrue(r["isError"])
            self.assertIn("confirm=true", r["content"][0]["text"])


class TestCarveWebRoutes(test_macguard.TestWebUI):
    def test_scan_preview_save(self):
        if "ExFAT" not in IMAGES:
            self.skipTest("no exFAT image")

        def wait(name):
            for _ in range(200):
                j = json.loads(self.req(f"/api/tools/job?name={name}")[1])
                if not j["running"]:
                    return j
                time.sleep(0.05)
        self.assertEqual(self.req("/api/recover/scan", body={"image": "/nope.img"})[0], 400)
        self.assertEqual(self.req("/api/recover/scan", body={"image": IMAGES["ExFAT"]})[0], 200)
        r = wait("recover-scan")["result"]
        png = next(i for i in r["items"] if i["name"] == "notes.png")
        rq = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/recover/preview?id={png['id']}")
        rq.add_header("X-Token", self.token)
        with urllib.request.urlopen(rq, timeout=10) as resp:
            self.assertEqual((resp.status, resp.headers["Content-Type"], resp.read()), (200, "image/png", FILES["notes.png"]))
        self.assertEqual(self.req("/api/recover/preview?id=999")[0], 404)
        dest = os.path.join(self.home, "Saved")
        self.assertEqual(self.req("/api/recover/save", body={"ids": [png["id"]], "to": dest})[0], 200)
        self.assertEqual(wait("recover-save")["result"]["saved"], 1)
        self.assertTrue(os.path.exists(os.path.join(dest, "notes.png")))
        self.assertEqual(self.req("/api/recover/scan", body={"image": IMAGES["ExFAT"]}, token=None)[0], 403)


for _name in dir(test_macguard.TestWebUI):
    if _name.startswith("test_"):
        setattr(TestCarveWebRoutes, _name, None)


if __name__ == "__main__":
    unittest.main()
