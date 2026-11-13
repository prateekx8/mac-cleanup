"""Tests for the AI image and voice check (macguard_aicheck): synthetic files only, c2patool stubbed."""
import io
import json
import os
import random
import struct
import sys
import types
import unittest
import urllib.error
import urllib.parse
import urllib.request
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macguard_aicheck as ai  # noqa: E402
import macguard_mcp as mcp  # noqa: E402
import macguard_tools as mtools  # noqa: E402
import media_fixtures as mf  # noqa: E402
import test_macguard  # noqa: E402
from test_macguard import TempHome  # noqa: E402

NO_TOOLS = mock.patch.object(ai.shutil, "which", lambda name: None)  # c2patool/exiftool never run unless stubbed


class TestCbor(unittest.TestCase):
    def test_round_trip(self):
        v = {"a": [1, -5, 2 ** 40, "x", b"\x00\x01", True, None, {"n": 1.5}], "b": "ü"}
        self.assertEqual(ai.cbor_loads(mf.cbor(v)), v)

    def test_indefinite_and_tags(self):
        raw = b"\x9f\x01\x02\xff" + b""  # [_ 1, 2]
        self.assertEqual(ai.cbor_loads(raw), [1, 2])
        self.assertEqual(ai.cbor_loads(b"\xc0\x63abc"), "abc")  # tag 0 kept as its value
        self.assertEqual(ai.cbor_loads(b"\x7f\x61a\x61b\xff"), "ab")

    def test_damaged_input_fails_safely(self):
        for bad in (b"\x9a\xff\xff\xff\xff", b"\x5a\x00\x10\x00\x00ab", b"\x81" * 100 + b"\x01", b"", b"\xbf\x01"):
            with self.assertRaises(ai.Damaged):
                ai.cbor_loads(bad)


class TestParsers(unittest.TestCase):
    def test_exif_dates_camera_gps(self):
        t = mf.exif_tiff(make="Canon", model="EOS R6", software="Firmware 1.0", taken="2026:11:13 10:00:00",
                         offset="+05:30", gps=(-33.86, 151.21), comment="hello")
        ex = ai.parse_tiff(t)
        self.assertEqual((ex["make"], ex["model"], ex["taken"], ex["offset"], ex["comment"]),
                         ("Canon", "EOS R6", "2026:11:13 10:00:00", "+05:30", "hello"))
        self.assertAlmostEqual(ex["gps"][0], -33.86, places=3)
        self.assertAlmostEqual(ex["gps"][1], 151.21, places=3)

    def test_c2pa_store_in_one_piece_and_split_over_app11(self):
        store = mf.c2pa_store("compositeWithTrainedAlgorithmicMedia", "Adobe Photoshop 26")
        whole = ai.read_c2pa(ai.find_c2pa_store(b"junk" * 10 + store + b"tail"))
        self.assertEqual(whole["sources"], ["compositeWithTrainedAlgorithmicMedia"])
        self.assertEqual(whole["generator"], "Adobe Photoshop 26 1")
        segs = mf.app11_segments(store, size=33)
        self.assertGreater(len(segs), 5)
        split = ai.read_c2pa(ai.jpeg_app11_store(segs))
        self.assertEqual(split["sources"], whole["sources"])

    def test_xmp_attribute_and_element_forms(self):
        x = mf.xmp(source="trainedAlgorithmicMedia", tool="Midjourney", description="a prompt").decode()
        got = ai.read_xmp(x)
        self.assertTrue(got["source"][0].endswith("trainedAlgorithmicMedia"))
        self.assertEqual(got["tool"], ["Midjourney"])
        self.assertEqual(got["description"], ["a prompt"])

    def test_sniff(self):
        cases = {"jpeg": mf.jpeg(), "png": mf.png(), "wav": mf.wav(), "mp3": mf.mp3([("TIT2", "x")]),
                 "m4a": mf.m4a({"©nam": "x"}), "tiff": mf.exif_tiff(make="x")}
        for fmt, b in cases.items():
            self.assertEqual(ai.sniff(b), fmt, fmt)
        self.assertIsNone(ai.sniff(b"plain text"))


@NO_TOOLS
class TestVerdicts(TempHome):
    def check(self, name, data, **kw):
        p = os.path.join(self.tmp, name)
        with open(p, "wb") as fh:
            fh.write(data)
        return ai.check(p, **kw)

    def test_no_markers_never_says_real(self):
        r = self.check("cam.jpg", mf.jpeg(exif=mf.exif_tiff(make="Canon", model="EOS R6", taken="2026:01:01 10:00:00")))
        self.assertEqual((r["verdict"], r["confidence"]), ("no-markers", "none"))
        self.assertIn("does NOT mean it's real", r["headline"])
        text = json.dumps(r).lower()
        self.assertNotIn("is real", text.replace("doesn't mean real", "").replace("does not mean it's real", ""))
        self.assertTrue(any("proves nothing" in e["detail"] for e in r["evidence"]))  # camera EXIF isn't proof

    def test_image_markers(self):
        cases = [
            ("c2pa.png", mf.png(chunks=[(b"caBX", mf.c2pa_store())]), "ai-declared", "strong"),
            ("edit.jpg", mf.jpeg(app11=mf.app11_segments(mf.c2pa_store("compositeWithTrainedAlgorithmicMedia"))),
             "ai-edited", "strong"),
            ("xmp.jpg", mf.jpeg(xmp_packet=mf.xmp(source="trainedAlgorithmicMedia")), "ai-declared", "moderate"),
            ("a1111.png", mf.png(texts={"parameters": "cat\nSteps: 20, Sampler: Euler, Seed: 1, Model: sdxl"}),
             "ai-declared", "moderate"),
            ("comfy.png", mf.png(texts={"prompt": '{"3": {"class_type": "KSampler"}}'}), "ai-declared", "moderate"),
            ("tool.jpg", mf.jpeg(exif=mf.exif_tiff(software="Adobe Firefly")), "ai-declared", "moderate"),
            ("synthetic.png", mf.png(chunks=[(b"caBX", mf.c2pa_store("compositeSynthetic"))]), "info", "weak"),
            ("camera-dst.jpg", mf.jpeg(xmp_packet=mf.xmp(source="digitalCapture")), "no-markers", "none"),
            ("photoshop.jpg", mf.jpeg(exif=mf.exif_tiff(software="Adobe Photoshop 26.0")), "no-markers", "none"),
        ]
        for name, data, verdict, conf in cases:
            r = self.check(name, data)
            self.assertEqual((r["verdict"], r["confidence"]), (verdict, conf), (name, r["headline"]))
            self.assertEqual(r["tool"], "ai-image")
            self.assertTrue(r["limits"])

    def test_voice_markers(self):
        cases = [
            ("tts.wav", mf.wav({"ISFT": "ElevenLabs v2"}), "ai-declared"),
            ("tts.mp3", mf.mp3([("TSSE", "ElevenLabs")]), "ai-declared"),
            ("tts.m4a", mf.m4a({"©too": "OpenAI TTS"}), "ai-declared"),
            ("c2pa.wav", mf.wav(extra_chunks=[(b"C2PA", mf.c2pa_store())]), "ai-declared"),
            ("c2pa.mp3", mf.mp3([("GEOB", "application/c2pa", mf.c2pa_store())]), "ai-declared"),
            ("lavf.mp3", mf.mp3([("TSSE", "Lavf61.1.100")]), "no-markers"),  # an encoder isn't a generator
            ("song.mp3", mf.mp3([("TIT2", "Bark at the moon"), ("TPE1", "Band")]), "no-markers"),
        ]
        for name, data, verdict in cases:
            r = self.check(name, data)
            self.assertEqual(r["verdict"], verdict, (name, r["headline"], r["evidence"]))
            self.assertEqual(r["tool"], "ai-voice")
        r = self.check("x.wav", mf.wav())
        self.assertTrue(any("voice services" in l for l in r["limits"]))

    def test_faked_metadata_is_declared_not_proven(self):
        r = self.check("fake.png", mf.png(texts={"Software": "Midjourney"}))
        self.assertEqual((r["verdict"], r["confidence"]), ("ai-declared", "moderate"))
        self.assertIn("added or faked", " ".join(r["limits"]))

    def test_c2patool_validates_or_fails(self):
        data = mf.jpeg(app11=mf.app11_segments(mf.c2pa_store(generator="Adobe Firefly")))

        def stub(state, failures=()):
            out = {"active_manifest": "m", "manifests": {"m": {"signature_info": {"issuer": "Adobe Inc."}}},
                   "validation_state": state, "validation_status": [{"code": c} for c in failures]}
            return lambda *a, **k: types.SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr="")
        with mock.patch.object(ai.shutil, "which", lambda n: "/usr/local/bin/c2patool" if n == "c2patool" else None):
            ok = self.check("signed.jpg", data, run=stub("Valid"))
            bad = self.check("broken.jpg", data, run=stub("Invalid", ["assertion.dataHash.mismatch"]))
        self.assertEqual((ok["verdict"], ok["confidence"]), ("ai-proven", "proven"))
        self.assertIn("Adobe Inc.", ok["headline"])
        self.assertEqual((bad["verdict"], bad["confidence"]), ("ai-declared", "weak"))
        self.assertIn("FAILED", bad["evidence"][0]["detail"])
        nostub = self.check("unsigned.jpg", data)
        self.assertIn("brew install c2patool", " ".join(nostub["next"]))

    def test_unsupported_and_too_big(self):
        self.assertEqual(self.check("x.txt", b"hello")["verdict"], "unsupported")
        with mock.patch.object(ai, "MAX_BYTES", 10):
            r = self.check("big.png", mf.png())
        self.assertEqual(r["verdict"], "unsupported")
        self.assertIn("over", r["headline"])

    def test_damaged_files_never_crash(self):
        rnd = random.Random(7)
        seeds = [mf.jpeg(exif=mf.exif_tiff(make="X", taken="2026:01:01 00:00:00"),
                         app11=mf.app11_segments(mf.c2pa_store())),
                 mf.png(texts={"parameters": "Steps: 1, Seed: 2"}, chunks=[(b"caBX", mf.c2pa_store())]),
                 mf.wav({"ISFT": "x"}, [(b"C2PA", mf.c2pa_store())]), mf.mp3([("TSSE", "x"), ("COMM", "y")]),
                 mf.m4a({"©too": "x"})]
        for i in range(300):
            b = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randint(1, 8)):
                b[rnd.randrange(len(b))] = rnd.randrange(256)
            if rnd.random() < 0.3:
                b = b[:rnd.randrange(8, len(b))]
            r = self.check(f"f{i}", bytes(b))
            self.assertIn(r["verdict"], mtools.VERDICTS)

    def test_huge_declared_lengths(self):
        png = bytearray(mf.png(texts={"a": "b"}))
        struct.pack_into(">I", png, 33, 0x7FFFFFF0)  # first chunk after IHDR claims ~2 GB
        r = self.check("liar.png", bytes(png))
        self.assertIn(r["verdict"], ("no-markers", "unsupported"))

    def test_mcp_ai_check(self):
        p = os.path.join(self.tmp, "a.png")
        with open(p, "wb") as fh:
            fh.write(mf.png(texts={"parameters": "Steps: 2, Sampler: x"}))
        r = mcp.call_tool("ai_check", {"path": p})["structuredContent"]
        self.assertEqual(r["verdict"], "ai-declared")
        self.assertIn("no such file", mcp.call_tool("ai_check", {"path": p + "x"})["content"][0]["text"])


class TestUploadRoute(test_macguard.TestWebUI):
    def upload(self, data, name="pic.png", token="use"):
        url = f"http://127.0.0.1:{self.port}/api/tools/ai-check?name={urllib.parse.quote(name)}"
        r = urllib.request.Request(url, data=data, method="POST")
        if token:
            r.add_header("X-Token", self.token if token == "use" else token)
        r.add_header("Content-Type", "application/octet-stream")
        try:
            with urllib.request.urlopen(r, timeout=10) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def test_upload_is_checked_and_deleted(self):
        with NO_TOOLS:
            code, r = self.upload(mf.png(texts={"parameters": "Steps: 2, Sampler: x"}), "my photo.png")
        self.assertEqual(code, 200, r)
        self.assertEqual((r["verdict"], r["file"]), ("ai-declared", "my photo.png"))
        inbox = os.path.join(test_macguard.mg.STATE_DIR, "tools", "inbox")
        self.assertEqual(os.listdir(inbox), [])
        self.assertEqual(oct(os.stat(inbox).st_mode & 0o777), "0o700")

    def test_upload_needs_token_and_size_limit(self):
        self.assertEqual(self.upload(mf.png(), token=None)[0], 403)
        self.assertEqual(self.upload(mf.png(), token="wrong")[0], 403)
        with mock.patch.object(mtools, "MAX_UPLOAD", 20):
            try:  # the server answers before reading the body, so the client may see a reset instead of the 413
                self.assertEqual(self.upload(mf.png())[0], 413)
            except (ConnectionResetError, BrokenPipeError, urllib.error.URLError):
                pass
            self.assertEqual(os.listdir(os.path.join(test_macguard.mg.STATE_DIR, "tools", "inbox"))
                             if os.path.isdir(os.path.join(test_macguard.mg.STATE_DIR, "tools", "inbox")) else [], [])


for _name in dir(test_macguard.TestWebUI):
    if _name.startswith("test_"):
        setattr(TestUploadRoute, _name, None)


if __name__ == "__main__":
    unittest.main()
