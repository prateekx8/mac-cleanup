"""Install and troubleshooting checks: setup.sh, build_app.sh, doctor's fixes and the install guide.

  /usr/bin/python3 -m unittest discover -s tests -v
"""
import os
import re
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from test_macguard import TempHome  # noqa: E402
import macguard as mg  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with open(os.path.join(ROOT, rel)) as fh:
        return fh.read()


class TestScripts(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for f in ("setup.sh", "build_app.sh", "MacCleanup.command"):
            r = subprocess.run(["bash", "-n", os.path.join(ROOT, f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{f}: {r.stderr}")

    def test_setup_help_and_bad_option(self):
        r = subprocess.run(["bash", os.path.join(ROOT, "setup.sh"), "--help"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        for opt in ("--app", "--test", "--uninstall"):
            self.assertIn(opt, r.stdout)
        r = subprocess.run(["bash", os.path.join(ROOT, "setup.sh"), "--bogus"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_app_bundles_every_engine_module(self):
        build = read("build_app.sh")
        self.assertIn('"$DIR"/macguard*.py', build)
        modules = sorted(f for f in os.listdir(ROOT) if re.match(r"macguard.*\.py$", f))
        self.assertIn("macguard_devsec.py", modules)
        for m in modules:  # the post-copy import check names each module macguard.py loads on demand
            self.assertIn(m[:-3], build)

    def test_installed_command_detects_a_moved_folder(self):
        setup = read("setup.sh")
        self.assertIn("the mac-cleanup folder is gone", setup)
        self.assertIn('exec $PY "$DIR/macguard.py"', setup)  # doctor parses this line


class TestDoctor(TempHome):
    def checks(self):
        with mock.patch.object(mg, "disk_info", lambda: {"total": 100 << 30, "used": 1, "free": 50 << 30}):
            return {name: (ok, detail) for ok, name, detail in mg.doctor_checks()}

    def test_command_pointing_to_a_missing_folder_fails_with_a_fix(self):
        os.makedirs(os.path.join(self.home, ".local/bin"))
        with open(os.path.join(self.home, ".local/bin/macguard"), "w") as fh:
            fh.write('#!/bin/bash\nexec /usr/bin/python3 "/nowhere/mac-cleanup/macguard.py" "$@"\n')
        ok, detail = self.checks()["macguard command"]
        self.assertFalse(ok)
        self.assertIn("run ./setup.sh from the new folder", detail)

    def test_command_pointing_here_passes(self):
        os.makedirs(os.path.join(self.home, ".local/bin"))
        with open(os.path.join(self.home, ".local/bin/macguard"), "w") as fh:
            fh.write(f'#!/bin/bash\nexec /usr/bin/python3 "{os.path.join(ROOT, "macguard.py")}" "$@"\n')
        self.assertTrue(self.checks()["macguard command"][0])

    def test_not_installed_is_optional(self):
        self.assertIsNone(self.checks()["macguard command"][0])

    def test_engine_files_and_low_disk(self):
        c = self.checks()
        self.assertTrue(c["Engine files"][0])
        with mock.patch.object(mg, "disk_info", lambda: {"total": 100 << 30, "used": 1, "free": 100 << 20}):
            low = {name: (ok, d) for ok, name, d in mg.doctor_checks()}["Free disk space"]
        self.assertFalse(low[0])
        self.assertIn("macguard scan", low[1])

    def test_every_failure_carries_advice(self):
        for name, (ok, detail) in self.checks().items():
            if ok is False:
                self.assertTrue(len(detail) > 10, name)


class TestGuide(unittest.TestCase):
    def anchors(self, text):
        return {re.sub(r"[^a-z0-9 -]", "", h.strip().lower()).replace(" ", "-")
                for h in re.findall(r"^#+ (.+)$", text, re.M)}

    def test_guide_links_resolve(self):
        guide = read("docs/INSTALL.md")
        heads = self.anchors(guide)
        for a in re.findall(r"\]\(#([^)]+)\)", guide):
            self.assertIn(a, heads, a)
        for doc in ("README.md", "docs/SUPPORT.md"):
            for a in re.findall(r"INSTALL\.md#([a-z0-9-]+)", read(doc)):
                self.assertIn(a, heads, f"{doc} -> #{a}")

    def test_guide_covers_the_problems_people_hit(self):
        guide = read("docs/INSTALL.md")
        for phrase in ("permission denied", "command not found: macguard", "command line developer tools",
                       "Open Anyway", "damaged", "engine did not start", "Address already in use", "doctor --bundle",
                       "--uninstall"):
            self.assertIn(phrase, guide)

    def test_design_docs_link_each_other(self):
        for doc, links in (("docs/TOOLS.md", ("RECOVERY.md", "AI-DETECTION.md")),
                           ("docs/RECOVERY.md", ("TOOLS.md",)), ("docs/AI-DETECTION.md", ("TOOLS.md",))):
            text = read(doc)
            for target in links:
                self.assertIn(f"]({target}", text, f"{doc} -> {target}")
                self.assertTrue(os.path.exists(os.path.join(ROOT, "docs", target)), target)
        for target in ("docs/TOOLS.md", "docs/RECOVERY.md", "docs/AI-DETECTION.md"):
            self.assertIn(f"]({target})", read("README.md"), target)

    def test_guide_commands_exist(self):
        out = subprocess.run([sys.executable, os.path.join(ROOT, "macguard.py"), "--help"], capture_output=True,
                             text=True).stdout
        for cmd in set(re.findall(r"`macguard ([a-z-]+)", read("docs/INSTALL.md"))):
            self.assertIn(cmd, out, cmd)


if __name__ == "__main__":
    unittest.main()
