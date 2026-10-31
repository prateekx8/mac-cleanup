#!/usr/bin/python3
"""Serve the real Mac Cleanup UI with made-up data, for screenshots and videos.

Nothing on this Mac is scanned, shown or deleted: every engine call the UI makes is
replaced with fake data, and "clean" only pretends.

  /usr/bin/python3 media/demo_server.py [--port 8790]
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import macguard as mg  # noqa: E402

G = 1024 ** 3
M = 1024 ** 2
DISK = {"total": int(494.4 * G), "used": int(431.2 * G), "free": int(63.2 * G)}


def entries(*pairs):
    return [(p, s, l) for p, s, l in pairs]


SCAN = [
    dict(id="sim-unavailable", name="Unavailable iOS simulators", risk="safe", note="",
         entries=entries(("~/Library/Developer/CoreSimulator/Devices/3F2A…", int(6.1 * G), "iPhone 16 Pro · iOS 18.2"),
                         ("~/Library/Developer/CoreSimulator/Devices/91BC…", int(5.1 * G), "iPad Air · iOS 18.2"))),
    dict(id="xcode-derived", name="Xcode DerivedData", risk="safe", note="",
         entries=entries(("~/Library/Developer/Xcode/DerivedData/Weather-ab12…", int(2.9 * G), ""),
                         ("~/Library/Developer/Xcode/DerivedData/Notes-cd34…", int(1.4 * G), ""))),
    dict(id="jetbrains-old", name="Old JetBrains IDE versions", risk="safe", note="",
         entries=entries(("~/Library/Application Support/JetBrains/IntelliJIdea2024.3", int(4.1 * G), ""),)),
    dict(id="xcode-devicesupport", name="Xcode iOS DeviceSupport", risk="safe", note="re-created when a device is connected",
         entries=entries(("~/Library/Developer/Xcode/iOS DeviceSupport/17.5 (21F79)", int(2.5 * G), ""),)),
    dict(id="gradle", name="Gradle caches", risk="safe", note="re-downloaded on next build",
         entries=entries(("~/.gradle/caches", int(1.6 * G), ""),)),
    dict(id="npm", name="npm cache", risk="safe", note="",
         entries=entries(("~/.npm/_cacache", int(980 * M), ""),)),
    dict(id="pip-uv", name="pip / uv caches", risk="safe", note="",
         entries=entries(("~/.cache/pip", int(466 * M), ""),)),
    dict(id="android-avd", name="Android emulator images", risk="review", note="",
         entries=entries(("~/.android/avd/Pixel_8_API_35.avd", int(4.5 * G), ""),)),
    dict(id="project-artifacts", name="Stale project build dirs", risk="review", note="",
         entries=entries(("~/Projects/old-landing/node_modules", int(812 * M), "last edited 2026-03-02"),
                         ("~/Projects/rust-cli/target", int(640 * M), "last edited 2026-02-11"))),
    dict(id="docker-install-tmp", name="Stuck Docker installer download", risk="review", note="quit Docker Desktop first",
         entries=entries(("~/Library/Application Support/com.docker.install/in_progress", int(2.1 * G), ""),)),
]
for r in SCAN:
    r["size"] = sum(e[1] for e in r["entries"])

SECURITY = [
    ("high", "macOS firewall is OFF", "System Settings > Network > Firewall > turn on"),
    ("medium", "Screen Sharing is enabled", "System Settings > General > Sharing > Screen Sharing off if unused"),
    ("medium", "Private key / secret file in ~/Downloads", "~/Downloads/server.pem - move to ~/.ssh or a password manager"),
    ("low", "Firewall stealth mode is off", "Turn on 'Stealth mode' so the Mac ignores probes/pings"),
    ("ok", "System Integrity Protection on", ""),
    ("ok", "Gatekeeper on", ""),
    ("ok", "FileVault on", ""),
]


def L(port, proc, host="*"):
    return dict(proto="tcp4", lhost=host, lport=port, rhost="*", rport=None, state="LISTEN", proc=proc, pid=100 + port % 900,
                exe=f"/System/Library/CoreServices/{proc}")


SNAP = dict(listeners=[L(5000, "ControlCenter"), L(7000, "ControlCenter"), L(5900, "launchd"), L(6379, "redis-server"),
                       L(5432, "postgres", "127.0.0.1"), L(3000, "node", "127.0.0.1")],
            conns=[], arp=[], gateway="192.168.1.1", iface="en0", gateway_mac="a4:2b:b0:12:34:56",
            dns=["1.1.1.1", "9.9.9.9"], hosts=[], time=0)

settings = dict(mg.DEFAULT_SETTINGS)


def fake_scan(*a, **k):
    time.sleep(1.6)  # feels like a real scan in recordings
    return [dict(r) for r in SCAN]


def fake_clean(r):
    time.sleep(0.4)
    return r["size"]


def fake_disk():
    return dict(DISK)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8790)
    a = ap.parse_args()
    freed = {"n": 0}

    def clean(r):
        n = fake_clean(r)
        freed["n"] += n
        DISK["free"] += n
        DISK["used"] -= n
        return n

    mg.scan_junk = fake_scan
    mg.clean_item = clean
    mg.disk_info = fake_disk
    mg.cmd_security = lambda *a, **k: list(SECURITY)
    mg.net_snapshot = lambda: SNAP
    mg.signature = lambda path: "apple" if "redis" not in path else "developer:Redis Ltd"
    mg.load_settings = lambda: dict(settings)
    mg.save_settings = lambda s: settings.update(s)
    mg.install_agent = lambda interval: (True, "")
    mg.remove_agent = lambda: None
    mg.log_event = lambda *a: None
    mg.run = lambda cmd, timeout=60: (1, "", "")  # launchctl print -> "not running"
    mg.cmd_ui(argparse.Namespace(port=a.port, no_open=True, stale_days=30, parent_pid=None))


if __name__ == "__main__":
    main()
