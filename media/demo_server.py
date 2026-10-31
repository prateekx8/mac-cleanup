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

APP_FINDINGS = [
    ("high", "App signature broken (modified after signing)", "PhotoTool 3.2 - /Applications/PhotoTool.app"),
    ("high", "End-of-life software - no security updates any more", "Adobe Flash Player 32.0"),
    ("medium", "Remote-access tool - a common attack vector; remove it if you don't use it", "AnyDesk 8.1"),
    ("medium", "Outdated app (Homebrew cask)", "zoom 6.0.2 -> 6.4.1  (brew upgrade --cask zoom)"),
    ("medium", "Outdated app (Homebrew cask)", "visual-studio-code 1.89.1 -> 1.97.2  (brew upgrade --cask visual-studio-code)"),
    ("medium", "Orphaned root helper (its app is gone, it still runs as root if loaded)", "/Library/PrivilegedHelperTools/com.oldvpn.helper"),
    ("low", "Intel-only app (likely unmaintained; needs Rosetta)", "Legacy Utility 1.4"),
    ("low", "42 outdated Homebrew packages", "openssl@3, curl, git, node, python@3.12, sqlite ...  (brew upgrade)"),
    ("info", "Network extension can see all traffic", "WireGuard (ABCDE12345) 1.0.16"),
]
K = 1024


def P(proc, pid, rx, tx, hosts, ports, exe):
    return dict(proc=proc, pid=pid, exe=exe, rx=rx * 6, tx=tx * 6, rx_rate=rx, tx_rate=tx, hosts=set(f"203.0.113.{i}" for i in range(hosts)),
                ports=set(ports), syn=0, port_hosts={}, new=0)


TRAFFIC = [
    P("updater", 4821, 9 * K, int(4.2 * K * K), 1, [443], "~/Library/Application Support/.cache/updater"),
    P("Google Chrome", 611, int(3.1 * K * K), 84 * K, 14, [443], "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    P("Dropbox", 733, 40 * K, 610 * K, 3, [443], "/Applications/Dropbox.app/Contents/MacOS/Dropbox"),
    P("Slack", 902, 120 * K, 22 * K, 4, [443], "/Applications/Slack.app/Contents/MacOS/Slack"),
    P("node", 2210, 18 * K, 9 * K, 1, [8888], "/opt/homebrew/bin/node"),
    P("Spotify", 812, 310 * K, 6 * K, 2, [443, 4070], "/Applications/Spotify.app/Contents/MacOS/Spotify"),
]
TRAFFIC_FINDINGS = [
    ("high", "Heavy upload (possible data exfiltration)", "updater (pid 4821) sent 25.2M in 6s (4.2M/s) to 203.0.113.0"),
    ("medium", "Unsigned program is using the internet", "updater (pid 4821) ~/Library/Application Support/.cache/updater"),
    ("low", "Traffic on uncommon ports", "node (pid 2210) -> ports 8888"),
]

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
    mg.apps_report = lambda online=False: (time.sleep(2.2), ([None] * 64, list(APP_FINDINGS)))[1]
    mg.traffic_sample = lambda seconds=6: (time.sleep(2.0), [dict(p) for p in TRAFFIC])[1]
    mg.analyze_traffic = lambda procs, seconds: list(TRAFFIC_FINDINGS)
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
