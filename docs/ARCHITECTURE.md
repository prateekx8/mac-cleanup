# Architecture

![mac-cleanup architecture](architecture.png)

([SVG version](architecture.svg), which adapts to light and dark themes.)

mac-cleanup is one Python module (`macguard.py`, standard library only) with four ways in: the CLI, a local web UI, a native macOS app, and an opt-in background watcher. Every feature calls read-only macOS tools and keeps its state in `~/.macguard`. Nothing is sent off the machine.

## Components

| Part | File | Responsibility |
|---|---|---|
| Engine and CLI | `macguard.py` | All logic, plus the `argparse` subcommands (`scan`, `clean`, `net`, `security`, `apps`, `traffic`, `uninstall`, `kill`, `watch`, `report`, `settings`, `ui`, `doctor`). |
| Web UI | `ui.html` | A single page with vanilla JS and glassmorphism styling. It talks to the engine's JSON API. |
| Native app | `app/main.swift` | An AppKit window with a `WKWebView`. It starts the engine and shows the UI. |
| App icon | `app/make_icon.swift` | Draws the original icon (gradient squircle with a sparkle) at build time. |
| Packaging | `build_app.sh` | Builds a universal `Mac Cleanup.app` (arm64 + x86_64), ad-hoc signs it, and makes a DMG. |
| Setup | `setup.sh`, `MacCleanup.command` | Checks prerequisites, installs the `macguard` command, runs `doctor` and the tests. |
| Tests | `tests/test_macguard.py` | 115 tests: unit tests on temp dirs and mocked system calls, plus live read-only checks. |

## Engines inside `macguard.py`

```mermaid
flowchart LR
  subgraph Cleanup
    J[JUNK registry<br/>safe / review] --> R[resolve: globs, simctl,<br/>docker, old versions,<br/>stale projects] --> S[scan_junk] --> C[clean_item<br/>HOME guard]
  end
  subgraph Network
    N1[netstat -anv] --> NS[net_snapshot]
    N2[arp · route · scutil · /etc/hosts] --> NS
    NS --> A[analyze_net<br/>exposed ports · bad ports ·<br/>unsigned · scans · ARP spoof]
  end
  subgraph Security
    SEC[firewall · SIP · Gatekeeper · FileVault<br/>sharing · launch items · stray keys]
  end
  subgraph Watch
    NS --> FP[fingerprint] --> D{diff vs<br/>baseline.json} --> EV[events.log + notification]
  end
```

### Cleanup

- `JUNK` is a declarative list. Each entry has an `id`, a `risk` (`safe` or `review`), and either glob `paths` or a `special` resolver (`simctl`, `docker`, `jetbrains`, `ndk`, `projects`, `downloads`).
- **Safe** items are caches that rebuild themselves. **Review** items need your decision.
- Project folders come in two kinds. **Dependencies** (`node_modules`, `.venv`, `venv`) are only offered once the project has gone stale. **Build output** (`target`, `build`, `dist`, `.next`, `__pycache__`, `.gradle`, lint and type caches, `cmake-build-*`) is also offered for active projects, through the optional `build-outputs` review check (`clean --builds`). Anything holding git-tracked files is skipped (`git ls-files`, cached once per repo), so a committed `dist/` is safe.
- Stale project folders only count when the project hasn't been edited for `--stale-days`. `build` and `dist` count only next to a matching build file, and `target` only next to `Cargo.toml` or `pom.xml`.
- `clean_item` refuses any path outside `$HOME` or shallower than four levels. Where a tool has its own cleanup command (`xcrun simctl delete unavailable`, `docker system prune`, `npm cache clean`, `brew cleanup`), that command is used.

### Docker and space insights

- Docker is split by risk. Build cache and dangling images are **safe**. Stopped containers, images no container uses, and dangling volumes are **review**, listed as `name (id)`. Cleanup removes exactly those IDs (`docker rm`, `docker rmi` and `docker volume rm` never use `--force`), so in-use objects stay. When Docker's engine isn't running, nothing is listed.
- `disk_health()`: **low** means under 10 GB or 10% free, **critical** under 5 GB or 5%. Scan and the UI show a banner, and the watcher alerts once per drop, then re-arms after recovery.
- `measure_dirs()` sizes app-data, container, dot-folder and project directories. `record_sizes()` keeps the last 30 snapshots in `~/.macguard/sizes.json`. `growth()` compares against the newest snapshot that's at least an hour old and drops a parent when a child explains the growth.
- `managed_storage()` reports large data that its owning app must remove: the Claude Cowork image, Docker's virtual disk, simulator runtimes, Ollama models, iPhone backups, Xcode archives and Time Machine local snapshots. Each comes with how to remove it. macguard never deletes these.

### Network

- `netstat -anv` lists every process's sockets without root. Process paths come from `ps`, and trust comes from `codesign` (cached per binary).
- Heuristics flag:
  - well-known services exposed beyond loopback (Redis, Docker API, VNC, AirPlay and so on)
  - known-bad ports
  - unsigned or temp-folder binaries
  - many connections from one remote address (a likely scan)
  - a gateway MAC address shared with another IP (ARP spoofing)
- **Limitation:** this inspects socket tables, not packets.

### Apps

- `app_inventory()` reads each bundle's `Info.plist` with `plistlib`. `app_trust()` adds the signer from `codesign -dv`, a seal check from `codesign --verify` (third-party apps only, run in parallel) and the architectures from `lipo -archs`.
- `analyze_apps()` flags:
  - broken seals (modified after signing)
  - unsigned or ad-hoc apps (browser web-app shims are skipped)
  - end-of-life and remote-access software (`RISKY_APPS`)
  - Intel-only apps on Apple Silicon
  - apps not updated in 3+ years
  - outdated Homebrew casks and formulae (`brew outdated --json=v2`, no auto-update)
  - orphaned root helpers and third-party system extensions
- **Limitation:** CVE matching needs an online vulnerability database, which isn't included. Outdated, unsigned and end-of-life software is the offline signal for "likely vulnerable". `--online` adds pending macOS updates from `softwareupdate --list`.

### Uninstall and leftovers

- `app_leftovers()` matches the app's data in `~/Library` by **exact** bundle ID, or by exact app name for names of 4+ characters that aren't generic. It covers Application Support, Caches, Preferences and ByHost, Containers, Group Containers, Application Scripts, Saved Application State, HTTPStorages, Cookies, WebKit, Logs and LaunchAgents, plus system `/Library/LaunchDaemons`, `/Library/LaunchAgents` and `/Library/PrivilegedHelperTools` entries named after the bundle ID.
- `do_uninstall()` refuses Apple, system and running apps. It moves each item to `~/.Trash` with `os.rename`, so it's recoverable, and never overwrites a name already there. For root-owned items it falls back to Finder, which asks for your password. The server re-plans from the app's path on every request, so the page never chooses which files go.
- `orphan_leftovers()` (the `app-leftovers` review item) lists reverse-DNS-named folders and plists whose ID no installed app, Apple app, launch item or running process owns. A shared vendor prefix is flagged "check first". Cleaning these also goes to the Trash.

### Quit app and everything under it

- `app_process_tree()` reads `ps -axo pid,ppid,uid,comm` once. It takes every process whose executable lives inside the app bundle (main app, helpers, XPC services, login items) or in `/Library/PrivilegedHelperTools/<bundle id>*`, adds all their descendants, and removes macguard itself and its ancestors, so it never kills the app or terminal it runs in.
- `kill_app()` first unloads the app's loaded launch agents (`launchctl bootout gui/<uid>/<label>`) so it can't respawn, which is what kept relaunching CCleaner. It sends TERM to the tree, waits up to 5 s, then sends KILL to survivors. Root-owned processes are reported for `sudo kill`. Core macOS processes (Finder, Dock, WindowServer, loginwindow…) are refused.
- A real end-to-end test compiles a tiny app binary that forks a child, then checks both are gone.

### Traffic

- `traffic_sample()` takes two `netstat -anv` snapshots a few seconds apart and diffs each socket's `rxbytes`/`txbytes` (TCP and UDP/QUIC) to get per-process rates and public destinations.
- `analyze_traffic()` flags:
  - heavy uploads by programs that aren't known uploaders (possible exfiltration)
  - outbound scanning (one port on 10+ hosts)
  - many unanswered SYNs
  - unsigned or temp-folder programs online
  - suspicious or uncommon ports

### Watch

- `fingerprint()` reduces a snapshot to listeners (ephemeral ports collapsed to `dyn`), programs talking to the internet, the gateway MAC, DNS servers and `/etc/hosts`.
- Each tick it diffs against `baseline.json`, logs new items, sends a macOS notification for medium and high events, and then folds them into the baseline so the same event doesn't alert twice.

## Web UI security

The UI server binds to **127.0.0.1 only**. Every API call needs:

1. a **per-launch random token**, embedded in the page and sent as `X-Token`, so other websites can't call the API (CSRF), and
2. a `Host` header of `127.0.0.1:<port>` or `localhost:<port>`, which blocks DNS-rebinding attacks.

`/api/clean` only accepts category ids from the most recent scan. It never takes paths from the client.

## Native app process model

```mermaid
sequenceDiagram
  participant App as Mac Cleanup.app (Swift)
  participant L as launchd (gui/uid)
  participant E as macguard.py ui (system python)
  App->>App: pick a free localhost port
  App->>L: bootstrap ~/.macguard/ui-session.plist (RunAtLoad, no KeepAlive)
  L->>E: start: ui --port N --parent-pid <app pid>
  App->>E: poll http://127.0.0.1:N/ until 200
  App->>App: load the page in WKWebView (JS confirm → native sheet)
  App-->>L: on quit: bootout ai.macguard.ui
  E-->>E: watchdog exits if the app pid disappears (crash)
```

**Why launchd instead of a child process?** On recent macOS a process only sees other processes' sockets if the system trusts the process responsible for it. The children of an ad-hoc signed app inherit its restrictions and see 0 sockets. Even "disclaiming" responsibility with `posix_spawn` didn't help. A launchd job running Apple's `/usr/bin/python3` sees everything, just like running from Terminal. The same reason explains why the CLI re-runs itself under `/usr/bin/python3` when started from Homebrew or pyenv Python.

## State (`~/.macguard`)

| File | Written by |
|---|---|
| `settings.json` | `settings`, the UI toggle |
| `baseline.json` | `watch` |
| `events.log` | `watch`, `clean` |
| `report.html` | `report` |
| `support-*.txt` | `doctor --bundle` |
| `app.log`, `ui-session.plist` | the native app |

## Design decisions

- **Standard library only.** Nothing to install or audit, and it runs on any Mac that has the Command Line Tools.
- **Dry run by default.** Deletion needs `--apply` plus typing `yes`, or a confirmation dialog in the UI.
- **The watcher is opt-in.** Nothing runs in the background or at login unless `settings background_watcher on` is set.
- **No root.** Every check works as the logged-in user.
