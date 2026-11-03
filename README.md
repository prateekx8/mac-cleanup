# Mac Cleanup

**Clean, monitor and secure a macOS development machine. Native app, web UI or CLI.**

Dev Macs pile up gigabytes of rebuildable junk: Xcode DerivedData, orphaned iOS simulators, old IDE versions, and npm, Gradle, Cargo and pip caches, plus stale `node_modules`. They also tend to have services quietly open to the network. Mac Cleanup (CLI name `macguard`) finds both, explains what it found, and fixes it only when you ask.

- **Disk cleanup**: sizes up junk by category (Docker split into build cache, dangling images, stopped containers, unused images and volumes). Each category is marked **safe** (caches that regenerate) or **review** (your call). It deletes nothing without confirmation, and only inside your home folder.
- **Space insights**: a low-disk warning (also in the watcher), what grew since the last scan, and big data that only its own app should remove (Claude Cowork image, Docker's virtual disk, simulator runtimes, Ollama models, iPhone backups), with how to remove each.
- **Security audit**: firewall and stealth mode, SIP, Gatekeeper, FileVault, Screen Sharing and SSH, launch agents and daemons (unsigned or orphaned), and private keys left in Downloads, Desktop or Documents.
- **Apps and traffic**: flags installed apps with broken or missing signatures, outdated, end-of-life or remote-access apps and orphaned root helpers, and samples live traffic per process to spot heavy uploads, scanning or odd destinations.
- **Network analysis**: every listening port with its owning binary and code signature, connections by process, gateway, DNS and ARP. Flags exposed services, known-bad ports, unsigned programs, inbound scans and ARP spoofing.
- **Watcher (opt-in)**: alerts on new open ports, gateway MAC changes, DNS or `/etc/hosts` changes. Off by default.
- **Three front ends**: a native **Mac Cleanup.app**, a local **web UI** with a glass design, and the **`macguard` CLI**.

Standard-library Python plus a small Swift wrapper. No root, no telemetry, nothing leaves your Mac.

![Mac Cleanup: scan results with safe items pre-selected](docs/screenshot.png)

## Quick start

```bash
git clone https://github.com/prateekx8/mac-cleanup.git
cd mac-cleanup
./setup.sh                      # checks prerequisites, installs `macguard`, runs the tests
./build_app.sh --install        # optional: native Mac Cleanup.app in /Applications
```

Requirements: macOS 13 or later, plus Apple's Command Line Tools (`xcode-select --install`) for `/usr/bin/python3` and `swiftc`.

| I want… | Do this |
|---|---|
| The app | `./build_app.sh --install`, then open **Mac Cleanup** from Applications (or use `dist/MacCleanup.dmg`) |
| One-click setup and the UI | Double-click **`MacCleanup.command`** in Finder |
| The CLI | `./setup.sh`, then open a new terminal and run `macguard --help` |

`setup.sh` checks prerequisites (macOS, Apple's Command Line Tools for `/usr/bin/python3`, system tools), installs the `macguard` command into `~/.local/bin`, runs `macguard doctor` and the test suite. It's safe to re-run. `./setup.sh --uninstall` removes everything.

## CLI

| Command | What it does |
|---|---|
| `macguard scan` | Disk junk analysis, low-disk warning, what grew since the last scan, app-managed storage. Read-only. |
| `macguard clean` | Dry run of the **safe** cleanup. |
| `macguard clean --apply` | Delete safe items after you type `yes`. |
| `macguard clean --only android-avd,project-artifacts --apply` | Clean specific **review** items. |
| `macguard clean --builds --apply` | Optional: also remove build output in **active** projects (`target`, `build`, `dist`, `.next`, `__pycache__`, `cmake-build-*`…). Dependencies such as `node_modules` and `.venv` are never touched, and neither is anything committed to git. |
| `macguard security` | Security posture audit. |
| `macguard net` | Network snapshot and threat findings. |
| `macguard apps [--online] [--list]` | Installed apps: broken or missing signatures, outdated (Homebrew), end-of-life or risky software, Intel-only, orphaned root helpers, system extensions. `--online` also checks Apple for macOS updates. |
| `macguard traffic [--seconds 8]` | Samples live traffic per process: heavy uploads, outbound scanning, unsigned or temp-folder programs online, odd ports. |
| `macguard watch` | Monitor in the foreground until Ctrl-C (`--once`, `--reset`). |
| `macguard ui` | Local web UI at `http://127.0.0.1:8787`. |
| `macguard report` | Static HTML report in `~/.macguard/report.html`. |
| `macguard settings [key value]` | `background_watcher on/off` (off by default), `watch_interval <sec>`. |
| `macguard doctor [--bundle]` | Check prerequisites and optionally write a support file. |

## Development

```bash
/usr/bin/python3 -m unittest discover -s tests -v   # 92 tests
./build_app.sh                                      # dist/Mac Cleanup.app + dist/MacCleanup.dmg
```

Unit tests run against temporary directories and mocked system commands. They never touch your real caches, settings or launch agents. The `LiveSystem` tests make read-only calls to macOS.

## Docs

- [Architecture](docs/ARCHITECTURE.md): components, data flow, UI security model, app process model, with a [diagram](docs/architecture.png)
- [Support and troubleshooting](docs/SUPPORT.md)

## Notes

- It always runs under Apple's `/usr/bin/python3`. On recent macOS other interpreters, and the children of ad-hoc signed apps, can't see other processes' sockets. The app runs its engine as a short-lived launchd job for the same reason.
- Network detection uses heuristics over the kernel's socket table, not packet inspection. For per-app outbound blocking, pair it with a firewall such as LuLu.
- The app is ad-hoc signed for local use. To distribute it more widely, sign it with a Developer ID and notarize it.

## License

[MIT](LICENSE). The narration in the demo videos uses Kokoro-82M (Apache-2.0). The videos show demo data only.
