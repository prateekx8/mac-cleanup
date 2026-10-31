# mac-cleanup

**Clean, monitor and secure a macOS development machine from one command.**

Dev Macs pile up gigabytes of rebuildable junk: Xcode DerivedData, orphaned iOS simulators, old IDE versions, and npm, Gradle, Cargo and pip caches, plus stale `node_modules`. They also tend to have services quietly open to the network. `mac-cleanup` (CLI name `macguard`) finds both, explains what it found, and fixes it only when you ask.

- **Disk cleanup**: sizes up junk by category. Each category is marked **safe** (caches that regenerate) or **review** (your call). It deletes nothing without `--apply` and a confirmation.
- **Security audit**: firewall and stealth mode, SIP, Gatekeeper, FileVault, Screen Sharing and SSH, launch agents and daemons (unsigned or orphaned), and private keys left in Downloads, Desktop or Documents.
- **Network analysis**: every listening port with its owning binary and code signature, connections grouped by process, gateway, DNS and ARP. Flags known-bad ports, unsigned programs on the internet, binaries in temp folders, inbound scans and ARP spoofing.
- **Watch mode (on demand)**: learns a baseline and alerts when a new program opens a port to your network, the gateway's hardware address changes, DNS or `/etc/hosts` changes, or a high-severity issue appears. Runs only when you call it, unless you turn on the background setting.
- **HTML report**: one dashboard covering all of the above.

Single Python file, standard library only, no root required.

## Install

```bash
alias macguard="/usr/bin/python3 ~/DEV/Workspace/mac-cleanup/macguard.py"
```

## Usage

| Command | What it does |
|---|---|
| `macguard scan` | Disk junk analysis. Read-only. |
| `macguard clean` | Dry run of the **safe** cleanup. |
| `macguard clean --apply` | Delete safe items after you type `yes`. |
| `macguard clean --only android-avd,project-artifacts --apply` | Clean specific **review** items. |
| `macguard security` | Security posture audit. |
| `macguard net` | Network snapshot and threat findings. |
| `macguard watch` | Monitor in the foreground until Ctrl-C (`--once` runs a single check, `--reset` re-learns the baseline). |
| `macguard report` | HTML dashboard, written to `~/.macguard/report.html`. |
| `macguard settings` | Show settings. |
| `macguard settings background_watcher on` | Opt in: run `watch` in the background at login and send macOS notifications. Off by default. |
| `macguard settings background_watcher off` | Stop the background watcher and remove its launch agent. |
| `macguard settings watch_interval 120` | Seconds between background checks. |

State lives in `~/.macguard/` (`settings.json`, `baseline.json`, `events.log`, `report.html`).

## Notes

- It always runs under Apple's `/usr/bin/python3`. On recent macOS, Homebrew or pyenv Python can't see other processes' sockets, so the script re-runs itself under the system interpreter.
- Network detection uses heuristics over the kernel's socket table (`netstat -anv`), not packet inspection. For per-app outbound blocking, pair it with a firewall such as LuLu.
- Project build folders (`node_modules`, `target`, `build`, `.venv` and so on) are only offered for cleanup when the project hasn't been edited for `--stale-days` (default 30). `build` and `dist` count only when they sit next to a matching build file.
