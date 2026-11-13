# Mac Cleanup

**Clean, monitor and secure a macOS development machine. Native app, web UI or CLI.**

Dev Macs pile up gigabytes of rebuildable junk: Xcode DerivedData, orphaned iOS simulators, old IDE versions, and npm, Gradle, Cargo and pip caches, plus stale `node_modules`. They also tend to have services quietly open to the network. Mac Cleanup (CLI name `macguard`) finds both, explains what it found, and fixes it only when you ask.

- **Disk cleanup**: sizes up junk by category (Docker split into build cache, dangling images, stopped containers, unused images and volumes). Each category is marked **safe** (caches that regenerate) or **review** (your call). It deletes nothing without confirmation, and only inside your home folder.
- **Space insights**: a low-disk warning (also in the watcher), what grew since the last scan, and big data that only its own app should remove (Claude Cowork image, Docker's virtual disk, simulator runtimes, Ollama models, iPhone backups), with how to remove each.
- **Security audit**: firewall and stealth mode, SIP, Gatekeeper, FileVault, Screen Sharing and SSH, launch agents and daemons (unsigned or orphaned), and private keys left in Downloads, Desktop or Documents.
- **Apps and traffic**: flags installed apps with broken or missing signatures, outdated, end-of-life or remote-access apps and orphaned root helpers, and samples live traffic per process to spot heavy uploads, scanning or odd destinations.
- **Full uninstall and app reset**: removes an app plus its scattered data (Application Support, Caches, Preferences, Containers, saved state, cookies, launch agents and system launch daemons) by exact bundle ID or name, and finds leftovers from apps you've already deleted. Everything goes to the **Trash**, so it's recoverable. Apple apps and running apps are refused.
- **Performance for dev work**: finds what is hogging CPU, memory and heat, grouped by app: Docker Desktop and its VM, Ollama, Remotion/headless-Chrome renders and ffmpeg, Spotlight indexing, booted iOS simulators, Gradle and Kotlin daemons, Unity, Android emulators, Node dev servers, and leftover processes whose parent has exited. Shows thermal throttling, load, memory pressure and swap. Each item is **safe** to stop or **review**, and stopping one always tells you how to start it again. `--before heavy` checks you're ready for a Unity, Xcode or Android build or a video render. **Dev focus** (`--focus`) pauses background apps that aren't dev tools, so only development work runs, and resumes them exactly where they were.
- **Developer mode**: one switch (`macguard devmode on`, or **⚡ Developer mode** in the app) that stops idle dev services, pauses apps that aren't dev tools, turns off animations and motion (Reduce Motion and Transparency, window, Dock and Finder animations), and keeps the Mac awake for long builds. `devmode off` puts every setting back and restarts what it stopped. It turns itself off after `focus_hours`.
- **Ready for shutdown**: one report before you turn the Mac off. It shows caches to clean, idle services to stop, work still running that a shutdown would cut off (a video render, dev servers, Docker), and git work that exists only on this Mac: uncommitted changes, unpushed commits and branches never pushed. **Prepare** does the safe part. Use `macguard ready`, the **⏻ Ready for shutdown** button, or **Mac Cleanup > Ready for Shutdown…** in the app menu.
- **Network analysis**: every listening port with its owning binary and code signature, connections by process, gateway, DNS and ARP. Flags exposed services, known-bad ports, unsigned programs, inbound scans and ARP spoofing.
- **Network monitor**: records every connection (program → IP:port, bytes) into a day-by-day history, names the IPs by reverse DNS, and warns about risky traffic: suspicious ports, unsigned or temp-folder programs online, inbound connections, unencrypted protocols, new destinations.
- **Dev session security**: start a session while you run local LLMs (Ollama, Hugging Face), AI agents (Claude Code) and Node projects, and see what they actually do: outbound connections per process with DNS names and bytes, shells, downloaders, `osascript` or `launchctl` spawned under node/npm/python/claude, programs left running, new launch agents, crontab and shell-config changes, edits to `~/.ssh`, `~/.aws` and `.env` files, npm packages with install scripts or known vulnerabilities, and LuLu allow rules that are too broad or past their time. One Markdown/JSON report at the end.
- **Heavy processes**: lists what is eating CPU or memory and says which are safe to stop. macOS, root-owned and the session's own processes are never killed.
- **MCP server**: exposes all of it to AI clients such as Claude (`macguard mcp`).
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
| `macguard deepscan [--clean] [--traffic]` | **Everything at once:** disk, security, network and apps in one prioritized report (Act now / Recommended / Good to know), each finding with its **fix**. Shows a 0–100 health score and what's **new since the last deep scan**. `--clean` then cleans the safe items. In the UI, use the **Deep scan** button. |
| `macguard scan` | Disk junk analysis, low-disk warning, what grew since the last scan, app-managed storage. Read-only. |
| `macguard clean` | Dry run of the **safe** cleanup. |
| `macguard clean --apply` | Delete safe items after you type `yes`. |
| `macguard clean --only android-avd,project-artifacts --apply` | Clean specific **review** items. |
| `macguard clean --only gradle --apply` | Gradle caches are a **review** item. Removing them makes every Spring Boot and Android build download its dependencies again. The cleanup refuses while a Gradle build runs and stops idle Gradle and Kotlin daemons first, so no daemon is left holding deleted jars. `~/.gradle/daemon` is never touched. |
| `macguard clean --builds --apply` | Optional: also remove build output in **active** projects (`target`, `build`, `dist`, `.next`, `__pycache__`, `cmake-build-*`…). Dependencies such as `node_modules` and `.venv` are never touched, and neither is anything committed to git. |
| `macguard security` | Security posture audit. |
| `macguard net` | Network snapshot and threat findings. |
| `macguard apps [--online] [--list]` | Installed apps: broken or missing signatures, outdated (Homebrew), end-of-life or risky software, Intel-only, orphaned root helpers, system extensions. `--online` also checks Apple for macOS updates. |
| `macguard uninstall <app> [--apply] [--leftovers-only]` | Dry-run by default: lists the app and every leftover. `--apply` moves them to the Trash; `--leftovers-only` resets the app and keeps it. Also in the UI under Applications → Manage apps. |
| `macguard kill <app> [--keep-agents]` | Quit an app **and everything under it**: helpers, XPC services, child processes and root helpers. It unloads the app's launch agents first so it can't relaunch, then sends TERM, then KILL after 5 s. Root processes get a ready `sudo kill` line. In the UI, running apps show a badge and a **Quit** button. `uninstall --quit` stops the app before removing it. |
| `macguard perf` | What's using CPU, memory and heat: dev daemons and leftover processes marked **safe** or **review**, the heaviest apps, thermal state, load, memory pressure and swap. Read-only. In the UI: **Performance**. |
| `macguard perf --apply` | Stop the **safe** items after you type `yes`: idle Docker Desktop and Ollama, idle Gradle daemons (`gradle --stop`), booted simulators (`xcrun simctl shutdown all`), leftover render helpers. Prints what it stopped and how to start each again. Never touches macOS or root processes, never uses `sudo`. |
| `macguard perf --only docker,unity --apply` | Stop specific **review** items (a busy Docker, Unity, an emulator, a running render, dev servers, orphans). |
| `macguard perf --before heavy` | Also checks free space (~30 GB for Unity or Xcode), Low Power Mode and battery, and lists what to close before a heavy build. |
| `macguard perf --focus [--apply]` | **Dev focus:** pause (SIGSTOP) your background apps that aren't development tools, such as browsers, chat, music, cloud sync, updaters and idle Ollama, with their helpers. Never paused: dev tools (Unity, Xcode and simulators, Android Studio/Gradle, VS Code, JetBrains, terminals and shells, node/python/dotnet/git, Docker, Claude), anything that starts a dev process, the app in front, password managers, VPNs, input and window tools, call apps, and macOS or root processes. Dry run without `--apply`; with it you type `yes`. No `sudo`. **Paused apps can show as "Not Responding"** until resumed; nothing is closed or lost. |
| `macguard perf --resume` | Continue (SIGCONT) everything dev focus paused, recorded in `~/.macguard/focus.json`. It also happens by itself after `focus_hours` (default 4) through a small background timer, at the next `macguard` run or watcher check after that, and when you close Mac Cleanup if focus was turned on there. |
| `macguard ready` | Ready-for-shutdown report. Read-only. It gives a verdict ("Ready" or "Check before shutting down"), what Prepare would clean and stop, what is still running and would be cut off (a render gets a **high** warning), and every repo under your project folders with uncommitted changes, unpushed commits or a branch that was never pushed. |
| `macguard ready --apply` | After you type `yes`, it cleans the safe caches, turns developer mode off, resumes apps paused by dev focus, and stops the safe `perf` items. It never commits, pushes, stops running work or shuts the Mac down. |
| `macguard devmode` | Shows what developer mode would do on this Mac right now. Read-only. |
| `macguard devmode on [--skip stop,pause,motion,awake]` | After you type `yes`, it does four things. It **stops** the safe `perf` items (idle Docker and Ollama, simulators, idle Gradle, leftover renders). It **pauses** non-dev apps, like `perf --focus`. It turns off **motion** by saving and then changing user settings: Reduce Motion and Transparency, window open/resize and smooth-scroll animations, Dock launch and minimize animations, Mission Control speed, and Finder animations. The Dock restarts for a second. It keeps the Mac **awake** with `caffeinate`. It also lists what it can't change without admin rights: Low Power Mode, Do Not Disturb, Spotlight exclusions. No `sudo`. If macOS refuses the Reduce Motion setting, it tells you where to switch it in System Settings. |
| `macguard devmode off` | Restores every changed setting to its previous value, resumes paused apps, opens Docker and Ollama again if it stopped them, and ends `caffeinate`. Simulators and Gradle start again by themselves when you next build. It also turns off by itself after `focus_hours` (default 4). |
| `macguard traffic [--seconds 8]` | Samples live traffic per process: heavy uploads, outbound scanning, unsigned or temp-folder programs online, odd ports. |
| `macguard netmon [--interval 5] [--seconds N]` | Record connections into `~/.macguard/netlog.db` until Ctrl-C. |
| `macguard capture [--seconds 30] [--preset all\|local\|plaintext] [--host IP] [--payload]` | Record packets (asks for your admin password) and show every flow: process, bytes, protocol, and what was sent when readable. `--list`, `--show ID`, `--file x.pcap`. |
| `macguard netlog [--days 7] [--proc NAME]` | Network history: connections per day, top programs and destinations (with names, ports, days seen), and risky-traffic findings. |
| `macguard procs [--cpu 30] [--mem-mb 1024]` | Heavy processes, classed **system** (never killed), **app** (quit the app instead) or **background** (safe for macOS to stop). |
| `macguard procs --kill <pid> [--force]` | Stop one non-system process after you type `yes` (SIGTERM, or SIGKILL with `--force`). |
| `macguard session start [--project DIR]` | Start a **dev session**: snapshot persistence, then watch connections, spawned tools and sensitive files in the background (every `session_interval` seconds, default 3). See [Dev session security](#dev-session-security). |
| `macguard session status \| stop \| report \| list` | Live alerts; stop and write the report (`--online` also asks OSV.dev about packages); print the last report (`--format json`); list past sessions. |
| `macguard net --live` | Live outbound connections per process: parent, DNS name, port, bytes, and flags. |
| `macguard procs --tree` | Process trees under node, npm, npx, python, ollama, claude, docker and editors, with risky children flagged. |
| `macguard persist [--diff] [--snapshot]` | Launch agents and daemons, login items, crontab, shell configs, `/etc/hosts`, git config and hooks, `.npmrc`: changes since the saved baseline, with diffs (token values hidden). |
| `macguard scan-deps [PATH] [--online]` | `package-lock.json` (v1–v3): packages with `preinstall`/`install`/`postinstall` scripts; `--online` adds known vulnerabilities from OSV.dev. |
| `macguard lulu [--all] [--tag UUID --hours N]` | Read-only audit of LuLu's allow rules; `--tag` sets a reminder to revoke a temporary permission. |
| `macguard alerts [--min warning]` | The local security alert log. |
| `macguard mcp` | MCP server on stdio for AI clients. See below. |
| `macguard watch` | Monitor in the foreground until Ctrl-C (`--once`, `--reset`). |
| `macguard ui` | Local web UI at `http://127.0.0.1:8787`. |
| `macguard report` | Static HTML report in `~/.macguard/report.html`. |
| `macguard settings [key value]` | `background_watcher on/off` (off by default), `watch_interval <sec>`, `focus_allow 'Spotify,Figma'` (apps dev focus never pauses), `focus_hours <h>` (auto-resume), `session_interval <sec>` (dev session polling), `osv_lookups on/off` (dev session reports ask OSV.dev; off by default). |
| `macguard doctor [--bundle]` | Check prerequisites and optionally write a support file. |

## MCP server

`macguard mcp` (or `macguard_mcp.py`) is a Model Context Protocol server on stdio, so Claude and other MCP clients can run the checks for you. Add it to Claude Code:

```bash
claude mcp add mac-cleanup -- /usr/bin/python3 /path/to/mac-cleanup/macguard.py mcp
```

| Tool | What it does |
|---|---|
| `disk_info`, `scan_junk` | Free space and junk by category. Read-only. |
| `plan_cleanup` | Dry run: the exact paths that would go, plus a `plan_id`. Safe categories by default, review ones only by id. |
| `apply_cleanup` | Deletes only the paths in that plan, needs `confirm: true`, and each plan works once (15 min). |
| `process_check` | Heavy CPU/memory processes with `kind` and `killable`. Read-only. |
| `kill_process` | Stops one non-system process. Needs the `exe` path from `process_check` (guards against pid reuse) and `confirm: true`. |
| `security_audit`, `network_snapshot`, `apps_audit`, `traffic_sample` | The same audits as the CLI. Read-only. |
| `network_history` | Recorded connections over N days: per day, top programs, top destination IPs with names. Read-only. |
| `network_alerts` | Risky traffic found in that history. Read-only. |
| `network_record` | Sample connections now for a few seconds and add them to the history. |
| `network_monitor_status` | Whether the background recorder runs and how many days are recorded. |
| `capture_list`, `capture_analyze` | Saved captures, and one decoded: flows, HTTP requests, MQTT topics and payloads, DNS names, CoAP paths, TLS server names. Read-only. |
| `packet_capture` | Records packets; macOS shows the user the admin password dialog. Needs `confirm: true`. |
| `dev_session` | Start, check, stop a dev session and get its report. Writes only macguard's own state. |
| `live_connections`, `process_tree` | Outbound connections with flags; process trees under dev tools with risky children. Read-only. |
| `persistence_changes`, `lulu_audit`, `security_alerts` | Persistence diff, LuLu allow-rule audit, the alert log. Read-only. |
| `lulu_reminder` | Remind the user to revoke a LuLu rule after N hours. Never edits LuLu. |
| `scan_dependencies` | Install scripts in a `package-lock.json`; `online: true` needs `confirm_online: true` (sends package names and versions to OSV.dev). |
| `doctor`, `recent_events` | Prerequisites, and the event log with settings. |

`apply_cleanup` and `kill_process` are marked destructive, so clients ask before running them. The server is standard-library Python like the rest.

## Network monitor

To keep a history all the time, turn on the background watcher (off by default):

```bash
macguard settings background_watcher on
```

It records the connection table every 10 seconds and keeps 90 days. It reads the kernel's socket table, so it needs no root and sends nothing anywhere. Closed TCP connections stay visible for about 30 seconds (`TIME_WAIT`), so most short requests are caught too. Limits: it sees IP addresses, not the domain names a program asked DNS for, so names come from reverse DNS and many IPs have none. Long IPv6 addresses of root-owned processes stay shortened because netstat cuts them.

## Packet capture

The network monitor shows who talks to whom; packet capture shows what they say. In the app, open **Packet capture**, pick *Local network (IoT devices)* or type a device IP, and press **Capture**. macOS asks for your admin password (tcpdump needs root), then every flow is listed with the process that opened it.

- Readable: HTTP (method, host, path, body), MQTT (client id, PUBLISH topic and payload, SUBSCRIBE), DNS and mDNS names, CoAP paths, SSDP, and any other plaintext as text or hex.
- Encrypted (HTTPS, MQTT over TLS, QUIC): only the server name the program asked for. To decrypt, start the program with `SSLKEYLOGFILE=~/.macguard/sslkeys.log`, capture, then open the saved `.pcap` in Wireshark with that key log.
- Flags credentials sent over plain HTTP, MQTT logins without TLS, and unencrypted IoT protocols to the internet.
- Captures are kept in `~/.macguard/captures` (newest 20, readable only by you); **Save .pcap to Downloads** exports one for Wireshark.

## Dev session security

For machines that run local models, AI agents and `npm install` all day: a session records what those tools do, then gives you one report. No root, no kernel extension, nothing sent anywhere (except OSV lookups you turn on).

```bash
macguard session start --project ~/code/my-app   # snapshot + background monitor
# ... npm install, ollama run, claude ...
macguard session status                          # alerts so far
macguard session stop                            # report: Markdown + JSON in ~/.macguard/devsec/sessions/<id>/
```

In the app or web UI, the **Dev session security** panel has the same Start/Stop plus live views: **Alerts**, **Connections**, **Process tree**, **Persistence**, **LuLu**, **Packages** and **Last report** (download as Markdown or JSON). Alerts have **Kill…** (with confirmation; macOS, root and the app's own processes are refused), **Copy** and **Show** (in Finder).

| Monitor | How | Flags |
|---|---|---|
| Network | `netstat -anv` (every process's sockets and byte counts, no root) plus `ps` for parents; reverse DNS cached for 24 h | IPs with no DNS name; Discord/Telegram webhooks, ngrok and other tunnels, pastebin, file-transfer and webhook-catcher sites; known-bad and uncommon ports; uploads over 50 MB. **Per-project baselines:** a project's first session learns its destinations (npm, GitHub, PyPI and Hugging Face are always fine), later sessions warn about new ones. **Ollama** listening beyond `127.0.0.1`, or connecting anywhere but its model registries. |
| Processes | `ps` every few seconds, trees under node, npm, npx, pnpm, yarn, bun, deno, python, ollama, claude, docker and editors (VS Code, Cursor, Windsurf, Zed, Antigravity) | `curl`, `wget`, `base64` (warning); `osascript`, `nc`, `launchctl`, `crontab` (critical); anything run from `/tmp` or `~/Downloads`; `curl … \| sh` and `base64 -d` command lines; processes **left running** after their tool exited. Shells are logged as info: npm scripts and agents use them all the time. |
| Persistence | Snapshot at start, diff at stop (also `macguard persist`) | Added or changed launch agents and daemons (binary plists shown as JSON), login items, crontab, `.zshrc`/`.zprofile`/`.bashrc`/`.bash_profile` and friends, `/etc/hosts`, `~/.gitconfig` and git hooks (global and per project), `.npmrc`, `~/.ssh/config` and `authorized_keys`. Token and password values are replaced with `***` before anything is stored or shown. |
| Sensitive files | FSEvents (through CoreServices, polling if it can't start) | Changes in `~/.ssh`, `~/.aws`, `~/.config`, `~/.kube`, `~/.gnupg`, `.netrc`, Docker config, keychains, browser credential stores (Login Data, Cookies, logins.json…), and `.env` files in the session's projects. **FSEvents sees changes, not reads**: a program that only reads your keys leaves no trace here. |
| LuLu | Reads `/Library/Objective-See/LuLu/rules.plist` (read-only) | Interpreters (node, python, java, curl…) allowed to connect anywhere, unsigned programs, programs in temp or Downloads folders, rules for programs that no longer exist, rules over 180 days old. Tag a temporary permission (`lulu --tag`) and the report and alerts remind you to revoke it in LuLu. If the file isn't readable, you get guidance instead. |
| Packages | `package-lock.json` v1–v3 and installed `package.json` files | Install scripts. With `--online` (or `osv_lookups on`), known vulnerabilities from OSV.dev; only package names and versions are sent. Advice: `npm install --ignore-scripts`, `npm audit`, `ignore-scripts=true` in `.npmrc`. |

Every alert has a severity (**info**, **warning**, **critical**), is written to the session's `events.jsonl` and to a rotating local log (`~/.macguard/devsec/alerts.jsonl`, 1 MB × 5), and critical ones also show a macOS notification.

**Phase 2 (needs Apple entitlements, not built):** an Endpoint Security system extension for real-time exec and file-open/read events, and a Network Extension content filter for live blocking and time-limited allow rules that revoke themselves. Both need an Apple Developer Program membership and Apple's approval for the Endpoint Security entitlement. Everything above keeps working without them.

## Development

```bash
/usr/bin/python3 -m unittest discover -s tests -v   # 251 tests
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
