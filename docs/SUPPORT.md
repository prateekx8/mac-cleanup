# Support and troubleshooting

Start here every time:

```bash
macguard doctor            # checks every prerequisite
macguard doctor --bundle   # also writes ~/.macguard/support-<time>.txt to attach to a bug report
```

The support bundle holds check results, your settings and the last 50 watch events. It holds no file contents or secrets. Read it before you share it.

## Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `zsh: command not found: macguard` | The command isn't installed | Run `./setup.sh`, then open a new terminal |
| Network section is empty or shows "0 sockets" | macOS hides sockets from untrusted interpreters | Use `/usr/bin/python3` (the `macguard` command does this for you). In the app, rebuild it with `./build_app.sh` |
| `doctor`: "System python" fails | Command Line Tools missing | `xcode-select --install` |
| App says "The cleanup engine did not start" | Engine crashed | Read `~/.macguard/app.log` |
| App won't open: "unidentified developer" | Ad-hoc signed local build | Right-click the app, choose **Open**, then confirm once |
| Docker installer cleanup does nothing | Docker Desktop is running | Quit Docker Desktop first |
| Simulator cleanup shows 0 | No simulators are unavailable | Nothing to do |
| Watcher alerts too often | The baseline is out of date | `macguard watch --once --reset` |

## Uninstall

```bash
./setup.sh --uninstall                       # command, watcher, ~/.macguard
rm -rf "/Applications/Mac Cleanup.app"       # if you installed the app
```

## Reporting a bug

Please include:

1. the output of `macguard doctor`
2. your macOS version (`sw_vers`)
3. the command or UI action that failed
4. the support bundle, if relevant

## Safety guarantees

- Nothing is deleted without `--apply` and a confirmation.
- Deletes are limited to paths inside your home folder.
- Nothing runs at login unless you turn on the background watcher.
- No network requests are made to anything except `127.0.0.1`.
