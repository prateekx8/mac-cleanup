# Install Mac Cleanup, step by step

This guide takes about 5 minutes on a Mac that already has Apple's Command Line Tools, and about 15 if it needs them. Nothing here needs an administrator password except installing the Command Line Tools themselves.

**What you need:** macOS 13 (Ventura) or later, an internet connection for the download, and about 50 MB of free space.

**Contents**

0. [Fastest: download the app](#fastest-download-the-app)
1. [Get the files](#1-get-the-files)
2. [Run the installer](#2-run-the-installer)
3. [Check that it works](#3-check-that-it-works)
4. [Pick how you want to use it](#4-pick-how-you-want-to-use-it)
5. [Troubleshooting](#troubleshooting)
6. [Update or uninstall](#update-or-uninstall)

---

## Fastest: download the app

If you only want the app and not the `macguard` command:

1. Download **`MacCleanup.dmg`** from https://github.com/prateekx8/mac-cleanup/releases/latest.
2. Open it and drag **Mac Cleanup** into **Applications**.
3. Open Mac Cleanup. The first time, macOS says it *can't check it for malicious software*, because the app is free
   and not notarized by Apple. Open **System Settings › Privacy & Security**, scroll down, click **Open Anyway**,
   then confirm. If macOS says the app is *damaged*, see [The app won't open](#the-app-wont-open).
4. If it asks for Apple's **Command Line Tools** (they include Python), click **Install**, wait, then open it again.

Want the `macguard` command, the web UI or the MCP server for AI assistants? Install from source below. It takes
about a minute.

## 1. Get the files

Open **Terminal**. Press <kbd>⌘</kbd> <kbd>Space</kbd>, type `Terminal`, then press <kbd>Return</kbd>.

**Option A: with git (recommended, makes updates one command)**

```bash
cd ~
git clone https://github.com/prateekx8/mac-cleanup.git
cd mac-cleanup
```

If macOS says *"The git command requires the command line developer tools"*, click **Install**, wait for it to finish, then run the three lines again.

**Option B: without git**

1. Open https://github.com/prateekx8/mac-cleanup, click the green **Code** button, then **Download ZIP**.
2. Double-click the ZIP in Downloads to unpack it.
3. Move the `mac-cleanup-main` folder into your home folder, and rename it `mac-cleanup` if you like.
4. In Terminal:

   ```bash
   cd ~/mac-cleanup        # or: cd ~/mac-cleanup-main
   ```

> Keep the folder where it is after installing. The `macguard` command points to it. If you move it, just run the installer again from the new place.

## 2. Run the installer

```bash
./setup.sh
```

You'll see six numbered steps, each with a ✔. It takes a few seconds:

```
[1/6] Checking macOS
[2/6] Checking Apple's Command Line Tools (they provide /usr/bin/python3)
[3/6] Checking the macOS tools it uses
[4/6] Installing the macguard command
[5/6] Health check (macguard doctor)
[6/6] Quick self-check
Done.
```

- **If step 2 opens an Apple window** asking to install the Command Line Tools, click **Install**, wait for it to finish (5–10 minutes), then run `./setup.sh` again.
- **If any step shows ✘**, the line below it starts with `fix:` and says what to do. The full output is saved to `~/.macguard/setup.log`.

Optional extras:

```bash
./setup.sh --app     # also builds the native app and puts it in Applications (about a minute)
./setup.sh --test    # also runs the full test suite (for developers)
```

## 3. Check that it works

**Open a new Terminal window** (<kbd>⌘</kbd> <kbd>N</kbd>), because the installer added `macguard` to your PATH, and only new windows see that. Then run:

```bash
macguard doctor
```

Every required line should have a ✔. A `–` means something optional is missing, for example Docker or LuLu, and that feature is just skipped. A ✘ line includes its fix.

Then try a read-only scan:

```bash
macguard scan
```

## 4. Pick how you want to use it

| You want | Do this |
|---|---|
| A window with buttons | Double-click **`MacCleanup.command`** in the mac-cleanup folder. It opens the web UI in your browser. Close the Terminal window it opens to stop it. |
| The native app | Download it (see [the top of this guide](#fastest-download-the-app)), or build it: `./setup.sh --app`, then open **Mac Cleanup** from Applications. The first time, macOS may ask you to confirm (see [The app won't open](#the-app-wont-open)). |
| The terminal | `macguard --help`. Start with `macguard scan`, `macguard clean` (dry run) and `macguard deepscan`. |
| Watch your dev tools | `macguard session start` in your project folder, work as usual, then `macguard session stop` for the report. |
| Claude or another AI client | `claude mcp add mac-cleanup -- /usr/bin/python3 ~/mac-cleanup/macguard.py mcp` (use your folder's path). |

Nothing runs in the background unless you turn it on (`macguard settings background_watcher on`). Nothing is deleted without a dry run and your confirmation.

---

## Troubleshooting

Start with these two commands. Most problems show up here with the fix next to them:

```bash
macguard doctor            # every check, with how to fix each ✘
macguard doctor --bundle   # also writes ~/.macguard/support-<time>.txt for a bug report
```

If `macguard` itself is not found, use the full path instead: `/usr/bin/python3 ~/mac-cleanup/macguard.py doctor`.

### Installing

| What you see | Why | Fix |
|---|---|---|
| `zsh: permission denied: ./setup.sh` | The ZIP download lost the "executable" mark | `bash setup.sh` (the installer restores the mark for next time) |
| `zsh: no such file or directory: ./setup.sh` | Terminal is in a different folder | `cd ~/mac-cleanup` (or wherever you put it), then `ls` should list `setup.sh` |
| A window asks to install "command line developer tools" | Apple's Command Line Tools are missing. They provide Python and git | Click **Install**, wait, then run `./setup.sh` again. No window? `xcode-select --install` |
| `xcode-select: error: command line tools are already installed` but setup still fails at step 2 | The tools are broken or half-installed | `sudo rm -rf /Library/Developer/CommandLineTools` then `xcode-select --install` (asks for your password) |
| `mac-cleanup is running from a disk image or external volume` | The folder is on a DMG or USB drive | Copy it to your home folder first |
| `macOS 13 (Ventura) or later is supported` | Older macOS | The CLI usually still works; the app needs 13+. Update macOS if you can |
| Setup worked but `zsh: command not found: macguard` | This Terminal window was opened before the install | Open a new window. Still missing? `echo $PATH` should include `.local/bin`; if not, add `export PATH="$HOME/.local/bin:$PATH"` to `~/.zshrc` (or `~/.bash_profile` for bash). Fish: `fish_add_path ~/.local/bin` |
| `macguard: the mac-cleanup folder is gone from …` | You moved or deleted the folder | Run `./setup.sh` again from the folder's new place |
| `macguard` runs something old or different | An old `alias macguard=` in `~/.zshrc` | Delete that line, open a new window |
| Doctor: **Socket visibility** ✘ or network views are empty | It ran under Homebrew or pyenv Python, which macOS doesn't let see other programs' sockets | Use the `macguard` command or `/usr/bin/python3` (macguard switches to it automatically when it can) |
| Doctor: **Engine files** ✘ | The download is incomplete | Download again (step 1), or `git pull` |
| Doctor: **Free disk space** ✘ | Under 1 GB free | `macguard scan`, then `macguard clean` (dry run) and `macguard clean --apply` |

### The app

#### The app won't open

| What you see | Fix |
|---|---|
| *"Mac Cleanup can't be opened because Apple cannot check it for malicious software"* or *"unidentified developer"* | The app is built and signed on your own Mac, not by Apple. Open **System Settings › Privacy & Security**, scroll down, click **Open Anyway** next to Mac Cleanup, then confirm. Or right-click the app, choose **Open**, then **Open**. |
| *"Mac Cleanup is damaged and can't be opened"* (a DMG or app copied from another Mac or the internet) | macOS quarantines downloaded files. Run `xattr -dr com.apple.quarantine "/Applications/Mac Cleanup.app"`, then open it. Building it yourself with `./setup.sh --app` avoids this. |
| *"Mac Cleanup needs Apple's Command Line Tools"* | Click **Install** in Apple's window, wait, then open the app again |
| *"The cleanup engine did not start"* | The page lists steps and the last lines of `~/.macguard/app.log`. Usually: quit and reopen; then `./setup.sh` and `macguard doctor`; then rebuild with `./build_app.sh --install`. |
| The window stays on "Starting…" | Quit, then `launchctl bootout gui/$(id -u)/ai.macguard.ui` in Terminal, and open the app again |
| The app opens, but the **Dev session security** panel says *Failed* | An app built before this feature is missing its module. Rebuild: `./build_app.sh --install` |
| `./build_app.sh` says `Missing swiftc` | `xcode-select --install`. The CLI and web UI don't need the app: `macguard ui` |

### The web UI (`macguard ui` or `MacCleanup.command`)

| What you see | Fix |
|---|---|
| `Address already in use` | Another copy is running. Close its Terminal window, or use another port: `macguard ui --port 8790` |
| The browser shows `forbidden` | Open the exact address macguard printed (`http://127.0.0.1:<port>/`). Bookmarks from an earlier run don't work: each run has a new key. |
| Double-clicking `MacCleanup.command` says it *can't be opened* | Right-click it, choose **Open**, then **Open**. Or run `./setup.sh` once; it clears the download quarantine on the folder. |

### Dev session security

| What you see | Fix |
|---|---|
| `session status` says *monitor NOT running* | The background monitor stopped (for example after a restart). `macguard session stop` writes the report from what it recorded; then `macguard session start` again. Its log: `~/.macguard/devsec/sessions/<id>/monitor.log` |
| macOS asks to let Python control **System Events** | This is the login-items check in the persistence snapshot. Allow it to include login items; deny it and they're skipped. Change it later under **System Settings › Privacy & Security › Automation**. |
| Session start says *already running* | `macguard session stop` first |
| The LuLu view says the rules aren't readable | LuLu keeps them root-only on some versions. Review them in LuLu › Rules. Nothing else is affected. |
| *"OSV lookup failed"* | No internet, or a firewall (LuLu, Little Snitch) blocked `api.osv.dev`. Allow `/usr/bin/python3` to reach `api.osv.dev` on port 443, or leave lookups off. Install-script checks work offline. |
| The file monitor says `files: polling` | FSEvents couldn't start, so it falls back to checking modification times. It is slower but still works. |
| Lots of *"connects to an IP with no DNS name"* notes | These are info only. Many cloud services have no reverse DNS name. Warnings and critical alerts are what matter. |

### Tools › Recover files

| What you see | Fix |
|---|---|
| *macOS protects the Trash, so it wasn't searched* | Press **Read the Trash through Finder** (or add `--finder`). macOS asks once to let Mac Cleanup (or your terminal) control Finder: allow it. Or give Full Disk Access in **System Settings › Privacy & Security › Full Disk Access**. |
| *Finder didn't answer in time* | A permission prompt may be waiting: answer it, then search again. A very large Trash is faster to search in Finder itself. |
| *Time Machine isn't set up* | Nothing to restore from backups. Turn on Time Machine for next time; check iCloud's and Photos' Recently Deleted now. |
| A memory card shows *Not by scanning* or *Very low* | It's the Mac's internal SSD or an encrypted APFS disk: deleted files there can't be found by scanning. Use backups. |
| My memory card isn't listed | Use a card reader, check it shows in Finder or `diskutil list external`, then press **Check again**. |
| *couldn't unmount the card* when imaging | An app (Photos, Image Capture, Finder preview) is using it. Quit it, then try again. |
| *imaging didn't run: cancelled* | The password prompt was cancelled. Imaging needs it once to read the card; nothing else runs as admin. |
| *not enough space for the image* | The image is as big as the whole card. Pick a folder on a disk with that much free space (not the card). |
| The scan finds files with names like `_MG_0001.JPG` | FAT keeps only 8.3 names for short names, and deleting erases their first letter. The file itself is fine. |
| A file shows **overwritten** or **damaged** | Newer files used some of its space, or it was fragmented. Save it anyway: photos often open partly. |

### Tools › AI image and voice check

| What you see | Fix |
|---|---|
| *No AI markers found* on a picture you think is AI | Most shared copies have lost their markers. Ask for the original file, not a screenshot or a downloaded copy. |
| *Signature not checked* | Install `c2patool` (`brew install c2patool`) to verify Content Credentials signatures. |
| *That file is over 200 MB* | Check it from Terminal: `macguard ai-check FILE`. |

### Tools › Photo sorter

| What you see | Fix |
|---|---|
| *without Vision: no Swift helper, dates only* | The command line compiles the helper with `swiftc` the first time; install the Command Line Tools (`xcode-select --install`) or use the app, which has it built in. |
| *That's inside a Photos library* | The sorter never touches the Photos library. In Photos, select the photos and use **File › Export › Export Unmodified Original**, then sort that folder. |
| *move only works on the same disk* | Choose **Copy** to sort onto another disk or from a card. |
| Many files in **Undated** | They have no date inside and none in the name; the file's own date only shows when it was copied. Tick **trust file dates** if you know those dates are right. |
| macOS asks to allow access to a folder or removable volume | Allow it once: the sorter only reads the folder until you choose Copy or Move. |

### Still stuck?

1. `macguard doctor --bundle`. It writes `~/.macguard/support-<time>.txt` with check results and settings, and no file contents or secrets. Read it before sharing.
2. Open an issue at https://github.com/prateekx8/mac-cleanup/issues with that file, your macOS version (`sw_vers`), and what you ran.

---

## Update or uninstall

**Update the downloaded app:** download the new `MacCleanup.dmg` from the latest release and replace the app in Applications.

**Update** (git install):

```bash
cd ~/mac-cleanup && git pull && ./setup.sh          # add --app if you use the app
```

ZIP install: download it again and replace the folder, then run `./setup.sh`.

**Uninstall:**

```bash
cd ~/mac-cleanup && ./setup.sh --uninstall           # command, background watcher, ~/.macguard
rm -rf "/Applications/Mac Cleanup.app"               # if you installed the app
rm -rf ~/mac-cleanup                                 # the folder itself
```

The installer's PATH line in `~/.zshrc` is harmless; delete the two lines under `# mac-cleanup: PATH` if you like.
