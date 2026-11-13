#!/bin/bash
# One-click setup for mac-cleanup (macguard). Safe to re-run.
#
#   ./setup.sh              check prerequisites, install the `macguard` command, quick self-check (~10 s)
#   ./setup.sh --app        also build "Mac Cleanup.app" and copy it to /Applications
#   ./setup.sh --test       also run the full test suite (developers; takes a few minutes)
#   ./setup.sh --uninstall  remove the command, background watcher and ~/.macguard state
#
# If ./setup.sh says "permission denied", run:  bash setup.sh
# Installs nothing from the internet except Apple's Command Line Tools (only if missing, via Apple's
# own installer). No pip packages are needed. Everything it prints is also saved to ~/.macguard/setup.log.
set -uo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
CMD="$BIN_DIR/macguard"
PY=/usr/bin/python3
GUIDE="docs/INSTALL.md"
G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; D=$'\033[2m'; X=$'\033[0m'
STEP=0; TOTAL=6
step() { STEP=$((STEP+1)); echo; echo "${B}[$STEP/$TOTAL] $*${X}"; }
ok()   { echo "  ${G}✔${X} $*"; }
warn() { echo "  ${Y}!${X} $*"; }
fix()  { echo "    ${D}fix:${X} $*"; }
die()  {
  echo "  ${R}✘ $1${X}"
  shift
  for f in "$@"; do fix "$f"; done
  echo
  echo "  Setup stopped. The full log is in ~/.macguard/setup.log."
  echo "  Step-by-step help: $DIR/$GUIDE (section \"Troubleshooting\")."
  exit 1
}

APP=0; TESTS=0; UNINSTALL=0
for a in "$@"; do
  case "$a" in
    --app) APP=1 ;;
    --test) TESTS=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "Unknown option: $a (try --help)"; exit 2 ;;
  esac
done

mkdir -p "$HOME/.macguard" 2>/dev/null && exec > >(tee "$HOME/.macguard/setup.log") 2>&1

if [[ $UNINSTALL == 1 ]]; then
  echo "${B}Uninstalling mac-cleanup${X}"
  [[ -x "$PY" ]] && "$PY" "$DIR/macguard.py" session stop >/dev/null 2>&1 || true
  [[ -x "$PY" ]] && "$PY" "$DIR/macguard.py" settings background_watcher off >/dev/null 2>&1 || true
  rm -f "$CMD" && ok "removed $CMD"
  rm -rf "$HOME/.macguard" && ok "removed ~/.macguard (settings, history, reports)"
  [[ -d "/Applications/Mac Cleanup.app" ]] && echo "  The app is still in /Applications: drag \"Mac Cleanup\" to the Trash to remove it."
  echo "  (the PATH line in your shell profile is left in place; it is harmless)"
  exit 0
fi
[[ $APP == 1 ]] && TOTAL=7
[[ $TESTS == 1 ]] && TOTAL=$((TOTAL+1))

echo "${B}mac-cleanup setup${X}  ${D}($DIR)${X}"

step "Checking macOS"
[[ "$(uname)" == "Darwin" ]] || die "mac-cleanup only runs on macOS"
OSV="$(sw_vers -productVersion)"
MAJOR="${OSV%%.*}"
ok "macOS $OSV on $(uname -m)"
if (( MAJOR < 13 )); then
  warn "macOS 13 (Ventura) or later is supported; older versions may work for the CLI but the app needs 13+"
fi
if [[ "$DIR" == /Volumes/* ]]; then
  die "mac-cleanup is running from a disk image or external volume ($DIR)" \
      "copy the mac-cleanup folder into your home folder (for example ~/mac-cleanup), then run setup.sh from there"
fi

step "Checking Apple's Command Line Tools (they provide /usr/bin/python3)"
if ! xcode-select -p >/dev/null 2>&1 || ! "$PY" -c 'import sys; assert sys.version_info >= (3, 8)' >/dev/null 2>&1; then
  warn "Command Line Tools are missing: opening Apple's installer"
  xcode-select --install >/dev/null 2>&1 || true
  die "Install the Command Line Tools first" \
      "click Install in the window that just opened (about 5-10 minutes), then run ./setup.sh again" \
      "no window? run: xcode-select --install   (or install Xcode from the App Store)"
fi
ok "$("$PY" --version 2>&1) at $PY"
ok "no extra Python libraries needed (standard library only)"

step "Checking the macOS tools it uses"
missing=()
for t in du df ps netstat codesign launchctl lsof arp route scutil osascript plutil; do
  command -v "$t" >/dev/null || missing+=("$t")
done
(( ${#missing[@]} == 0 )) || die "missing system tools: ${missing[*]}" \
  "these ship with macOS; check that PATH includes /usr/bin:/bin:/usr/sbin:/sbin (echo \$PATH)"
ok "all present"
for t in xcrun docker brew npm; do
  if command -v "$t" >/dev/null; then ok "optional: $t"; else echo "  ${D}– optional: $t not installed (its cleanup is skipped)${X}"; fi
done

step "Installing the macguard command"
mkdir -p "$BIN_DIR" || die "could not create $BIN_DIR" "check that your home folder is writable: ls -ld ~"
cat > "$CMD" <<EOF
#!/bin/bash
# Installed by mac-cleanup setup.sh. Re-run setup.sh if you move the mac-cleanup folder.
if [[ ! -f "$DIR/macguard.py" ]]; then
  echo "macguard: the mac-cleanup folder is gone from $DIR (moved or deleted)." >&2
  echo "Run ./setup.sh again from its new location." >&2
  exit 1
fi
exec $PY "$DIR/macguard.py" "\$@"
EOF
chmod +x "$CMD" "$DIR/macguard.py" "$DIR/setup.sh" "$DIR/build_app.sh" "$DIR/MacCleanup.command" 2>/dev/null || true
# a folder downloaded as a ZIP is quarantined; clear it on our own files so double-clicking works
xattr -dr com.apple.quarantine "$DIR" 2>/dev/null || true
ok "$CMD"
RC="$HOME/.zshrc"
case "${SHELL:-}" in
  */bash) RC="$HOME/.bash_profile" ;;
  */fish) RC="" ; warn "fish shell: run  fish_add_path ~/.local/bin  once to put macguard on your PATH" ;;
esac
if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
  ok "~/.local/bin is already on your PATH"
elif [[ -n "$RC" ]]; then
  if ! grep -qs 'mac-cleanup: PATH' "$RC"; then
    printf '\n# mac-cleanup: PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC" || die "could not write $RC" \
      "add this line to your shell profile yourself: export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
  ok "added ~/.local/bin to PATH in $RC ${Y}(open a new terminal window to use \`macguard\`)${X}"
fi
if grep -qs 'alias macguard=' "$HOME/.zshrc"; then
  warn "an old 'alias macguard=' line exists in ~/.zshrc and hides the new command: delete it"
fi

step "Health check (macguard doctor)"
if ! "$PY" "$DIR/macguard.py" doctor; then
  die "doctor found a problem (marked ✘ above, each with its fix)" \
      "fix it, then run ./setup.sh again"
fi

step "Quick self-check"
check() {  # check <label> <command...>: runs it with a time limit, prints ok or the error
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then ok "$label"; else
    echo "  ${R}✘ $label${X}"; echo "$out" | tail -5 | sed 's/^/      /'; return 1; fi
}
failed=0
check "CLI starts" "$PY" "$DIR/macguard.py" --help || failed=1
check "disk scan engine loads" "$PY" -c "import sys; sys.path.insert(0, '$DIR'); import macguard as m; m.disk_info()" || failed=1
check "security monitor loads" "$PY" -c "import sys; sys.path.insert(0, '$DIR'); import macguard_devsec as s; s.proc_snapshot()" || failed=1
check "MCP server answers" "$PY" -c "
import json, subprocess, sys
r = subprocess.run([sys.executable, '$DIR/macguard.py', 'mcp'], input=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}) + '\n',
                   capture_output=True, text=True, timeout=30)
assert json.loads(r.stdout)['result']['tools'], r.stderr" || failed=1
(( failed == 0 )) || die "the self-check failed" "run: macguard doctor --bundle   and attach the file to a bug report"

if [[ $APP == 1 ]]; then
  step "Building Mac Cleanup.app"
  command -v swiftc >/dev/null || die "swiftc is missing (needed only for the app)" "install the Command Line Tools: xcode-select --install" \
    "or skip the app: the CLI and web UI (macguard ui) work without it"
  "$DIR/build_app.sh" --install || die "the app build failed (see above)" \
    "the CLI and web UI still work: macguard ui" "to retry after updating the Command Line Tools: ./build_app.sh --install"
  ok "installed /Applications/Mac Cleanup.app"
fi

if [[ $TESTS == 1 ]]; then
  step "Running the full test suite"
  if "$PY" -m unittest discover -s "$DIR/tests" 2>&1 | tail -3 | grep -q '^OK'; then
    ok "all tests passed"
  else
    "$PY" -m unittest discover -s "$DIR/tests" 2>&1 | tail -30
    die "tests failed" "the app still works; please report it with the output above"
  fi
fi

echo
echo "${G}${B}Done.${X} Background watcher: ${B}off${X} (turn on with: macguard settings background_watcher on)"
cat <<EOF

  Open a new terminal window, then try:
    macguard ui                 # the web UI: scan, clean, security, dev session monitor
    macguard scan               # disk junk report in the terminal
    macguard session start      # watch what your dev tools do, then: macguard session stop
    macguard doctor             # re-check everything; --bundle writes a support file

  Or double-click MacCleanup.command in Finder to open the UI.
  $( [[ $APP == 1 ]] && echo "Or open Mac Cleanup from your Applications folder." || echo "Want the native app?  ./setup.sh --app" )
  Something not working? See $GUIDE
EOF
