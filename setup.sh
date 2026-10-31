#!/bin/bash
# One-click setup for mac-cleanup (macguard).
#
#   ./setup.sh              install prerequisites + `macguard` command, run checks and tests
#   ./setup.sh --uninstall  remove the command, background watcher and ~/.macguard state
#
# Safe to re-run. Installs nothing from the internet except Apple's Command Line Tools
# (only if missing, via Apple's own installer). No pip packages are needed.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="$HOME/.local/bin"
CMD="$BIN_DIR/macguard"
PY=/usr/bin/python3
G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; B=$'\033[1m'; X=$'\033[0m'
step() { echo; echo "${B}==> $*${X}"; }
ok()   { echo "  ${G}✔${X} $*"; }
warn() { echo "  ${Y}!${X} $*"; }
die()  { echo "  ${R}✘ $*${X}"; exit 1; }

if [[ "${1:-}" == "--uninstall" ]]; then
  step "Uninstalling"
  [[ -x "$PY" ]] && "$PY" "$DIR/macguard.py" settings background_watcher off >/dev/null 2>&1 || true
  rm -f "$CMD" && ok "removed $CMD"
  rm -rf "$HOME/.macguard" && ok "removed ~/.macguard"
  echo "  (the PATH line in ~/.zshrc is left in place; it is harmless)"
  exit 0
fi

step "Checking macOS"
[[ "$(uname)" == "Darwin" ]] || die "mac-cleanup only runs on macOS"
ok "macOS $(sw_vers -productVersion) on $(uname -m)"

step "Checking system Python (Xcode Command Line Tools)"
if ! xcode-select -p >/dev/null 2>&1 || ! "$PY" -c 'import sys; assert sys.version_info >= (3, 8)' >/dev/null 2>&1; then
  warn "Command Line Tools missing - opening Apple's installer"
  xcode-select --install || true
  die "Finish the Command Line Tools install, then run ./setup.sh again"
fi
ok "$("$PY" --version) ($PY)"
ok "no extra Python libraries needed (standard library only)"

step "Checking required macOS tools"
for t in du df netstat codesign launchctl lsof arp route scutil osascript plutil; do
  command -v "$t" >/dev/null || die "missing system tool: $t"
done
ok "all present"
for t in xcrun docker brew npm; do
  if command -v "$t" >/dev/null; then ok "optional: $t"; else warn "optional: $t not installed (its cleanup is skipped)"; fi
done

step "Installing the macguard command"
mkdir -p "$BIN_DIR"
cat > "$CMD" <<EOF
#!/bin/bash
exec $PY "$DIR/macguard.py" "\$@"
EOF
chmod +x "$CMD" "$DIR/macguard.py" "$DIR/MacCleanup.command" 2>/dev/null || true
ok "$CMD"
if [[ ":$PATH:" != *":$BIN_DIR:"* ]]; then
  RC="$HOME/.zshrc"; [[ "${SHELL:-}" == */bash ]] && RC="$HOME/.bash_profile"
  if ! grep -qs 'mac-cleanup: PATH' "$RC"; then
    printf '\n# mac-cleanup: PATH\nexport PATH="$HOME/.local/bin:$PATH"\n' >> "$RC"
    ok "added ~/.local/bin to PATH in $RC (open a new terminal)"
  fi
else
  ok "~/.local/bin already on PATH"
fi
if grep -qs 'alias macguard=' "$HOME/.zshrc"; then
  warn "an old 'alias macguard=' line exists in ~/.zshrc - you can delete it"
fi

step "Running health check (macguard doctor)"
"$PY" "$DIR/macguard.py" doctor || die "doctor reported problems - see above"

step "Running test suite"
if "$PY" -m unittest discover -s "$DIR/tests" 2>&1 | tail -3 | grep -q '^OK'; then
  ok "all tests passed"
else
  "$PY" -m unittest discover -s "$DIR/tests" 2>&1 | tail -30
  die "tests failed"
fi

step "Done"
cat <<EOF
  Background watcher: ${B}off${X} (turn on with: macguard settings background_watcher on)

  Try:
    macguard ui          # small web UI: scan, clean, security & network checks
    macguard scan        # disk junk report in the terminal
    macguard doctor      # re-check prerequisites; --bundle writes a support file

  Or double-click MacCleanup.command in Finder to open the UI.
EOF
