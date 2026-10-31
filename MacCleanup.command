#!/bin/bash
# Double-click in Finder: runs first-time setup if needed, then opens the mac-cleanup UI.
DIR="$(cd "$(dirname "$0")" && pwd)"
[[ -x "$HOME/.local/bin/macguard" ]] || "$DIR/setup.sh" || { read -r -p "Setup failed. Press Enter to close."; exit 1; }
echo "Opening mac-cleanup UI... (close this window or press Ctrl-C to stop)"
exec /usr/bin/python3 "$DIR/macguard.py" ui
