#!/bin/bash
# Builds the YouTube video, the Short, a thumbnail, subtitles and an upload kit into dist/videos/.
# Uses demo data only. Needs: node (npm i in media/), Google Chrome, ffmpeg, macOS `say`.
#   media/make_videos.sh            MC_VOICE="Ava (Premium)" media/make_videos.sh
set -euo pipefail
cd "$(dirname "$0")"
PORT=8790
[[ -d node_modules ]] || npm install --no-audit --no-fund
mkdir -p out
[[ -f out/icon.png ]] || { swiftc -O -swift-version 5 -o out/make_icon ../app/make_icon.swift && out/make_icon out/icon.png; }

serve() { /usr/bin/python3 demo_server.py --port $PORT >out/demo.log 2>&1 & echo $!; }
for fmt in long short; do
  rm -rf "out/$fmt"
  pid=$(serve); sleep 1.2
  node capture.mjs "$fmt" "http://127.0.0.1:$PORT/" "out/$fmt" out/icon.png
  kill "$pid"
done
/usr/bin/python3 build_videos.py
