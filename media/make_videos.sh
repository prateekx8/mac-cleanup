#!/bin/bash
# Builds the YouTube video, the Short, a thumbnail, subtitles and an upload kit into dist/videos/.
# Uses demo data only. Needs: node, Google Chrome, ffmpeg; Homebrew python3 for the natural voice.
#   media/make_videos.sh                       natural voice (Kokoro, default)
#   MC_KOKORO_VOICE=am_michael media/make_videos.sh
#   MC_TTS=say MC_VOICE=Samantha media/make_videos.sh   (macOS voice, personal use only)
set -euo pipefail
cd "$(dirname "$0")"
PORT=8790
[[ -d node_modules ]] || npm install --no-audit --no-fund
# natural voice: Kokoro-82M (Apache-2.0), ~340 MB one-time download
if [[ "${MC_TTS:-kokoro}" == kokoro ]]; then
  [[ -d .venv ]] || { /opt/homebrew/bin/python3 -m venv .venv && .venv/bin/pip install -q kokoro-onnx soundfile; }
  mkdir -p models
  for f in kokoro-v1.0.onnx voices-v1.0.bin; do
    [[ -s "models/$f" ]] || curl -sSL --fail -o "models/$f" "https://github.com/thewh1teagle/kokoro-onnx/releases/download/model-files-v1.0/$f"
  done
fi
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
