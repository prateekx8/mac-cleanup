"""Natural narration with Kokoro-82M (Apache-2.0), fully offline.

  media/.venv/bin/python media/tts_kokoro.py jobs.json
jobs.json: [{"text": "...", "out": "/path/seg.wav"}, ...]
Voice/speed via MC_KOKORO_VOICE (default af_heart) and MC_KOKORO_SPEED (default 1.0).
Models live in media/models (see make_videos.sh for the download).
"""
import json
import os
import sys

import soundfile as sf
from kokoro_onnx import Kokoro

HERE = os.path.dirname(os.path.abspath(__file__))
voice = os.environ.get("MC_KOKORO_VOICE", "af_heart")
speed = float(os.environ.get("MC_KOKORO_SPEED", "1.0"))
tts = Kokoro(os.path.join(HERE, "models", "kokoro-v1.0.onnx"), os.path.join(HERE, "models", "voices-v1.0.bin"))
for job in json.load(open(sys.argv[1])):
    samples, rate = tts.create(job["text"], voice=voice, speed=speed, lang="en-us")
    sf.write(job["out"], samples, rate)
    print(f"  tts {os.path.basename(job['out'])}", flush=True)
