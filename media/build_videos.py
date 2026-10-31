#!/usr/bin/python3
"""Turns captured shots + narration into the YouTube video and the Short.

  /usr/bin/python3 media/build_videos.py            (after capture; see make_videos.sh)

Needs ffmpeg/ffprobe and macOS `say`. Voice: MC_VOICE env (default "Samantha"),
rate: MC_RATE (default 182 wpm). All audio is generated locally (TTS + synthesized pad),
so there is no third-party music or licensing to worry about.
"""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
DIST = os.path.join(os.path.dirname(HERE), "dist", "videos")
VOICE = os.environ.get("MC_VOICE", "Samantha")
RATE = os.environ.get("MC_RATE", "182")
FPS = 30
FORMATS = {
    "long": dict(w=1920, h=1080, pad=0.75, name="MacCleanup_YouTube_1080p.mp4"),
    "short": dict(w=1080, h=1920, pad=0.35, name="MacCleanup_Short_1080x1920.mp4"),
}


def sh(*cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"command failed: {' '.join(cmd)}\n{r.stderr[-2000:]}")
    return r.stdout


def duration(path):
    return float(sh("ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", path).strip())


def ts(t, srt=False):
    h, m, s = int(t // 3600), int(t % 3600 // 60), t % 60
    return f"{h:02d}:{m:02d}:{s:06.3f}".replace(".", ",") if srt else (f"{m}:{int(s):02d}" if not h else f"{h}:{m:02d}:{int(s):02d}")


def build(fmt):
    cfg = FORMATS[fmt]
    scenes = json.load(open(os.path.join(HERE, "scenes.json")))[fmt]
    work = os.path.join(OUT, fmt, "clips")
    os.makedirs(work, exist_ok=True)
    W, H = cfg["w"], cfg["h"]
    clips, timeline, t = [], [], 0.0
    for i, sc in enumerate(scenes):
        aiff = os.path.join(work, f"{i:02d}.aiff")
        sh("say", "-v", VOICE, "-r", RATE, "-o", aiff, sc["say"])
        d = duration(aiff) + 0.25 + cfg["pad"]
        img = os.path.join(OUT, fmt, "shots", sc["shot"] + ".png")
        cap = os.path.join(OUT, fmt, "captions", f"{i:02d}.png")
        clip = os.path.join(work, f"{i:02d}.mp4")
        frames = int(d * FPS)
        # slow push-in (zoompan on a 2x upscale keeps it smooth), caption fades in, soft fades between scenes
        vf = (f"[0:v]scale={W * 2}:{H * 2},zoompan=z='1+0.035*on/{frames}':x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)'"
              f":d={frames}:s={W}x{H}:fps={FPS},setsar=1[bg];"
              f"[1:v]scale={W}:{H},format=rgba,fade=t=in:st=0.15:d=0.3:alpha=1[cap];"
              f"[bg][cap]overlay=0:0,fade=t=in:st=0:d=0.25:color=0x0b0d1a,fade=t=out:st={d - 0.25:.3f}:d=0.25:color=0x0b0d1a,format=yuv420p[v];"
              f"[2:a]adelay=250|250,apad,atrim=0:{d:.3f},afade=t=out:st={d - 0.2:.3f}:d=0.2,aresample=48000[a]")
        sh("ffmpeg", "-y", "-loglevel", "error", "-loop", "1", "-i", img, "-loop", "1", "-i", cap, "-i", aiff,
           "-filter_complex", vf, "-map", "[v]", "-map", "[a]", "-t", f"{d:.3f}",
           "-c:v", "libx264", "-preset", "medium", "-crf", "17", "-r", str(FPS), "-c:a", "aac", "-b:a", "192k", "-ac", "2", clip)
        clips.append(clip)
        timeline.append((t, t + d, sc))
        t += d
        print(f"  {fmt} {i + 1}/{len(scenes)}  {sc['shot']:<9} {d:5.1f}s", flush=True)

    lst = os.path.join(work, "list.txt")
    with open(lst, "w") as fh:
        fh.writelines(f"file '{c}'\n" for c in clips)
    voice = os.path.join(work, "voice.mp4")
    sh("ffmpeg", "-y", "-loglevel", "error", "-f", "concat", "-safe", "0", "-i", lst, "-c", "copy", voice)

    # synthesized ambient pad (Am9-ish chord, slow swell), mixed well under the voice
    total = t
    pad = ("aevalsrc='0.05*(sin(2*PI*110*t)+0.8*sin(2*PI*164.81*t)+0.6*sin(2*PI*220*t)+0.5*sin(2*PI*246.94*t)+0.4*sin(2*PI*329.63*t))"
           "*(0.7+0.3*sin(2*PI*0.07*t))':s=48000:c=stereo")
    os.makedirs(DIST, exist_ok=True)
    final = os.path.join(DIST, cfg["name"])
    sh("ffmpeg", "-y", "-loglevel", "error", "-i", voice, "-f", "lavfi", "-t", f"{total:.3f}", "-i", pad,
       "-filter_complex",
       f"[1:a]lowpass=f=900,volume=0.35,afade=t=in:d=2,afade=t=out:st={total - 2.5:.3f}:d=2.5[m];"
       f"[0:a][m]amix=inputs=2:duration=first:normalize=0,alimiter=limit=0.95[a]",
       "-map", "0:v", "-map", "[a]", "-c:v", "copy", "-c:a", "aac", "-b:a", "192k", "-movflags", "+faststart", final)

    # subtitles for upload
    with open(final.replace(".mp4", ".srt"), "w") as fh:
        for n, (a, b, sc) in enumerate(timeline, 1):
            fh.write(f"{n}\n{ts(a + 0.25, True)} --> {ts(b - 0.2, True)}\n{sc['say']}\n\n")
    return final, timeline, total


def main():
    long_path, long_tl, long_len = build("long")
    short_path, _, short_len = build("short")
    thumb = os.path.join(OUT, "long", "shots", "thumb.png")
    sh("ffmpeg", "-y", "-loglevel", "error", "-i", thumb, "-vf", "scale=1280:720", os.path.join(DIST, "MacCleanup_thumbnail.png"))

    chapters_map = {"title": "Intro", "problem": "The problem", "hero": "Tour", "scanning": "Scan your Mac",
                    "results": "Safe vs review", "cleaning": "Clean", "security": "Security audit",
                    "network": "Network check", "watcher": "Background watcher", "cli": "CLI",
                    "app": "Install", "privacy": "Privacy", "outro": "Wrap up"}
    chapters = [f"{ts(a)} {chapters_map[sc['shot']]}" for a, _, sc in long_tl if sc["shot"] in chapters_map]
    chapters[0] = "0:00 Intro"
    md = f"""# Upload kit

## YouTube: {os.path.basename(long_path)} ({long_len:.0f}s, 1920x1080)

**Title:** Mac Cleanup: free up 25 GB of hidden developer junk and lock down your Mac (free, local)

**Description:**

Developer Macs quietly fill up with Xcode DerivedData, dead iOS simulators, stale node_modules, old IDE versions and package-manager caches, and they often leave services exposed on the network. Mac Cleanup finds all of it in one place. It runs 100% locally, needs no root and deletes nothing without your confirmation.

What it does:
- One-click scan. Safe caches are pre-selected, and risky items wait for you
- Security audit: firewall, FileVault, SIP, Gatekeeper, sharing services, startup items, stray private keys
- Network check: every open port and the program behind it, exposed services, port scans, ARP spoofing
- Optional background watcher: alerts on new open ports or router/DNS changes
- Native Mac app, glass web UI, and a `macguard` CLI

Chapters:
{chr(10).join(chapters)}

#macOS #developer #productivity #cybersecurity #opensource

**Tags:** mac cleanup, macos cleanup, free up disk space mac, xcode deriveddata, delete simulators, node_modules cleanup, mac security audit, mac firewall, developer tools, macguard

**Thumbnail:** MacCleanup_thumbnail.png
**Captions:** {os.path.basename(long_path).replace('.mp4', '.srt')} (upload under Subtitles, English)

## Short: {os.path.basename(short_path)} ({short_len:.0f}s, 1080x1920)

**Title:** Your Mac is hiding 25 GB of dev junk #Shorts

**Description:** One free, local tool finds and safely cleans developer junk, then audits your security and network. Full walkthrough on the channel. #macOS #developer #Shorts

**Captions:** {os.path.basename(short_path).replace('.mp4', '.srt')}

---
Narration: macOS "{VOICE}" voice (on-device). Music: synthesized pad generated by the build script. All UI footage uses demo data, so no real files, paths or network details appear.
"""
    with open(os.path.join(DIST, "UPLOAD_KIT.md"), "w") as fh:
        fh.write(md)
    print(f"\n{long_path}\n{short_path}\n{DIST}/MacCleanup_thumbnail.png\n{DIST}/UPLOAD_KIT.md")


if __name__ == "__main__":
    main()
