# Photo sorter: research and design

**Status (14 Nov 2026):** P1 is built, plus two P2 parts (similar-photo groups and search): `macguard photos`, the
Photo sorter card, MCP `photos_*`, `macguard_photos.py` and `helpers/photo_sense.swift` (prebuilt into the app;
compiled once into `~/.macguard/bin` for the command line). Best-shot picks, side-by-side review and P3 (Photos
library albums) are next. Part of the **Tools** section ([TOOLS.md](TOOLS.md)).

**Checked when P1 was built:** a test folder with dated photos, a burst, a screenshot, a receipt, a duplicate, a
Live Photo with its edit sidecar and an undated file: index (with the real helper), events named from Vision
("2026-08-10 Bird, owl"), the burst grouped as similar, copy, move, undo of every move, and Finder tags, from the
command line and the web UI. Similar-photo threshold: a fingerprint distance under 0.45 within 10 seconds (measured:
a rotated or cropped copy 0.26–0.41, different subjects 0.6 and up).

**Goal:** point Mac Cleanup at a folder of photos (Downloads, an old export, a memory card, a backup drive). It
first builds an index of every photo: when it was taken, what camera made it, and what Apple's on-device Vision
sees in it. Then it proposes a tidy layout: by date, by event, and by kind (camera photos, screenshots, documents
and receipts, duplicates). You look at the plan, and only then does it copy or move anything.

**Principles**
- **Index first, sort second.** Nothing moves until you've seen the plan.
- **Copy by default.** Moving is an option, and every move is written to an undo log. Nothing is ever deleted:
  duplicates go to their own folder for you to check.
- **On this Mac only.** Vision runs on-device. No uploads, no cloud, no online place-name lookups.
- **Never inside the Photos library.** `Photos Library.photoslibrary` is a database. Moving files inside it breaks
  it, so the sorter refuses that folder. Photos support comes later through Apple's Photos framework (phase P3).
- **No face recognition.** It counts faces ("3 people") but never identifies anyone.

---

## What was checked on this Mac (13 Nov 2026, macOS 27.2, Swift 6.4)

A 40-line Swift probe using Vision and ImageIO, run on Apple's sample pictures and a generated invoice image:

| Image | Vision labels (confidence) | Other results | Time |
|---|---|---|---|
| Owl (512 px) | animal, bird, raptor, owl (0.97) | aesthetic 0.85 | 0.67 s (first image: model load) |
| Zebra (512 px) | animal, mammal, zebra (0.98) | aesthetic 0.79 | 0.03 s |
| Dahlia (512 px) | flower, plant, dahlia (0.61) | aesthetic 0.83 | 0.03 s |
| Sonoma wallpaper (6016 px) | none above 0.3 | aesthetic −0.39 | 0.26 s |
| Generated invoice (PNG) | document 0.35, printed page 0.32 | 12 text lines, **utility: yes** | 0.09 s |

- `VNClassifyImageRequest` knows **1,303 labels**, including `screenshot`, `document`, `receipt`, `whiteboard`,
  `food`, `people`, `beach`, `mountain`, `dog`, `cat`.
- `VNCalculateImageAestheticsScoresRequest` (macOS 15+) gives a quality score and an **isUtility** flag: true for
  screenshots, receipts and documents. That is the best single signal for "not a real photo".
- `VNGenerateImageFeaturePrintRequest` gives a 768-number fingerprint per image. The distance between two
  fingerprints finds near-duplicates and bursts.
- ImageIO reads EXIF from JPEG, HEIC, PNG and RAW without converting anything.
- Python can't call Vision without PyObjC, and macguard is standard-library only. So the Vision part is a small
  Swift helper (see Code layout). The Command Line Tools that setup already needs include `swiftc`.

Estimate: 10,000 photos at 0.03–0.3 s each is **5–30 minutes** on first index, run at low priority. Later runs
only look at new or changed files.

---

## Step 1 · Build the index (metadata first)

The helper walks the folder and writes one row per file to `~/.macguard/photos/index.sqlite` (stdlib `sqlite3`,
folder readable only by you).

| Field | Where it comes from |
|---|---|
| path, size, modified time, quick hash | the file system; the hash covers the size plus the first and last 64 KB. A full SHA-256 is computed only for duplicate candidates |
| **taken at** | EXIF `DateTimeOriginal` + `OffsetTimeOriginal` → QuickTime `CreationDate` for videos → a date in the file name (`IMG_20231105_…`, `Screenshot 2026-11-13 at …`, `WhatsApp Image 2024-01-02 at …`, `PXL_…`) → the file's modified time, marked **guessed** |
| camera | EXIF `Make` / `Model`, lens, and whether there is GPS (the coordinates stay in the index and are never looked up online) |
| size in pixels, kind | ImageIO; JPEG, HEIC, PNG, GIF, WebP, TIFF, RAW (DNG, CR3, NEF, ARW), and MOV/MP4 for videos (date and length only) |
| labels | Vision: the top 5 labels above 0.3 confidence |
| faces, text lines | Vision: a count of faces and of lines of text (the text itself isn't stored) |
| quality, utility | Vision aesthetics score and the isUtility flag |
| fingerprint | Vision feature print, stored for the similar-photo check |
| groups | Live Photo pairs (`IMG_1234.HEIC` + `.MOV`), RAW + JPEG pairs, edit sidecars (`.AAE`, `.XMP`): they always move together |

Indexing is resumable. Unchanged files (same path, size and modified time) are skipped. Files that can't be read
are listed with the reason.

## Step 2 · Make sense of it

**Kinds** (each photo gets one):

| Kind | Rule |
|---|---|
| Camera photo | camera `Make` present, or Vision sees a scene and isUtility is false |
| Screenshot | Vision label `screenshot`, a screenshot file name, or a PNG at a screen size with no camera data |
| Document or receipt | isUtility true and labels `document`, `receipt`, `printed_page` or `whiteboard`, or many text lines |
| Saved or forwarded | no camera data, a messaging-app file name (WhatsApp, Telegram), or a web image size |
| Video | MOV, MP4, M4V |
| Duplicate | the same full hash as an earlier file (the earliest or best-named copy stays where it sorts) |
| Similar | fingerprint distance under a threshold within 10 seconds of each other: bursts and retakes. Shown as a group, never moved apart |

**Events:** photos sorted by time are split where the gap is longer than 3 hours (you can change this), or where
GPS jumps more than 50 km. Each event is named from its date and its most common labels, for example
`2026-11-13 · beach, people (42)`. You can rename events in the plan.

## Step 3 · The plan

```text
Sorted Photos/
  2026/
    2026-11 November/
      2026-11-13 Beach, people/      ← events, when "by event"
  Screenshots/2026-11/
  Documents and receipts/2026/
  Videos/2026/
  Duplicates/                        ← to check, never deleted
  Undated/                           ← only a modified-time date: not trusted alone (--trust-file-dates sorts them anyway)
```

Layouts: **by event** (default), **by month** (`YYYY/YYYY-MM`), **by kind** (kinds first, then by month). The plan
shows counts per folder, 10 sample moves per folder, the date source for each file (EXIF, file name, guessed) and
everything it will skip.

## Step 4 · Apply

- **Copy** (default): into a new folder you pick, `~/Pictures/Sorted Photos <date>` unless you say otherwise. The
  source isn't touched. Memory cards and read-only drives are copy only.
- **Move**: only within the same disk, and every move is written to `~/.macguard/photos/undo-<time>.jsonl` first.
  `macguard photos undo` puts every file back where it was, as long as nothing else has used that name since.
- **Tag in place**: writes Finder tags (`Screenshot`, `Receipt`, `2026-11-13 Beach`) and moves nothing. Uses the
  `xattr` command.
- Never overwrites: a name clash becomes `name (2).jpg`. Free space is checked before a copy. It stops cleanly if the
  disk fills or the card is removed, and the undo log covers what was done.

---

## Access ("disk access")

| Folder | What macOS does |
|---|---|
| Pictures, home folders, external drives you pick | Readable. macOS may ask once for Desktop, Documents, Downloads or removable volumes |
| Memory card (`/Volumes/<card>`) | Readable after one "allow access to removable volumes" prompt |
| `Photos Library.photoslibrary` | Refused by the sorter (P1). Phase P3 uses the Photos framework with your permission |
| Folders protected without Full Disk Access (Mail, Messages attachments) | Skipped and listed. We never turn on Full Disk Access for you; the guide says how if you want it |

The native app runs the helper from inside its bundle, so the macOS prompts name Mac Cleanup.

---

## How you use it

**App and web UI:** a **Photo sorter** card in Tools: pick a folder → **Index** (progress, can be stopped) →
an overview (years, events, kinds, duplicates, a few thumbnails per event made in memory and not saved) → choose a
layout and destination → **Copy** / **Move** / **Tag** → a result with **Undo**.

**CLI:**

```bash
macguard photos index ~/Downloads             # build or update the index
macguard photos summary ~/Downloads           # years, events, kinds, duplicates
macguard photos plan ~/Downloads --by event --to ~/Pictures/Sorted
macguard photos apply --plan last [--move | --tag]
macguard photos undo                          # reverse the last move
macguard photos find "beach 2024"             # search labels, dates and cameras in the index
```

**MCP:** `photos_index`, `photos_summary`, `photos_plan` and `photos_find` are read-only. `photos_apply` needs
`confirm: true` after the plan has been shown, like `apply_cleanup`.

---

## Code layout

| Part | Contents |
|---|---|
| `helpers/photo_sense.swift` | The Vision and ImageIO helper: reads a list of paths on stdin and writes one JSON line per file. It never writes files. Low priority (QoS utility), one image at a time, a size cap per image |
| `macguard_photos.py` | Index (sqlite3), date rules, kinds, events, plan, apply, undo, CLI, results in the shared Tools shape |
| `build_app.sh` | Compiles `photo_sense` into the app bundle |
| CLI without the app | Compiles `photo_sense` once with `swiftc` into `~/.macguard/bin/`. Without Swift, falls back to `mdls` dates and file names: sorting by date still works, kinds and similar photos don't, and the result says so |

## Phases

| Phase | Ships |
|---|---|
| **P1 · Sort a folder** | Index, dates, kinds, events, exact duplicates, plan, copy / move with undo, Finder tags, CLI, Tools card, MCP |
| **P2 · Review** | Similar-photo groups with a suggested best shot (sharpness and aesthetics), side-by-side review, search, "low quality" suggestions (never removed automatically) |
| **P3 · Photos library** | In the native app, with your Photos permission: index the library through PhotoKit (read-only) and create albums (by event, Screenshots, Receipts). Never deletes from Photos. Optional place names from an offline city list |

## Tests

- Synthetic files only: JPEGs written by the test with hand-made EXIF dates, PNGs at screen sizes, file names in
  every pattern, Live Photo and RAW + JPEG pairs, and exact copies for duplicates. Never real photos of people.
- The Swift helper is stubbed with recorded JSON lines. One smoke test compiles and runs it on a generated image,
  and is skipped when `swiftc` is missing.
- Must pass: nothing written to the source in copy mode; undo restores every moved file; name clashes never
  overwrite; pairs stay together; the Photos library is refused; a missing date goes to `Undated`, never to a
  guessed year on its own.
