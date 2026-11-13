# Data recovery: research and design

**Status (14 Nov 2026):** R1 (light recovery and analyze), R2 (card imaging and carving) and R3 (FAT and exFAT
undelete) are built: `macguard recover search|analyze|image|scan`, the Recover files card with the gallery, MCP
`recover_*`, `macguard_recover.py` and `macguard_carve.py`. R4 (resumable imaging, scanning a mounted card's free space,
reports) and Sleuth Kit/PhotoRec as optional back ends are next.

**Checked when R2/R3 were built:** FAT32 (MBR), FAT16 (no partition table) and exFAT (GPT) images made with
`hdiutil`, with three files deleted on each: every deleted file came back byte for byte (`tests/test_carve.py`).
exFAT and long FAT names come back whole; a deleted 8.3 name loses its first letter (`_MG_0001.JPG`), as on every
FAT undelete tool. Carving finds JPEG, PNG, PDF, DOCX, WAV, MP4, HEIC and NEF in a hand-built "formatted card". The
imaging worker runs as root only inside the password prompt, passed inline (`python3 -I -c`), so no file on disk
can be swapped in; it was tested on a regular file with a simulated bad sector. Imaging a real card wasn't tried
from automation, because it needs the password dialog.
It's the first tool in the new **Tools** section ([TOOLS.md](TOOLS.md)), which also gets the AI image and voice checks.

**Goal:** help people get back files they deleted by mistake, on the Mac and on memory cards (SD, microSD, USB
sticks, camera cards), without ever making things worse. It comes in tiers, from a safe "light recovery" anyone can
run, through **analyze**, to **deep recovery** of a card.

**Principles** (the same as the rest of mac-cleanup):
- **Read-only on the source, always.** We never write to the card or disk being recovered. Recovered files go to a
  different volume.
- Local only: recovered files, thumbnails and logs never leave the Mac.
- Dry run first. Restoring copies files, it never moves them.
- No root except for the one step that truly needs it (reading a raw card), behind the normal macOS admin prompt.
- Standard library only for the built-in parts. Better tools are used if the user has them installed.
- Only the user's own devices.

---

## What can and can't be recovered

| Where the file was | Chance | Why |
|---|---|---|
| Trash (not emptied) | Very high | It's still there |
| Mac, with a Time Machine backup or APFS local snapshot from before the deletion | High | Restore from the backup or snapshot |
| iCloud Drive or Photos, within 30 days | High | "Recently Deleted" on icloud.com or in Photos |
| Git: a lost commit, a reset or deleted branch | High | `git reflog`, dangling objects |
| VS Code: an older version of a file | Medium | VS Code Local History |
| Memory card or USB stick (FAT32 or exFAT), deleted recently and **not written to since** | Medium to high | The data stays until it's overwritten |
| Memory card that was **formatted** (quick format) | Medium | The data area usually survives a quick format; file names don't |
| Internal Mac SSD (APFS), deleted and Trash emptied, no backup | **Almost none** | Apple Silicon storage is always encrypted with per-file keys, and TRIM erases freed blocks, very likely by the next restart |

The last row matters most for honesty: **no tool can undelete files from the internal SSD of a modern Mac.** The tool
says so plainly and points to backups and snapshots instead of pretending to search.

Sources: [Apple Platform Security, data protection](https://support.apple.com/guide/security/sece8608431d/web) ·
[Eclectic Light: better security means less recoverability](https://eclecticlight.co/2025/03/25/better-security-means-less-recoverability/) ·
[What TRIM does](https://rossmanngroup.com/technical-reference/what-trim-does-and-why-it-destroys-data) ·
[Apple: recover iCloud Drive files](https://support.apple.com/en-gb/111763) ·
[TestDisk/PhotoRec docs](https://www.cgsecurity.org/testdisk_doc/presentation.html)

---

## The tiers

### Tier 1 · Light recovery (no root, no risk)

`macguard recover` (and the **Recover files** card in the app's Tools section):

| Source | How | Notes |
|---|---|---|
| Trash | List `~/.Trash` and `.Trashes` on external volumes, newest first, with original paths where known | "Restore" copies to the original folder, or one you pick. Reading other volumes' `.Trashes` may need Full Disk Access |
| Time Machine | `tmutil listbackups`, then find the file's versions by path | Restore copies the chosen version out |
| APFS local snapshots | `tmutil listlocalsnapshots /`, mount read-only with `mount_apfs -s <snapshot> / <dir>` | Mounting may ask for admin (to test). Unmount afterwards |
| iCloud Drive, Photos | Guidance only: where "Recently Deleted" is, and the 30-day limit | Their libraries are databases; we don't read them |
| Git | `git reflog`, `git fsck --lost-found` per repo (repos are already found by `find_repos`) | Shows lost commits and dangling blobs with their first lines |
| VS Code Local History | `~/Library/Application Support/Code/User/History/` (path to verify) | Lists older versions of a file, by path |

Search is by name, type or path ("my thesis.docx", "*.jpg from last Tuesday"), across all sources at once.

### Tier 2 · Analyze (no root)

`macguard recover analyze [diskN]` before any deep recovery:
- **Which device:** `diskutil list -plist`, `diskutil info -plist`. Name, size, internal or removable, protocol
  (USB, SD), partition map, filesystem (FAT32, exFAT, HFS+, APFS), mounted or not, read-only, encrypted.
- **Health:** SMART status where the device reports it. Most USB card readers report "Not Supported", and we say so.
- **Verdict:** internal APFS SSD → "can't be recovered by scanning; use Tier 1". Card or stick → "good chance, stop
  using it now" (every write lowers the odds), with the next step.
- **Free space and file count** of a mounted card, so the user knows how full it is.

### Tier 3 · Deep recovery of a card (one admin prompt)

1. **Image the card first** (the only step that needs root):
   - Unmount, don't eject: `diskutil unmountDisk diskN`.
   - Read `/dev/rdiskN` read-only in sector-sized blocks into an image file on the Mac (or another disk), skipping
     bad blocks and recording them in a map. If GNU `ddrescue` is installed, use it: it retries and resumes.
   - It runs once behind the macOS admin password dialog, like packet capture does today.
   - Everything after this reads the **image**, never the card, and runs as the normal user.
2. **Undelete on FAT32/exFAT (keeps file names):** read directory entries in the image. On FAT a deleted entry
   starts with `0xE5` and still holds the start cluster and size, so contiguous files (most camera files) come back
   with their names. On exFAT the entry's in-use bit is cleared.
3. **Carve by file signature (no names):** for formatted cards or other filesystems, find files by their
   header and footer:
   - Photos: JPEG (`FF D8 FF … FF D9`), PNG (`89 50 4E 47 … IEND`), HEIC
   - Video: MP4 and MOV (ISO-BMFF `ftyp`, following the box sizes)
   - Camera RAW: CR2, NEF, ARW and other TIFF-based formats (TIFF header plus the IFD walk)
   - Documents: PDF (`%PDF … %%EOF`), ZIP-based files such as DOCX and XLSX (`PK\x03\x04` plus the central directory)
   - Carved files get generic names (`recovered-0001.jpg`). Fragmented files may come back damaged; we check each
     one (does the JPEG decode, does the ZIP open) and say which look intact.
4. **Review and save:** a gallery of what was found, with size, type and "looks intact". The user picks what to
   save, to a folder that **must be on a different volume than the card**.

Optional backends, used when installed (we call them as separate programs and never copy their code, so
mac-cleanup stays MIT):

| Tool | Licence | Used for |
|---|---|---|
| PhotoRec / TestDisk | GPL v2+ | Carving about 480 formats, partition repair |
| GNU ddrescue | GPL v2+ | Imaging cards with bad sectors, resumable |
| The Sleuth Kit (`fls`, `tsk_recover`) | IPL/CPL and others | Filesystem-aware undelete, including HFS+ |

`brew install testdisk ddrescue sleuthkit` adds them. The built-in carver works without any of them.

---

## Safety rules (enforced in code, tested)

1. The source device and image are only ever opened read-only (`O_RDONLY`). A test mocks `open` and fails on any
   other mode.
2. The output folder must not be on the source device. Compare `st_dev`, and `diskutil` for raw devices; refuse
   otherwise.
3. Deep scans of internal APFS are refused, with the reason and the Tier 1 alternatives.
4. Confirmation before imaging: "Only recover cards and disks you own." Recovered files may include other people's
   data on a second-hand card. The tool says so.
5. Nothing is sent anywhere. Logs go to `~/.macguard/recover/`. Deleting images or results goes to the Trash.
6. Never write to `/dev/disk*` and never run tests against real devices.

---

## Phases

| Phase | Ships | Root |
|---|---|---|
| **R1 · Light recovery and analyze** | The Tools section itself ([TOOLS.md](TOOLS.md)), `recover` (Trash, Time Machine, snapshots, git, VS Code history, iCloud and Photos guidance), `recover analyze`, the Recover files card, MCP tools `recover_search` and `recover_analyze` (read-only) | No |
| **R2 · Card imaging and carving** | `recover image diskN` (admin prompt, read-only, bad-block map, ddrescue if present), `recover carve <image>` (stdlib carver, about 8 formats, intact checks), the gallery | Imaging only |
| **R3 · Filesystem undelete** | FAT32/exFAT directory-entry undelete in pure Python (keeps names), Sleuth Kit as an optional backend for HFS+, PhotoRec as an optional deep carver | Imaging only |
| **R4 · Polish** | Resume interrupted imaging, recover straight from a mounted card's free space where possible, reports | — |

Each phase ships with its docs (README, ARCHITECTURE, INSTALL troubleshooting rows) and tests, like the rest of
mac-cleanup.

## Test strategy

- **Unit tests on byte buffers:** signatures, FAT/exFAT entries and the intact checks run on hand-built bytes, so
  they need neither `hdiutil` nor root.
- **End-to-end on synthetic images, never real cards:** create a FAT32 or exFAT image in a temp folder
  (`hdiutil create -size 64m -fs "MS-DOS FAT32" -layout NONE`, or `newfs_msdos -F 32` on a plain file), attach it
  (`diskutil image attach`), copy fixture files in, delete them, detach, then run undelete and carve on the image
  file and compare checksums. This was tried during research without root: a deleted JPEG's bytes were still in
  the image.
- **Safety tests:** read-only opens, output on another volume, internal APFS refused.
- `newfs_exfat` can't format a plain file, so exFAT fixtures come from `hdiutil`. On macOS 27, `hdiutil attach`
  prints a deprecation notice; use `diskutil image attach`.

## Verified on this Mac during research (macOS 27.2, Apple Silicon)

- `/dev/rdisk*` is `root:operator` mode 640: raw reads need root.
- `diskutil info` gives SMART status, protocol, removable, filesystem and FileVault without root.
- `tmutil listlocalsnapshots /` works without root.
- None of PhotoRec, TestDisk, ddrescue or Sleuth Kit is installed by default; `dd`, `hdiutil`, `newfs_msdos` and
  `newfs_exfat` are.
- The synthetic-image test flow works as described above.

Everything else in this document comes from the cited documentation, and gets checked as each phase is built.
