# AI image and voice check: research and design

**Status:** research and design, 13 Nov 2026. Nothing is built yet. Part of the **Tools** section
([TOOLS.md](TOOLS.md)), built after Recover files (R1).

**Goal:** you give Mac Cleanup a picture or a voice clip, and it tells you whether it carries signs of being made
by AI. It shows what it found, how strong that evidence is, and what it couldn't check.

**Principles**
- Local first. The file is analyzed on your Mac. An online check is an extra, per-file choice that says where the
  file would go. It's never automatic.
- Honest results. Evidence has strengths, and the tool shows them. **It never says a file is "real".** "No AI
  markers found" is a different statement, and the result says so.
- Read-only. Files you give it are never changed, and uploads to the local UI are deleted after the check.
- Standard library for the built-in checks. Stronger checks use tools or models you choose to install.

---

## What can and can't be detected

| Signal | Strength | Survives a re-save or screenshot? | Built-in? |
|---|---|---|---|
| **Content Credentials (C2PA)** with a valid signature | Proven: a signed statement from the tool that made it | No: most conversions and every screenshot remove it | Detect and read: yes. Verify the signature: with `c2patool` |
| C2PA manifest present, signature not verified | Strong, but unverified | No | Yes |
| **Metadata** that names an AI tool: IPTC `DigitalSourceType`, Stable Diffusion/ComfyUI PNG text, a TTS name in audio tags | Declared: easy to add, remove or fake | Rarely | Yes |
| **Invisible watermarks** (Google SynthID, Stable Diffusion's watermark, Meta AudioSeal) | Moderate when found | Partly | No: needs optional models, or the vendor's online detector |
| **AI classifier models** (image or voice) | Weak to moderate: often wrong on new generators and compressed files | — | No: optional local model |
| **Nothing found** | Says nothing about being real | — | — |

Most files people share have lost their markers: messaging apps, social networks and screenshots strip
metadata and Content Credentials. So the most common honest answer is "no AI markers found, which doesn't prove
anything". The tool says that clearly, along with what would help, such as getting the original file.

---

## Images

### Content Credentials (C2PA)

Where the manifest lives, by format (c2pa-rs asset handlers, C2PA 2.2 spec):

| Format | Location |
|---|---|
| JPEG | JUMBF in APP11 segments (may span several; must contain a `jumb` superbox labelled `c2pa`) |
| PNG | `caBX` chunk |
| HEIC, AVIF, MP4, MOV, M4A | ISO-BMFF `uuid` box (identifier to confirm against c2pa-rs) |
| WebP, WAV | RIFF `C2PA` chunk (to confirm) |
| MP3, FLAC | ID3v2 `GEOB` frame, MIME `application/c2pa` |

What we read, with a small CBOR decoder (about 150 lines; the stdlib has none):
- `c2pa.actions` / `c2pa.actions.v2`: a `c2pa.created` action with a `digitalSourceType`.
- IPTC digital source types (http://cv.iptc.org/newscodes/digitalsourcetype/):

  | Value | Meaning shown |
  |---|---|
  | `trainedAlgorithmicMedia` | Created with generative AI |
  | `compositeWithTrainedAlgorithmicMedia` | Edited with generative AI |
  | `compositeSynthetic` | Combined with synthetic content |
  | `algorithmicMedia` | Made by an algorithm (not AI) |

- `claim_generator` / `claim_generator_info`: the tool that made the claim (for example Adobe Firefly).

**Signatures:** a C2PA signature is COSE_Sign1 with an X.509 chain, an optional timestamp, hash bindings over the
file and trust lists. The standard library can't verify that, and a home-made verifier risks false "verified"
results. So:
- built in: "Content Credentials found: they say *created with generative AI* (by *tool*). Signature not checked."
- with `c2patool` installed (Apache-2.0/MIT): run it and quote its validation result as is.

Generators reported to embed C2PA (secondary sources, to confirm before we quote them in the UI): Adobe Firefly,
OpenAI image generation, Microsoft Designer and Bing Image Creator, Google Imagen and Gemini.

### Metadata

Parsed with the standard library (JPEG segments, PNG chunks, XMP as XML):
- XMP `Iptc4xmpExt:DigitalSourceType` (the same IPTC values as above).
- EXIF `Software`, `ImageDescription`, `UserComment`, `Artist`.
- PNG text chunks from local generators: Automatic1111 `parameters` ("Steps:, Sampler:, Seed:, Model:"), ComfyUI
  `prompt` and `workflow` (JSON), InvokeAI `invokeai_metadata`, NovelAI `Software` and `Comment`.
- Midjourney's IPTC description and digital source type.
- No camera `Make`/`Model` is **not** used on its own. Screenshots and web images lack them too.

macOS's own tools (`mdls`, `sips`) don't show most of these fields (checked during research), so we parse them
ourselves. `exiftool` is used if installed.

### Watermarks and classifiers (optional)

- **Google SynthID:** closed. Google's SynthID Detector is an online upload service (reported public in Oct 2026),
  so it can only be a Phase C, opt-in link.
- **Stable Diffusion `invisible-watermark`** (MIT): needs numpy, OpenCV and PyWavelets; its own docs say decoding
  isn't guaranteed. Phase B, weak signal.
- **Classifier models:** good in tests on known generators, much worse on new ones (one model reports 98% in-domain
  and about 76–83% on Imagen and Flux), and confused by JPEG compression and resizing. Many popular weights are
  non-commercial or no-derivatives licences; only MIT/Apache weights can be offered. A result shows the model's
  name, its score and that models like it are often wrong.

---

## Voice and audio

| Signal | Notes |
|---|---|
| C2PA in WAV, MP3, M4A, FLAC | Same parsing as images; rare in text-to-speech output today |
| Metadata | RIFF `LIST/INFO` (`ISFT`, `ICMT`), ID3 (`TSSE`, `TENC`, `COMM`, `TXXX`), MP4 `©too`. Only an explicit TTS or vendor name counts, as "declared". `Lavf` or `LAME` only names the encoder, not AI |
| Meta **AudioSeal** watermark (MIT code and weights) | Finds AudioSeal watermarks only, which few vendors use. Needs torch: Phase B |
| **AASIST / AASIST-L** anti-spoofing models (MIT, tiny) | Research models: about 1% error on the dataset they trained on, 12–17% on newer ones, and worse on modern voices. Phase B, shown as "a research model, often wrong" |
| ElevenLabs AI Speech Classifier | Online, detects ElevenLabs audio only. Phase C, opt-in link |
| Acoustic tricks (no breaths, flat noise, frequency cut-off) | Not used: phone calls and codecs look the same |

macOS has no built-in AI-voice classifier. A converted model could run through Core ML in the native app (Phase B).

---

## Verdicts

| Verdict | When | Shown as |
|---|---|---|
| `ai-proven` | `c2patool` validated a signed manifest that says AI | **Made with AI**: signed Content Credentials from *signer* |
| `ai-declared` (C2PA) | Manifest says AI, signature not checked | **Made with AI**, says an unverified Content Credentials record |
| `ai-edited` | `compositeWithTrainedAlgorithmicMedia` and similar | **Edited with AI** |
| `ai-declared` (metadata) | XMP, PNG generator text, TTS tag | **Made with AI**, says the file's metadata (metadata can be added or faked) |
| `likely-ai` | Phase B watermark or model | **Possibly AI**: *model*, score *x*, known error rate *y* |
| `no-markers` | Nothing found | **No AI markers found.** This does NOT mean it's real: most shared files have lost their markers |
| `unsupported` | Format not readable | What formats work, and how to convert without losing data |

Every result lists the evidence used, what wasn't checked, and the next step (for example "open the original file,
not a screenshot", or "install c2patool to verify the signature").

---

## Phases

| Phase | Ships |
|---|---|
| **A · Built in** | `macguard ai-check FILE`, the AI image and voice cards in Tools, MCP `ai_check`. Bounds-checked parsers for JPEG, PNG, ISO-BMFF, RIFF and ID3; a small CBOR reader for C2PA; XMP. `c2patool` and `exiftool` used when installed. Files are treated as untrusted: size limits, length checks, no recursion bombs |
| **B · Optional local models** | You opt in to an isolated environment (`~/Library/Application Support/macguard/ai-models`) or Core ML weights: invisible-watermark, AudioSeal, AASIST-L, an MIT/Apache image detector. Licence and size shown first, hashes pinned, never downloaded without asking |
| **C · Optional online checks** | Per file, with consent: SynthID Detector, ElevenLabs classifier, contentcredentials.org/verify. Shows where the file goes; never in batches; off by default |

## Tests (synthetic files only)

- Hand-built PNGs with `tEXt`, `iTXt` and `caBX` chunks (with CRCs), JPEGs with APP1 XMP and multi-segment APP11
  JUMBF, a WAV with `LIST/INFO` and a `C2PA` chunk, an MP3 with ID3 `TSSE` and `GEOB`.
- Hand-encoded CBOR actions for every digital source type.
- Must-pass cases: a file with no markers gives `no-markers` (never "real"); a file with faked metadata says
  "declared", not "proven"; truncated and oversized lengths fail safely.
- `c2patool` is stubbed in tests. Never real people's photos or voices.
- Checked during research: a stdlib script built a PNG with A1111 `parameters` and a `caBX` chunk, and a WAV with
  `ISFT="FakeTTS 1.0"`, and a 15-line parser read all three back.

## Ethics

- No upload without per-file consent. No telemetry. No copies, thumbnails or hashes kept after the check.
- Results are advice, not forensic or legal proof. A wrong "AI" label can hurt a real person, so error rates are
  always shown, and model results are never shown as proof.
- The tool never offers to strip, add or forge provenance.
- Model licences are respected: non-commercial or no-derivatives weights are never bundled.

## Sources

C2PA 2.2 specification (spec.c2pa.org) · c2pa-rs asset handlers (docs.rs/crate/c2pa) · c2patool (docs.rs/crate/c2patool) ·
IPTC digital source types (cv.iptc.org/newscodes/digitalsourcetype) · invisible-watermark (pypi.org/project/invisible-watermark) ·
AudioSeal (github.com/facebookresearch/audioseal) · AASIST (github.com/clovaai/aasist; huggingface.co/SpeechAntiSpoofingBenchmarks/AASIST) ·
ElevenLabs AI Speech Classifier (elevenlabs.io/docs/product-guides/audio-tools/ai-speech-classifier) ·
Community Forensics (arxiv.org/abs/2411.04125) · Microsoft Content Credentials (learn.microsoft.com/azure/foundry-classic/openai/concepts/content-credentials) ·
SMOGY detector model card (huggingface.co/Smogy/SMOGY-Ai-images-detector).
Vendor adoption, the SynthID Detector launch date and two container identifiers come from secondary sources or
memory and are checked again before Phase A ships.
