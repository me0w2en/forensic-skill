---
name: multimedia-stego
description: |
  Image, audio and video steganography and media forensics: metadata, LSB, appended/embedded data,
  spectrograms, tamper localisation, container repair for playback, frame/OCR extraction, and geolocation.
  Enter when the artifact is a PNG/JPG/GIF/BMP/WEBP/WAV/MP3/FLAC/MP4/AVI/MKV, a dashcam/DVR/360 clip, or a
  "hidden message / won't play / find the flag in this image" task. Structure-only repair of a corrupted
  file may start in file-format-carving; stego and media analysis are here.
  Trigger keywords: stego, 스테가노그래피, steganography, LSB, zsteg, steghide, stegseek, stegsolve, outguess,
  exif, exiftool, spectrogram, sox, audacity, morse, dtmf, sstv, png, jpeg, gif, wav, mp3, mp4, avi, ffmpeg,
  ffprobe, h264, mdat, moov, ftyp, movi, fourcc, dashcam, dvr, 360, equirect, ocr, tesseract, what3words, 은닉.
---

# Multimedia & Steganography

Follow a decision tree by carrier type. Universal first pass first, then the carrier-specific tools.
When a file won't play, repair its structure before analysing content.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/` (hashes verified, timezone/format recorded).
2. `NOW`  Read `../../tool-index.md`: `exiftool`/`binwalk`/`zsteg`/`pngcheck`/`ffmpeg`/`ffprobe`/`sox`/
   `outguess`/`imagemagick`/`tesseract` availability. `steghide`/`stegseek` are missing on mac-ARM → docker.
3. `NEXT` Universal pass: `file`, `exiftool -a -u -g1`, `strings -n8`/`-el`, `binwalk`, check data after trailer.
4. `NEXT` Branch by carrier (PNG/JPEG/audio/video) using the workflow below.
5. `ACT`  Save recovered artifacts, hash, convert any timestamp to the asked timezone, log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| A corrupted container needing pure structure/CRC repair | `skills/file-format-carving/` (repair), then return here |
| An embedded archive/document/PE | `skills/file-format-carving/` |
| A photo's device provenance in a mobile dump | `skills/mobile-artifacts/` (EXIF LensModel) |
| Audio/keystrokes carried inside network traffic | `skills/network-forensics/` |

## Tools (install-name → what it's for)
- `exiftool` ✅ — all metadata + embedded thumbnail: `exiftool -a -u -g1 f`.
- `binwalk` ✅ — embedded/appended files; `binwalk -e`.
- `zsteg` ✅ / `zsteg-mask` ✅ — PNG/BMP LSB & channel stego: `zsteg -a f.png`.
- `pngcheck` ✅ — PNG chunk validity/text: `pngcheck -vtp7 f.png`.
- `ffmpeg` ✅ / `ffprobe` ✅ — stream inspection, frame/subtitle/audio extraction, VR de-warp, raw H.264 decode.
- `sox` ✅ — spectrogram: `sox f.wav -n spectrogram -o spec.png`.
- `outguess` ✅ — JPEG stego extract.
- `identify`/`convert` ✅ (imagemagick) — corruption spotting, palette/raw rendering, image diff.
- `tesseract` (brew) — OCR extracted frames.
- `steghide`/`stegseek` (no mac-ARM build) — JPEG/BMP/WAV passworded stego → `docker run rickdejager/stegseek`.
- StegSolve (java jar) — bit-plane/alpha/MSB browsing, image XOR.
- `python3` + `librosa`/`numpy` — audio tamper localisation.

## Workflow

### Phase 0 — Universal first pass
```bash
file f; exiftool -a -u -g1 f; strings -n 8 f; strings -el f      # UTF-16 too
binwalk f; tail -c 32 f | xxd                                     # data after IEND/FFD9/%%EOF?
```

### Phase 1 — PNG / BMP
```bash
zsteg -a f.png                       # try all LSB/channel combos
zsteg -E 'b1,rgb,lsb,xy' f.png > out.bin
pngcheck -vtp7 f.png                 # chunk order, tEXt/zTXt/iTXt, data after IEND
# IHDR height reduced to hide pixels (CRC error but sane dims): recompute/brute-force height, then re-view.
# StegSolve: browse all bit planes incl. ALPHA and MSB (zsteg misses alpha/MSB by default).
```

### Phase 2 — JPEG (no LSB; use DCT-domain tools)
```bash
exiftool -Comment -UserComment f.jpg
docker run --rm -v "$PWD":/d rickdejager/stegseek /d/f.jpg /d/rockyou.txt   # passworded steghide
# or: steghide extract -sf f.jpg -p ''   (empty password FIRST) via docker
outguess -r f.jpg out.txt
```

### Phase 3 — Audio
```bash
sox f.wav -n spectrogram -o spec.png            # ALWAYS spectrogram first (hidden text/SSTV/harsh tone)
ffprobe f.wav; mediainfo f.wav
# Morse/DTMF: multimon-ng -a MORSE_CW -a DTMF -t wav f.wav
# LSB in WAV: stegolsb wavsteg -r -i f.wav -o out.txt -n 1 -b 1000
```
Tamper localisation with a reference (KDFC #104 Fake Voice): per-frame STFT magnitude L1 diff:
```python
import numpy as np, librosa
o,sr=librosa.load('original.wav'); m,_=librosa.load('modified.wav')
d=np.sum(np.abs(np.abs(librosa.stft(o))-np.abs(librosa.stft(m))),axis=0)
i=np.where(d>1)[0]           # threshold above baseline mean/max
t=lambda idx: idx*(len(o)/sr)/len(d)
print('insert', t(i[0]), '->', t(i[-1]), 'sec')
```
Answer is a song title? Use music recognition (Melon/Shazam), not transcription (KDFC #101).

### Phase 4 — Video & containers
```bash
ffprobe -hide_banner f.mp4                      # extra/odd streams, projection
ffmpeg -i f.mkv -map 0:s:0 subs.srt             # subtitles
ffmpeg -dump_attachment:t "" -i f.mkv           # attachments
ffmpeg -i f.mp4 -vn audio.wav                   # audio track
ffmpeg -i f.gif -vsync 0 out/f%05d.png          # frames -> then tesseract
```
Container repair / smuggling:
- MP4 won't play, `moov` missing, `mdat` size 0 → set `mdat size = moov_offset - mdat_offset` (KDFC #101).
- "Wrong box for the container": an AVI `movi` box inside an MP4 hides data (KDFC #302).
- Raw H.264 Annex-B (`00 00 00 01 67` SPS / `41` P-slice) can be concatenated into `.h264` and played:
  ```bash
  ffplay out.h264; ffmpeg -i out.h264 -frames:v 1 frame.png
  ```
- Proprietary DVR: hex-scan for repeated 4-char tags (`00VI`/`00VP`) with a following LE size + embedded
  LE Y/M/D/h/m/s timestamp; walk chunks, dump all timestamps, find the outlier (KDFC #152/#202).
360/VR de-warp then OCR (KDFC #302):
```bash
ffmpeg -i seoul.mp4 -vf v360=equirect:c3x2 cube.mp4     # then split faces, tesseract each
# a word.word.word string is a what3words geocode -> resolve to a location.
```

## Flag-hiding checklist
- Metadata (Comment/UserComment/Artist), embedded thumbnail (`exiftool -b -ThumbnailImage`).
- Data appended after IEND/FFD9/%%EOF; embedded files via binwalk.
- LSB across channels/bit-planes/alpha/MSB (zsteg + StegSolve).
- IHDR height tamper hiding pixels below the visible image.
- Passworded steghide/outguess (try empty password, then rockyou via stegseek).
- Spectrogram text, Morse/DTMF/SSTV in audio; >15 kHz bands.
- Audio hidden in MP4 `mdat` with no `moov` — strip video/subtitle structs, import raw in Audacity (KDFC #304).
- Wrong-container box smuggling; encrypted blob inside a box → decrypt → often a PNG with more stego.
- On-screen text in video (subtitle overlay, VR faces) via frame diff + OCR; what3words location.

## Pitfalls
- Repair structure BEFORE stego tools (a broken PNG defeats zsteg).
- Match tool to carrier: zsteg = PNG/BMP only; steghide = JPEG/BMP/WAV; outguess = JPEG.
- `librosa.load` resamples to 22050 by default — load both files identically or the diff is meaningless.
- A single P-frame can't decode alone — extract from the preceding I-frame (SPS/PPS) through it.
- Equirectangular frames are unreadable until reprojected.

## Worked precedents
- **KDFC2023 #104 Fake Voice** — STFT per-frame diff localises inserted audio.
- **KDFC2023 #101/#304** — dashcam MP4 `mdat` size 0 repair; recover hidden songs from `mdat`.
- **KDFC2023 #152 / #202** — proprietary DVR/AVI FourCC walker → raw `.h264` → ffmpeg.
- **KDFC2023 #302 Do not blink** — `movi`-in-MP4 timestamp, VR de-warp + OCR, decrypt → PNG stego → what3words.

## References
- `../../references/magic-bytes.md`
- Aperi'Solve stego decision tree: https://www.aperisolve.com/cheatsheet
- stego-toolkit: https://github.com/DominicBreuker/stego-toolkit
- Audio stego / spectrogram: https://img2sound.com/articles/audio-steganography-cheatsheet/ (`knowledge/web-dfir-sources.md` §6)
