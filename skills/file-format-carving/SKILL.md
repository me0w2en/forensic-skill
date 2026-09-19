---
name: file-format-carving
description: |
  Fallback and file-format skill for anything `file` calls "data", corrupted or repaired containers,
  archives, Office/HWP/PDF documents, PE-in-disguise, and polyglots. Identify by magic bytes, carve
  embedded files, diagnose declared-vs-actual sizes, repair headers, crack/inspect archives, and read
  document/PE internals (Rich Header, PDB path, VBA macros, PDF objects). Enter when the artifact is an
  unknown blob, a broken/unopenable file, an archive, an OOXML/HWP/PDF, or a file whose real type differs
  from its extension. Media/stego repair proper belongs to multimedia-stego; deep RE belongs elsewhere.
  Trigger keywords: data, unknown, corrupt, magic bytes, 매직바이트, carving, 카빙, binwalk, foremost,
  bulk_extractor, scalpel, dd carve, zip, rar, 7z, gzip, ooxml, docx, xlsx, pptx, hwp, hwpx, pdf, polyglot,
  rich header, PDB, PE, MZ, olevba, oledump, pdfid, pdf-parser, qpdf, bkcrack, zip2john, CRC, chunk.
---

# File Format & Carving (fallback)

You are here because the type is unknown/corrupted, it is a container/document, or the extension lies.
Trust bytes, not names. Fix structure before extracting payloads.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm you arrived via `forensics-router` with a `work/<case>/` (hashes verified, timezone +
   answer format recorded). If not: `scripts/case-init.sh`, `scripts/identify.sh`.
2. `NOW`  Read `../../tool-index.md`; on this host binwalk/foremost/bulk_extractor/7z/qpdf/olevba/
   pdfid.py/pdf-parser.py/oledump.py/yara are ✅. Read `../../references/magic-bytes.md`.
3. `NEXT` `xxd file | head` and `tail -c 32 file | xxd` — compare header/trailer to the magic-bytes table.
   Check entropy (identify.sh prints it): ~8.0 = encrypted/compressed, ~7.9 also common for media.
4. `NEXT` Decide: unknown blob → carve; corrupted known type → repair header first; archive/doc → inspect
   internals; extension mismatch → treat as the real type.
5. `ACT`  Extract to `work/<case>/extracted/`, hash outputs, verify with `file`, log to `timeline.md`.

## When to use / hand off
| If the artifact is really… | Go to |
|---|---|
| Media that won't play, or stego in image/audio/video | `skills/multimedia-stego/` (do structure repair here first if needed) |
| A whole disk / filesystem image | `skills/disk-image/` |
| A pcap | `skills/network-forensics/` |
| An extracted PE that needs real reverse engineering | out of scope — collect strings/YARA/IOCs, hand to an RE pack |
| SQLite / browser / app DB | `skills/mobile-artifacts/` |

## Tools (install-name → what it's for)
- `binwalk` ✅ — signature scan + `-e`/`-M` recursive extract of embedded files.
- `foremost` ✅ — header/footer carving by type: `foremost -t all -i blob -o out`.
- `bulk_extractor` ✅ — scan a blob for emails/urls/ip/zip/json/aes_keys without a filesystem — great first pass.
- `scalpel` (apt; no brew) — configurable carver; fallback to foremost.
- `7z` ✅ / `unzip` ✅ / `zipdump.py` ✅ — archive listing/extraction; `7z l` often reads polyglots.
- `qpdf` ✅ / `pdftotext` ✅ (poppler) / `pdfid.py` ✅ / `pdf-parser.py` ✅ — PDF structure, decrypt, extract.
- `olevba` ✅ / `oledump.py` ✅ / `oleid` ✅ / `rtfobj` ✅ — Office OLE/OOXML macros and embedded objects.
- `hwp5txt` (pip `pyhwp`) / `olefile` — HWP 5.x (OLE) text/streams; HWPX is a zip.
- `yara` ✅ — signature-match a blob against rules.
- `john`/`zip2john` ✅, `fcrackzip` (apt), `bkcrack` (build) — archive password / ZipCrypto known-plaintext.
- `xxd`/`hexdump`/`dd` ✅ — manual inspection and byte-surgery carve.

## Workflow

### Phase 1 — Identify unknown blobs
```bash
file blob; xxd blob | head; tail -c 32 blob | xxd
binwalk blob                                  # embedded signatures + offsets
bulk_extractor -o be_out blob                 # emails/urls/ip/zip/aes_keys feature files
strings -n 8 blob | grep -iE 'flag\{|ctf\{|kdfc|dfc\{|http|BEGIN'
```
TrID or `binwalk` for obscure formats. `bgrep 89504e47 blob` finds a magic anywhere.

### Phase 2 — Carve embedded / appended files
```bash
binwalk -e blob                               # auto-extract (watch _blob.extracted/)
binwalk -M -e blob                            # recursive
foremost -t all -i blob -o fore_out
# Manual carve when you know offset+length (from binwalk):
dd if=blob of=extracted/inner.zip bs=1 skip=1335205 count=40668937
# Appended data after a trailer (very common CTF trick):
#   PNG ends at IEND(49454E44AE426082), JPEG at FFD9, PDF at %%EOF — anything after is hidden.
```

### Phase 3 — Repair a corrupted known type (do this BEFORE extraction/stego)
Diagnose with declared-vs-actual size (KDFC #202): if a chunk's declared size disagrees with the
distance to the next chunk by an amount that scales with size, a fixed-period marker was injected.
```bash
# find the period and value, then strip in python:
python3 - <<'PY'
d=open('in.img','rb').read()
d=d.replace(bytes.fromhex('<8-byte marker hex from your size-delta analysis>'.replace(' ','')),b'')  # example marker every 0x1000
open('clean.bin','wb').write(d)
PY
```
PNG repair (see multimedia-stego for stego; here just structure): `pngcheck -vtp7 f.png`; fix signature
`89 50 4E 47 0D 0A 1A 0A`, IHDR length/type, recompute CRC `python3 -c "import zlib;print(hex(zlib.crc32(b'IHDR'+data)&0xffffffff))"`.

### Phase 4 — Archives
```bash
7z l suspect.png            # is there a zip appended?
zipdetails -v file.zip      # (perl) full structure, encryption method
unzip -l file.zip           # filenames are visible even when encrypted
zip2john file.zip > h; john --wordlist=rockyou.txt h        # AES-encrypted zip
# ZipCrypto (not AES) with known plaintext of any stored file -> bkcrack:
bkcrack -C file.zip -c secret.txt -p known_plain.bin
```

A zip appended after another file's trailer (PNG `IEND`, JPEG `FFD9`, …) is often truncated —
the writer stopped after the last central-directory entry and never wrote the End Of Central
Directory record, so `unzip`/`7z` refuse it ("cannot find zipfile directory"). Rebuild the EOCD
by hand instead of assuming the archive is corrupt or bogus:
```python
import struct
zdata = data[pk0304_offset:]                       # slice starting at the first "PK\x03\x04"
cd_start = data.find(b'PK\x01\x02') - pk0304_offset  # first central-directory offset, relative
cd_size  = len(zdata) - cd_start
n_entries = zdata.count(b'PK\x01\x02')
eocd = b'PK\x05\x06' + struct.pack('<HHHHIIH', 0, 0, n_entries, n_entries, cd_size, cd_start, 0)
open('fixed.zip', 'wb').write(zdata + eocd)
```
If `unzip` then reports the entry itself as encrypted (general-purpose flag bit 0 set), that's a
normal ZipCrypto/AES password gate, not a second corruption — go to password recovery below.

### Phase 5 — Documents (OOXML / OLE / RTF / HWP / PDF)
```bash
# OOXML is a zip:
unzip -o doc.docx -d docx_x; ls -R docx_x
#   hidden text: grep -R 'w:val="FFFFFF"\|w:vanish' docx_x/word/document.xml
#   macros: docx_x/word/vbaProject.bin -> olevba
olevba --decode suspect.docm
oledump.py suspect.doc; oledump.py -s 3 -v suspect.doc      # decompress VBA stream 3
rtfobj suspect.rtf                                          # embedded objects
# Orphaned media: cross-check every word/media/* (or ppt/, xl/) file against every
# .rels that could reference it. A picture/PNG present in the package but absent from
# ALL relationship files is never rendered by the app and is a prime place to hide a
# trailer-appended archive or LSB payload (see Phase 4 / multimedia-stego).
grep -o 'media/[^"]*' word/_rels/document.xml.rels word/_rels/header*.rels word/_rels/footer*.rels 2>/dev/null \
  | sort -u > referenced.txt
ls word/media | sort > present.txt
comm -13 referenced.txt present.txt     # media files nobody points to
hwp5txt report.hwp                                          # HWP 5.x (OLE) text; HWPX: unzip
# PDF:
pdfid.py f.pdf                                              # /JS /OpenAction /Launch /EmbeddedFile /ObjStm counts
pdf-parser.py --search flag f.pdf
pdf-parser.py -o 12 -f -d out.bin f.pdf                     # filter+dump stream of object 12
qpdf --qdf --object-streams=disable in.pdf greppable.pdf   # then grep
grep -c '%%EOF' f.pdf                                       # multiple = incremental updates (older revisions via /Prev)
```

### Phase 6 — PE and PE-in-disguise
```bash
xxd suspect.pptx | head        # starts with 4D 5A ("MZ") => it's a PE, not a pptx (KDFC #303/#253)
# Rich Header (build toolchain fingerprint, ~offset 0x80, DanS...Rich+XOR key):
python3 -c "import pefile;pe=pefile.PE('a.exe');print(pe.parse_rich_header())"
#   map ProductIDs via kirschju/richheader prodids.py -> [ProductID].[BuildID].[Count]
# CodeView PDB path (build folder / user):
python3 -c "import pefile;pe=pefile.PE('a.exe');pe.parse_data_directories();\
print([e.entry.PdbFileName for e in pe.DIRECTORY_ENTRY_DEBUG if hasattr(e.entry,'PdbFileName')])"
```

## Flag-hiding checklist
- Data appended after PNG `IEND` / JPEG `FFD9` / `%%EOF`; `binwalk -e`, `7z l file.png`, `dd` carve.
- Deliberately corrupted header/CRC/chunk-length — repair, then re-extract.
- IHDR height reduced to hide pixels (CRC mismatch) — recompute/brute-force (see multimedia-stego).
- Fixed-period injected marker inflating chunk sizes (KDFC #202) — strip then carve.
- Extension lies: `.pptx`/`.png` that is really `MZ`/PE; `movi` box inside an MP4.
- Archive: filenames visible in encrypted zip; ZipCrypto known-plaintext; empty-password first.
- OOXML: white/vanished text, `docProps` author/times, unreferenced parts (Phase 5), `vbaProject.bin`
  macros, and hand-inserted `customXml/itemN.xml` parts with no matching `itemPropsN.xml`/`.rels` —
  a real Office feature always registers both; an orphan custom-XML part (fake "classification"/
  "keyWrap"/"metadata" tags) is author-planted and worth decoding, not dismissing as flavour text.
- PDF: incremental-update older revisions (`/Prev`), JavaScript/Launch, invisible layers, embedded files.
- PE provenance: Rich Header + PDB path reveal toolchain/user/build folder (KDFC #103).
- A "custom crypto tool" binary (stripped ELF/PE, may statically link a real crypto lib like OpenSSL for
  the cipher primitive itself) that seeds its own key/permutation generator from `srand(time(NULL))` or
  equivalent is a recurring, deliberately-weak pattern. `strings`/`nm` for `srand`/`rand`/`time` imports is
  the tell. Reimplement the exact PRNG in Python (glibc's `rand()` is a public TYPE_3 additive-feedback
  algorithm — a from-scratch reimplementation is easy to verify against the textbook seed=1 output
  sequence `1804289383, 846930886, ...`) and brute-force the seed using a filesystem timestamp
  (mtime/ctime, ideally sub-second/nanosecond resolution) as the search anchor — the seed is almost always
  within a couple of seconds of when the output file was written. Replay the *same* call order the binary
  uses (RNG calls for setup tables consume the stream before the "real" per-round choice) before applying
  any inverse transform, and validate each candidate seed against a structural check (file magic bytes,
  padding validity) rather than trusting the first plausible-looking output.
- Layered encodings: hex → base64 → zlib/gzip → XOR → ROT13; decode iteratively in CyberChef or by hand.
  A base64-shaped string that decodes to non-printable noise is not automatically a decoy — the encoder
  order may be reversed from what you tried (e.g. ROT13-then-base64: rotate the *encoded* string 13
  first, THEN base64-decode the result). Before writing any suspicious string off as noise/red herring,
  try ROT13 (and a single-byte XOR sweep) on it BEFORE base64-decoding, not just after.

## Pitfalls
- Repair structure BEFORE running stego/extraction tools — polluted payloads defeat zsteg/steghide.
- `bytes.replace` of a marker can hit a legitimate payload occurrence — verify positions are period-aligned.
- Rich Header XOR key is the 4 bytes AFTER `Rich`; decode with pefile, not by hand.
- A single H.264 P-frame can't decode alone — that's a media task; hand to multimedia-stego.
- Java int-array IVs like `{...,9,16,17...}` may be meant as hex bytes `09 10 11` (KDFC #301 trap).
- Don't sink time into password brute-force (rockyou + rules, alnum exhaustion, themed wordlists) before
  re-checking every suspicious string in the package for a layered-encoding password hint — an archive
  password that resists a large wordlist attack is a signal you're missing a decode step, not that you
  need a bigger wordlist. Exhaust "decode this string differently" before "guess more passwords".
- A zip that fails to open with "cannot find zipfile directory" is usually just missing its EOCD record
  (see Phase 4), not a hash-mismatched or intentionally-destroyed archive — try the EOCD rebuild first.
- Before spending time on real cryptanalysis of a "custom crypto tool", check whether it just seeds a
  standard PRNG from the current time — a `srand(time())`-class bug turns "unbreakable" into "look up the
  file timestamp" and is far more common in these binaries than a genuine algorithm weakness.

## Worked precedents
- **KDFC2023 #103 A suspicious developer** — Rich Header `[ProductID].[BuildID].[Count]` + CodeView PDB path prove build provenance.
- **KDFC2023 #202 Why is not it playing** — 8-byte marker injected every 0x1000 inflates AVI chunk sizes; strip then carve H.264.
- **KDFC2023 #303 Audit My Corporation / #253** — a `.pptx`/`.png` that is actually a PE; check `MZ` first.
- **KDFC2023 #251 Find the suspect** — Dropbox `config.dbx`/SQLite carving for deleted rows.
- **Unreferenced-media + truncated appended zip + ROT13-wrapped password** — a plain-looking `.docx`
  hid its payload in a `word/media/*.png` with no relationship reference; the PNG's `IEND` was followed
  by a zip missing its EOCD (Phase 4 rebuild), the inner entry was ZipCrypto-locked, and the password
  was hidden as a decoy-looking `customXml` value that only became valid base64 after ROT13. The
  flag itself was then a further base64 layer inside the decrypted note. Large wordlist/brute-force
  attacks on the zip password were a dead end by design — the fix was decoding the hint differently,
  not guessing harder.
- **`srand(time())`-seeded "unbreakable" cipher** — a small stripped binary XOR/substitution/permutation
  "encrypted" a file byte-for-byte in rounds, with per-round tables generated by `rand()` seeded once from
  `time(NULL)`. Recovering the exact glibc `rand()` algorithm and brute-forcing the ~few-second window
  around the ciphertext file's own filesystem mtime (nanosecond-resolution ext4 timestamps narrowed the
  window to a handful of candidates) recovered the seed outright; the first correct candidate was
  confirmed by the decrypted output starting with the expected file's magic bytes.

## References
- `../../references/magic-bytes.md`, `../../references/timestamps.md`
- Trail of Bits CTF Field Guide — Forensics: https://trailofbits.github.io/ctf/forensics/
- pngcheck repair walkthrough (picoCTF c0rrupt): https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/c0rrupt.md
- bulk_extractor: https://github.com/simsong/bulk_extractor
- Didier Stevens PDF/OLE tools: https://blog.didierstevens.com/ (`knowledge/web-dfir-sources.md` §7)
