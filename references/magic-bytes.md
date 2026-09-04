# Magic bytes quick reference

Hex at offset 0 unless noted. Source: filesig.search.org (successor to Gary Kessler's table).
`identify.sh` prints the first/last 16 bytes of every file — compare against this.

## Images / media
| Format | Header | Trailer / note |
|--------|--------|----------------|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | trailer `49 45 4E 44 AE 42 60 82` (IEND). Data after IEND = hidden. |
| JPEG | `FF D8 FF E0/E1/E8/DB` | trailer `FF D9`. Data after = hidden. |
| GIF | `47 49 46 38 37 61` / `...39 61` | GIF87a / GIF89a |
| BMP | `42 4D` | |
| WEBP | `52 49 46 46 .. .. .. .. 57 45 42 50` | RIFF….WEBP |
| TIFF | `49 49 2A 00` / `4D 4D 00 2A` | LE / BE |
| WAV | `52 49 46 46 .. .. .. .. 57 41 56 45` | RIFF….WAVE |
| MP3 | `49 44 33` (ID3) or `FF FB` | |
| FLAC | `66 4C 61 43` | fLaC |
| OGG | `4F 67 67 53` | OggS |
| MP4/MOV | `.. .. .. .. 66 74 79 70` at offset 4 | `ftyp`. Boxes: ftyp/mdat/moov. mdat size 0 = unfinalized. |
| AVI | `52 49 46 46 .. .. .. .. 41 56 49 20` | RIFF….AVI . movi LIST holds 00dc/01wb/02tx. |
| Matroska/MKV | `1A 45 DF A3` | |
| H.264 Annex-B | `00 00 00 01 67` SPS / `68` PPS / `65` IDR / `41` non-IDR | concatenate into .h264, ffmpeg plays it |

## Archives / documents
| Format | Header | Note |
|--------|--------|------|
| ZIP / DOCX / XLSX / PPTX / JAR / APK | `50 4B 03 04` | empty `50 4B 05 06`, spanned `50 4B 07 08`. Central dir ends `50 4B 05 06`. |
| RAR | `52 61 72 21 1A 07 00` (v4) / `..01 00` (v5) | |
| 7z | `37 7A BC AF 27 1C` | |
| GZIP | `1F 8B 08` | |
| BZIP2 | `42 5A 68` | |
| XZ | `FD 37 7A 58 5A 00` | |
| PDF | `25 50 44 46` (%PDF) | trailer `%%EOF` (may repeat — /Prev = older revision) |
| OLE/CFB (doc/xls/ppt/msi/hwp) | `D0 CF 11 E0 A1 B1 1A E1` | HWP 5.x is OLE; stream "HWP Document File" |
| HWPX | `50 4B 03 04` (it is a zip) | mimetype = application/hwp+zip |
| RTF | `7B 5C 72 74 66` | {\rtf |

## Executables
| Format | Header | Note |
|--------|--------|------|
| PE (exe/dll/sys) | `4D 5A` (MZ) | "PE\0\0" at e_lfanew. Rich header ~0x80. A `.pptx`/`.png` starting MZ is a disguised PE. |
| ELF | `7F 45 4C 46` | |
| Mach-O | `FE ED FA CE/CF` / `CA FE BA BE` (fat) | |

## Forensic artifacts
| Artifact | Header | Note |
|----------|--------|------|
| SQLite | `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00` | "SQLite format 3". Byte 18/19: 0x02 = WAL mode. |
| EVTX | `45 6C 66 46 69 6C 65 00` | "ElfFile" |
| Registry hive | `72 65 67 66` | "regf" |
| Prefetch | `53 43 43 41` at offset 4 (SCCA) | Win10 compressed: `4D 41 4D 04` (MAM) |
| LNK | `4C 00 00 00 01 14 02 00` | |
| PCAP | `D4 C3 B2 A1` / `A1 B2 C3 D4` | ns: `4D 3C B2 A1` |
| PCAPNG | `0A 0D 0D 0A` | |
| E01 (EWF) | `45 56 46 09 0D 0A FF 00` | "EVF" |
| VMDK | `4B 44 4D 56` | "KDMV" (sparse) |
| VDI/VHD/QCOW2 | `<< oracle` / `conectix` / `51 46 49 FB` | |
| LUKS | `4C 55 4B 53 BA BE` | version at offset 6 (1 or 2) |
| ISO9660 | `43 44 30 30 31` at 0x8001 | CD001 |

## Locate a signature inside a blob
```bash
xxd file | head                      # eyeball header
bgrep 89504e47 blob.bin              # find PNG magic (from binwalk suite)
binwalk blob.bin                     # signature scan
foremost -t all -i blob.bin -o out   # carve by signature
```
