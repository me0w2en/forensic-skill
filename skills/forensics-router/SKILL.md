---
name: forensics-router
description: |
  Entry point for any digital-forensics / DFIR / forensic-CTF task. Identifies what artifact you were
  handed (disk image, memory dump, pcap, EVTX/registry, Docker/K8s/cloud logs, mobile dump, image/audio/video,
  odd file, blockchain address) and routes to the specialist skill, after enforcing hash verification,
  read-only handling, and answer-format/timezone capture. Use when the task mentions forensics, DFIR, CTF
  forensic challenge, KDFC/DFC, evidence, artifact, "find the flag in this file", disk/memory/network analysis,
  or when several forensic skills could apply and you are unsure where to start.
  Trigger keywords: forensics, forensic, DFIR, 포렌식, 디지털 포렌식, evidence, artifact, image file, dump, pcap,
  evtx, registry, carving, stego, timeline, CTF, KDFC, DFC, flag, writeup.
---

# Forensics Router

You were handed one or more artifacts and a question. Do not guess the tool. Do the four steps
below **in order**, then open exactly one specialist skill and follow it.

## ACTION REQUIRED (do now, do not stop to confirm)

1. `NOW`  If `work/<case>/` does not exist for this task: `scripts/case-init.sh <name> <artifacts...>`.
   Fill in `scope.md → question.asked`, `answer_format`, **`timezone`** from the challenge text verbatim.
2. `NOW`  `scripts/identify.sh work/<case>/evidence/` — read TYPE/MAGIC/TAIL/ENTROPY/ROUTE for every file.
   Verify provided MD5/SHA256 against the computed ones; record `verified: true|false` in scope.md.
3. `NEXT` `scripts/route.sh work/<case>/evidence/* "<the question text>"` → PRIMARY skill.
   Read `tool-index.md` (regenerate with `scripts/refresh-tool-index.sh` if older than the last install).
4. `ACT`  Open `skills/<PRIMARY>/SKILL.md` and start its workflow. Log each step in `timeline.md`.

## Routing table (mirrors `config/routing.json` — keep in sync, `scripts/test-routing.sh` checks)

| ID | You were handed… | Skill | Typical questions |
|----|------------------|-------|-------------------|
| R1 | E01/dd/raw/vmdk/vhd/ad1, partition dumps, NTFS/FAT/ext/ReFS/APFS, LUKS/BitLocker containers | `disk-image/` | deleted/renamed files, partition recovery, format time, which user, file system journaling |
| R2 | .mem/.vmem/.vmss/.lime/.dmp, hiberfil/pagefile, ELF core, CRIU `pages-*.img` | `memory-forensics/` | processes, injected code, passwords/keys in RAM, LUKS/FBE/wallet keys, network sockets |
| R3 | pcap/pcapng, Bluetooth HCI, USB HID captures, flow logs, ETL | `network-forensics/` | exfil, C2, file transfer reconstruction, keystrokes/mouse from HID, audio from RTP |
| R4 | EVTX, Sysmon, registry hives, Prefetch, LNK, JumpLists, Amcache, SRUM, ActivitiesCache, CSV exports of these | `windows-artifacts/` | execution time, persistence, lateral movement, log clearing, initial access, user activity |
| R5 | Docker/OCI tars, K8s/CRIU checkpoints, CloudTrail/GuardDuty/S3/VPC/Route53 logs, Linux server logs, Workspace/M365 audit | `linux-container-cloud/` | dropped payload in container, IAM compromise chain, exfil volume, pivot host, Linux persistence |
| R6 | Android/iOS dumps, app SQLite (+WAL), browser profiles, Chromium caches/LevelDB, messenger/AI-app DBs | `mobile-artifacts/` | accounts, Wi-Fi/location, photo provenance, what the user did in app X, AI prompts, deleted rows |
| R7 | PNG/JPG/GIF/WAV/MP3/MP4/AVI, dashcam/DVR dumps, 360 video, "won't play" media | `multimedia-stego/` | hidden data (LSB/append/chunks), repair container, tamper localisation, OCR/what3words, music ID |
| R8 | A timeline question, suspected timestomping/wiping/log clearing, timestamp conversion | `anti-forensics-timeline/` | SI vs FN, super-timeline, wiper traces, FILETIME/WebKit/Unix conversions, UTC↔KST |
| R9 | Wallet apps, mnemonics, addresses/tx hashes, smart-contract or DeFi incident, mining pool IOCs | `blockchain-forensics/` | derive wallet, trace funds, multisig/permission abuse, proxy upgrade drain, attacker cluster |
| R10 | "start a case", "write the report", "review evidence" | `case-ops/` | scaffolding, E/F/A chain review, report generation, knowledge write-back |
| R0 | Anything `file` calls "data", corrupted headers, archives, OOXML/HWP/PDF, PE-in-disguise, polyglots | `file-format-carving/` | fix header, carve embedded files, declared-vs-actual sizes, Rich header/PDB, macro/OLE, zip crypto |

Multiple routes usually apply. Start with PRIMARY; when it says "hand off to …" switch skills and
keep the same `work/<case>/`.

## Hard rules (RFC-2119)

- You **MUST NOT** modify an original artifact. Work on `work/<case>/evidence/` copies; mount read-only (`-o ro,noload` / `qemu-nbd --read-only` / `ewfmount`).
- You **MUST** recompute hashes yourself. A hash printed in a log (Sysmon, CloudTrail) is a *claim*, not a fact (KDFC 2026 #102 planted mismatching hashes).
- You **MUST** answer in the timezone and format the challenge states. KDFC alternates UTC+0 and UTC+9 between problems. Convert; never guess.
- You **MUST** grade every conclusion `direct | correlation | withheld` (see `ops/evidence-finding-path.md`). Saying "the artifacts cannot prove X" is a valid, often graded, answer.
- You **MUST NOT** order events across log channels by record ID. Normalise to UTC and sort by time.
- You **SHOULD** corroborate every key timestamp with a second artifact (Timeline + PCA; Prefetch + USN; MFT SI + FN).
- You **SHOULD** hunt outliers: dump *every* timestamp/size/cert-date/hash of a set, then look for the one that differs. This solved a large fraction of KDFC problems.
- You **MAY** use public lookups (hash reputation, blockchain explorers, what3words, music ID). You **MUST NOT** upload the artifact itself to a third-party service without asking.
- When a format is undocumented (ReFS `$Logfile`, vendor DVR), you **SHOULD** build a ground-truth sample in a VM, generate known events, and diff — do not guess struct layouts.

## What "done" looks like

Every question in `scope.md` has an `A-nnn` record with a `format_check`, every `A` points at an `F` with ≥1 `E`,
and `knowledge/` has a short entry with whatever was new. Then hand the answers back to the user.

## Read next
- `RULES.md` (repo-wide behaviour chain)
- `knowledge/_index.md` — 30 distilled KDFC writeups + curated web sources; grep it for your artifact type before you start
- `references/magic-bytes.md`, `references/timestamps.md`, `references/windows-event-ids.md`
