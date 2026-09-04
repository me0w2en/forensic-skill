---
name: anti-forensics-timeline
description: |
  Timeline reconstruction and anti-forensics detection: build a super timeline, detect timestomping,
  read wiper/shredder and log-clearing traces, and convert every timestamp epoch to the required timezone.
  Enter when the question is about "when did things happen" across an image, about tampered/impossible
  timestamps, about a wiper or cleared logs, or when you must convert a raw timestamp value. This is a
  cross-cutting skill you use alongside disk-image and windows-artifacts.
  Trigger keywords: timeline, 타임라인, super timeline, plaso, log2timeline, psort, mactime, timesketch,
  timestomp, 타임스톰핑, SI vs FN, $STANDARD_INFORMATION, $FILE_NAME, MACB, wiper, shredder, sdelete,
  ccleaner, bleachbit, log clear, wevtutil, 1102, 104, USN journal, volume shadow, VSS, FILETIME, WebKit,
  chrome epoch, cocoa time, unix epoch, DCode, UTC, KST, timezone.
---

# Anti-Forensics & Timeline

Two jobs: (1) build a defensible timeline in the required timezone, and (2) catch tampering — timestomping,
wiping, log clearing. Losing points to a timezone error is the single most common CTF mistake here.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/`; re-read `scope.md → question.timezone`. Convert EVERY
   timestamp to that zone and write the offset beside it.
2. `NOW`  Read `../../tool-index.md` (plaso `log2timeline`/`psort` ✅ via uv, `mactime` ✅ via TSK) and
   `../../references/timestamps.md` (epochs + NTFS MACB rules).
3. `NEXT` Decide: whole-image timeline (plaso) vs targeted tamper check (SI/FN, USN, $LogFile).
4. `NEXT` For tamper claims, corroborate with a second artifact (Prefetch/Amcache/LNK/USN).
5. `ACT`  Emit one timeline table (UTC + local), grade each row `direct|correlation|withheld`, log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| Parsing individual Windows artifacts (EVTX/registry/Prefetch) | `skills/windows-artifacts/` (come here to fuse them into a timeline) |
| Mounting/enumerating the image | `skills/disk-image/` |
| App-DB / browser timestamps | `skills/mobile-artifacts/` |

## Tools (install-name → what it's for)
- `log2timeline` ✅ (plaso) — parse an image/artifacts into a `.plaso` store.
- `psort` ✅ (plaso) — filter/sort/output a timeline; `--output-time-zone` is critical.
- `psteal` ✅ (plaso) — one-shot source → CSV.
- `pinfo` ✅ (plaso) — what parsers ran / what's in the store.
- `mactime` ✅ (TSK) — bodyfile → sorted MAC timeline.
- `chainsaw` ✅ — `analyse gaps` finds cleared/missing EVTX ranges.
- DCode (GUI, Windows) — decode FILETIME/OLE/WebKit/Unix/100ns-tick values interactively.
- Timesketch (server) — collaborative timeline review of large `.plaso`.

## Workflow

### Phase 1 — Super timeline (whole image)
```bash
log2timeline.py --storage-file tl.plaso evidence/disk.E01     # output FIRST, source SECOND
#   scope it: --partitions all --vss-stores all --parsers 'win7,!filestat' -z UTC --hashers md5,sha256
pinfo.py --sections sources tl.plaso                          # verify what parsed
psort.py --output-time-zone Asia/Seoul -o l2tcsv -w super.csv tl.plaso \
  "date > datetime('2023-04-25T00:00:00') AND date < datetime('2023-04-27T00:00:00')"
# quick path:
psteal.py --source evidence/disk.raw -o dynamic -w timeline.csv
```
Add the filesystem layer from an MFT bodyfile and disable `filestat` to avoid duplicates:
```bash
# MFTECmd (Windows/.NET) --body -> mft.body, then:
log2timeline.py --parsers 'mactime' --storage-file tl.plaso mft.body
```

### Phase 2 — Timestomping detection
```bash
# SI (user-writable) vs FN (kernel-only). SI Born earlier than FN Born is impossible normally.
istat -o <start> evidence/disk.E01 <mft_entry>       # shows $SI and $FN times
# MFTECmd flags SI<FN automatically; also compare the MFT entry NUMBER ordering with neighbours
#   (a "2015" file whose entry number sits between 2023 files = stomped).
```
Signals: zeroed sub-seconds (`.0000000`); SI vs FN contradiction; MFT-entry-number out of sequence; USN
`BASIC_INFO_CHANGE`; `$LogFile` retains the ORIGINAL name/time before a rename or stomp; a file whose
times exactly match a system binary (copied). Corroborate with Prefetch/Amcache/ShimCache/LNK.

### Phase 3 — NTFS MACB rules (apply, don't guess)
See `../../references/timestamps.md`. Key rules: create sets all SI+FN; rename updates SI C and FN;
copy gives fresh SI B/M/A/C and fresh FN; move-same-volume touches SI A/C only, FN unchanged;
move-cross-volume behaves like copy; access-time updates disabled by default since Vista.

### Phase 4 — Wiper / shredder traces
The tool leaves execution artifacts even when the wiped files are gone:
- Prefetch / Amcache / `PcaAppLaunchDic.txt` / ActivitiesCache.db show the wiper ran (KDFC #102: Moo0 FileShredder).
- USN `$J`: SDelete-style sequential `RENAME_OLD_NAME`/`RENAME_NEW_NAME` to `AAA.AAA`,`BBB.BBB` then `FILE_DELETE`.
- Recover the wiped file's original name/time from `$UsnJrnl`/`$LogFile` even after deletion.
```bash
# extract USN, look for the wipe pattern:
icat -o <s> evidence/disk.E01 <usnjrnl_inode> > UsnJrnl_J    # then parse with your USN tool
```

### Phase 5 — Log clearing
```bash
# Security 1102 / other-logs 104 mark a clear. Report a clear as PROVEN only if the event exists.
chainsaw analyse gaps ./evtx --json -o gaps.json    # detect missing/cleared ranges
# KDFC #102 trap: `wevtutil cl` seen in Sysmon but NO 1102 -> report "attempted", not "succeeded".
```

### Phase 6 — Timestamp conversion (the point-loser)
```bash
# FILETIME / 100ns tick (e.g. <tick-value>):
python3 -c "import datetime as d;print(d.datetime(1601,1,1)+d.timedelta(microseconds=<tick-value>/10))"
# Chrome/WebKit us:   /1e6 - 11644473600 -> unix.  Apple/Cocoa s: +978307200 -> unix.  Android ms: /1000.
TZ=Asia/Seoul date -r $((1692737999)) 2>/dev/null || date -d @1692737999 -u   # unix -> local/UTC
```
Then restate in the challenge's timezone. KDFC alternates UTC+0 and UTC+9 between problems — check each.

## Flag-hiding checklist
- The answer is often the last events *before* a 1102/104, or the `analyse gaps` window.
- An impossible/out-of-sequence timestamp is the pointer to the tampered file.
- Wiped file names survive in `$UsnJrnl`/`$LogFile`; the wiper's own execution survives in Prefetch/PCA.
- A file backdated to before OS install, or exactly matching a system binary, is stomped.
- Cross-artifact time corroboration (Timeline+PCA, Prefetch+USN) resolves "which run was the real one".

## Pitfalls
- Wrong timezone — convert explicitly, write the offset, re-check per problem.
- Ordering across log channels by Record ID — always sort by UTC (KDFC #101/#102).
- Claiming logs were cleared without the 1102/104 event — say "attempted".
- SI/FN check alone is bypassable (stomp SI then rename copies SI→FN); use USN/$LogFile too.
- plaso: put the output file FIRST; scope parsers/VSS or the run is enormous.

## Worked precedents
- **KDFC2023 #102 File Wiper** — Moo0 FileShredder install/run times cross-checked between ActivitiesCache.db and PcaAppLaunchDic.txt; installer auto-launch vs real run.
- **KDFC2026 #102 Masquerade** — SI vs FN timestomp on `wmiapsvr.exe`, `wevtutil cl` with no 1102 → "attempted".
- **KDFC2023 #302 Do not blink** — `<tick-value>` 100ns tick decoded to KST via DCode.

## References
- `../../references/timestamps.md`, `../../references/windows-event-ids.md`
- SANS time-stamp manipulation / Windows Time Rules: https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation
- inversecos timestomping: https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html
- Plaso docs: https://plaso.readthedocs.io/en/latest/
