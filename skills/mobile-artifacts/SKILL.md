---
name: mobile-artifacts
description: |
  Mobile, app-database and browser forensics: Android logical dumps, iOS backups, app SQLite (with WAL),
  Chromium/browser history and caches, messenger and AI-app databases, and MediaStore. Enter when the
  artifact is an Android/iOS extraction, an app `.db` (+ `-wal`/`-shm`), a browser profile, a Chromium
  cache/LevelDB, or a question about accounts, Wi-Fi/location, photo provenance, chat/AI-app usage, or
  deleted app records.
  Trigger keywords: android, 안드로이드, ios, iphone, itunes backup, Manifest.db, plist, bplist, shared_prefs,
  /data/data, userdata.img, FBE, mediastore, external.db, sqlite, wal, shm, leveldb, session storage,
  chrome history, login data, cookies, hindsight, ccl_chromium, kakaotalk, telegram, instagram, samsung
  internet, sbrowser, honeyboard, clipitem, ALEAPP, conversations.db, claude cache, exodus, keepass, 모바일.
---

# Mobile / App / Browser Artifacts

Modern app forensics = SQLite + WAL + LevelDB/Session Storage + Chromium cache. GUI viewers hide deleted
rows and can't unfold nested caches — reach for targeted Python parsers. Always collect the sidecar files.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/` (hashes verified, timezone/format recorded).
2. `NOW`  Read `../../tool-index.md`: `sqlite3` ✅, `python3` ✅, `hindsight.py` ✅ (pyhindsight),
   ALEAPP/iLEAPP and `ccl_chromium_reader` via pip if needed.
3. `NEXT` Copy `.db` **with** `-wal` and `-shm` before opening; open read-only (`file:x.db?mode=ro`).
4. `NEXT` For deleted records, carve freelist/WAL; for browser caches, use Hindsight / CCL reader.
5. `ACT`  Convert every timestamp epoch to the required timezone; hash extracted media; log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| An encrypted Android FBE `userdata.img` + a `ramdump` | `skills/memory-forensics/` (fbekeyfind/aeskeyfind recover keys, then decrypt) |
| A crypto-wallet password in process memory | `skills/memory-forensics/`; on-chain tracing → `skills/blockchain-forensics/` |
| A whole-disk / filesystem image (not a logical dump) | `skills/disk-image/` |
| A carved media file with stego | `skills/multimedia-stego/` |

## Tools (install-name → what it's for)
- `sqlite3` ✅ — query app DBs; `.tables`, `.schema`, `PRAGMA freelist_count`.
- `python3` ✅ — carving (freelist/WAL), CCL Chromium reader, MHTML MIME parsing.
- `hindsight.py` ✅ — parse a whole Chromium profile (History/Cache/Cookies/Storage/Extensions).
- ALEAPP / iLEAPP (pip `aleapp`/`ileapp`) — Android/iOS artifact parsers → HTML/TSV report.
- `ccl_chromium_reader` (pip) — Session Storage, CacheStorage (Simple Cache), HTTP Cache LevelDB.
- `exiftool` ✅ — photo provenance (Make/Model/LensModel, DateTime vs DateTimeOriginal).
- `sqlite-dissect` (pip, DoD) — carve deleted rows / recover history from a DB.

## Workflow

### Phase 1 — Android logical dump triage
```bash
# accounts: app shared_prefs + account-named dirs
grep -rl '@gmail.com\|account' data/*/shared_prefs/*.xml 2>/dev/null
ls data/com.google.android.apps.docs/                # account-named subfolder
# Wi-Fi + geolocation:
cat data/misc/apexdata/com.android.wifi/WifiConfigStore.xml     # or wpa_supplicant.conf
cat data_backup/ABR/WIFICONFIG/Semconfigurations.json          # Samsung: per-network lat/long
# usage / recent apps (ALEAPP): system_ce/0/usagestats/, recent_tasks/ + snapshots/
# UID -> package: data/system/packages.list
```
Photo provenance:
```bash
exiftool -Make -Model -LensModel -DateTimeOriginal -ModifyDate -a DCIM/Camera/*.jpg
#  LensModel betrays a renamed foreign photo; DateTime(Modify) < DateTimeOriginal = edited (KDFC #151).
```

### Phase 2 — App SQLite (+ WAL) and deleted rows
```bash
cp app.db app.db-wal app.db-shm work/case/evidence/ 2>/dev/null   # ALWAYS copy sidecars
sqlite3 "file:work/case/evidence/app.db?mode=ro" ".tables"
# if the main db is tiny (e.g. 4KB) the data is in the WAL (KDFC #104 Claude cache):
sqlite3 app.db "PRAGMA wal_checkpoint;"   # DON'T on originals — checkpointing destroys WAL evidence
# recover deleted rows:
python3 -m sqlite_dissect app.db -e csv -d out/     # or read freelist pages directly
```
SQLite header byte 18/19 = 0x02 → WAL mode. WAL can hold multiple versions of an edited row (history).

### Phase 3 — Chromium browser & caches
```bash
hindsight.py -i "Default" -o case1 -f sqlite -t UTC          # whole profile
# History (WebKit us since 1601):
sqlite3 History "SELECT datetime(last_visit_time/1000000-11644473600,'unixepoch'), url FROM urls;"
# Login Data / Cookies / Web Data tables similarly. Cache often holds the actual payload.
# Session Storage / CacheStorage (LevelDB) & HTTP Cache -> CCL reader (KDFC #104 AI-service recon):
python3 -m ccl_chromium_reader.ccl_chromium_cache <cache_dir>
```
Simple Cache framing magic `30 5C 72 A7 1B 6D FB FC`; key length at offset 12 (`<I`), body at `24+keylen`.

### Phase 4 — iOS backup
```bash
sqlite3 Manifest.db "SELECT fileID,domain,relativePath FROM Files WHERE relativePath LIKE '%sms.db%';"
# files are named sha1(domain-relativePath); stable hashes: sms.db=3d0d7e5f..., Photos.sqlite=12b144c0...
# Apple epoch: datetime(timestamp + 978307200,'unixepoch'). Encrypted backup: iOSbackup (python) + keybag.
```

### Phase 5 — Messenger / AI-app DBs
- ChatGPT Android: `conversations.db` — `DBConversation` JSON via `json_extract`, reassemble `DBMessageChunk` by `chunkIndex` (`group_concat`).
- Claude: conversation in WAL (`cachedConversations`/`cachedMessages`), main db ~4KB — copy WAL+SHM.
- Samsung Internet (`com.sec.android.app.sbrowser`): History/downloads + READINGLIST + offline MHTML.
- Samsung Keyboard (Honeyboard) `ClipItem.db` `clip_table` — clipboard with `caller_app_uid`.
```bash
# extract a webp part from a saved MHTML:
python3 - <<'PY'
from email import policy; from email.parser import BytesParser
m=BytesParser(policy=policy.default).parse(open('page.mhtml','rb'))
for part in m.walk():
    if part.get_content_type()=='image/webp':
        open('out.webp','wb').write(part.get_payload(decode=True))
PY
```

## Flag-hiding checklist
- Deleted rows in SQLite freelist / prior versions in `-wal` — carve, don't just SELECT.
- The real data in the WAL when the main `.db` is tiny — copy `-wal`/`-shm`.
- Account names in `shared_prefs/*.xml` and account-named app dirs, not just `accounts.db`.
- Wi-Fi geolocation in Samsung `Semconfigurations.json`; SSID in `wpa_supplicant.conf`.
- Photo origin via EXIF `LensModel`; edit via `DateTime` < `DateTimeOriginal`.
- Browser cache holding the actual downloaded payload / the flag page (Hindsight).
- AI-app output tied through client-state (Session Storage) → server job (HTTP Cache) → device file (MediaStore + hash).
- Photo Picker synthetic files under `.transforms/synthetic/picker/` are all-zero — not evidence.

## Pitfalls
- Opening a DB with a non-forensic tool checkpoints and destroys the WAL — work on read-only copies.
- Epoch mixups: Chrome WebKit us/1601, Apple s/2001, Android ms/1970 — convert to the asked timezone.
- Distinguish server job status (`x-task-status=COMPLETED`) from analyst-assigned client state.
- A Samsung-format filename (`YYYYMMDD_HHMMSS.jpg`) on an iPhone photo is a deliberate decoy.

## Worked precedents
- **KDFC2023 #151 Android Live** — accounts in shared_prefs, Wi-Fi geo in Semconfigurations.json, EXIF LensModel catches a renamed iPhone photo.
- **KDFC2026 #104 Tells a Story** — ChatGPT/Firefly/Claude reconstruction from SQLite+WAL+Chromium caches (CCL reader), Samsung Internet MHTML → WebP hash match.
- **KDFC2023 #251 Find the suspect** — Dropbox `sync_history.db` deleted-row carving, `config.dbx` key.
- **KDFC2023 #401 Find an illegally filmed image** — Android FBE; recover keys in `memory-forensics`, decrypt here.

## References
- `../../references/timestamps.md`
- Android 14 paths (Epifani): https://blog.digital-forensics.it/2024/01/a-first-look-at-android-14-forensics.html
- iOS backup structure (Reincubate): https://reincubate.com/support/how-to/iphone-backup-files-structure/
- SQLite WAL: https://www.sqlite.org/wal.html · Hindsight: https://github.com/obsidianforensics/hindsight
