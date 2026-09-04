# Timestamp & epoch reference

**The single most common way to lose CTF points is the wrong timezone.** KDFC alternates
UTC+0 and UTC+9 (KST) *between problems in the same set*. Read `scope.md → question.timezone`
every time and convert explicitly. Write the offset next to every timestamp in the report.

## Epochs you will meet
| Source | Epoch | Unit | Convert to UTC |
|--------|-------|------|----------------|
| Unix | 1970-01-01 | seconds | as-is |
| Unix (ms) — Android, Java | 1970-01-01 | milliseconds | `/1000` |
| Windows FILETIME | 1601-01-01 | 100 ns ticks | `ticks/1e7 - 11644473600` = Unix s |
| Windows 100ns "tick" value (e.g. a Windows 100ns tick value) | 1601-01-01 | 100 ns | same as FILETIME; DCode decodes it |
| WebKit / Chrome (History, cookies) | 1601-01-01 | microseconds | `us/1e6 - 11644473600` = Unix s |
| Apple / Cocoa (iOS, macOS, Safari) | 2001-01-01 | seconds (or ns) | `+ 978307200` = Unix s |
| NTFS $SI/$FN | 1601-01-01 | FILETIME | as FILETIME |
| FAT | 1980-01-01 | DOS date/time, local tz | tz-dependent |

## SQLite one-liners
```sql
-- Chrome/WebKit microseconds
SELECT datetime(visit_time/1000000 - 11644473600, 'unixepoch') FROM visits;
-- Apple seconds
SELECT datetime(timestamp + 978307200, 'unixepoch') FROM ...;
-- Unix ms (Android)
SELECT datetime(ts/1000, 'unixepoch') FROM ...;
```

## Python
```python
import datetime as dt
def filetime(t):  return dt.datetime(1601,1,1)+dt.timedelta(microseconds=t//10)   # FILETIME/WebKit-us -> use t//10 for FILETIME, t for webkit-us? see below
webkit = lambda us: dt.datetime(1601,1,1)+dt.timedelta(microseconds=us)
ft     = lambda ticks: dt.datetime(1601,1,1)+dt.timedelta(microseconds=ticks/10)
apple  = lambda s: dt.datetime(2001,1,1)+dt.timedelta(seconds=s)
# then .replace(tzinfo=timezone.utc).astimezone(ZoneInfo("Asia/Seoul")) for KST
```

## CLI
```bash
date -u -r 1692737999                      # unix -> UTC (macOS)
date -d @1692737999 -u                      # unix -> UTC (Linux)
TZ=Asia/Seoul date -r 1692737999            # -> KST
# DCode (GUI, Windows) decodes FILETIME/OLE/WebKit/Unix/tick values interactively
```

## NTFS MACB time rules (SANS)
`$SI` = $STANDARD_INFORMATION (user/API-writable — timestompable). `$FN` = $FILE_NAME (kernel-only).
| Operation | $SI | $FN |
|-----------|-----|-----|
| Create | M A C B all set | M A C B all set |
| Modify | M, C (A if enabled) | unchanged |
| Copy (new file) | fresh B/M/A/C | fresh, = copy time |
| Move same volume | A(*), C | unchanged |
| Move across volumes | like copy | like copy |
| Rename | C | updated |
| Access | A only, disabled by default since Vista | — |

**Timestomp tells:** `$SI` Born earlier than `$FN` Born (impossible normally); zeroed sub-seconds
(`.0000000`); MFT entry number out of chronological sequence with neighbours; USN `BASIC_INFO_CHANGE`;
`$LogFile`/`$UsnJrnl` times contradicting `$SI` by months. Corroborate with Prefetch/Amcache/LNK.
