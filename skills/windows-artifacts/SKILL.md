---
name: windows-artifacts
description: |
  Windows host forensics: EVTX/Sysmon event logs, registry hives (SAM/SYSTEM/SOFTWARE/SECURITY/NTUSER.DAT/UsrClass.dat/Amcache.hve),
  program-execution artifacts (Prefetch, Amcache, ShimCache/AppCompatCache, BAM/DAM, UserAssist, SRUM, ActivitiesCache.db Windows
  Timeline, Win11 PcaAppLaunchDic.txt), persistence (Run/Services/Winlogon/TaskCache), devices (USBSTOR/MountedDevices), user activity
  (ShellBags/RecentDocs/OpenSavePidlMRU/TypedPaths/WordWheelQuery), $MFT (SI vs FN), $RECYCLE.BIN. Use for execution time, persistence,
  lateral movement, initial access, log clearing, RDP, and "when/who/what ran" questions on a Windows box.
  Trigger keywords: evtx, sysmon, event id, 4624, 4625, 4688, 4104, 1102, registry, hive, NTUSER.DAT, Amcache, ShimCache, AppCompatCache,
  BAM, UserAssist, Prefetch, SRUM, ActivitiesCache, PcaAppLaunchDic, ShellBags, USBSTOR, TaskCache, $MFT, $RECYCLE.BIN, RDP, chainsaw,
  hayabusa, regipy, RegRipper, 윈도우 아티팩트, 레지스트리, 이벤트로그, 프리패치, 실행흔적.
---

# Windows Artifacts

## ACTION REQUIRED
1. `NOW` Confirm you arrived via `forensics-router` and `work/<case>/scope.md` exists with **verified hashes** and the answer **timezone** recorded verbatim. If not → `case-ops` / re-run `scripts/case-init.sh`.
2. `NOW` Read `../../tool-index.md`. On this macOS/arm64 host use `evtx_dump chainsaw hayabusa regipy-dump regipy-plugins-run target-query mactime log2timeline`. Eric Zimmerman tools (MFTECmd/PECmd/LECmd/SrumECmd/EvtxECmd) are Windows/.NET — run on a Windows box or via `dotnet`; use the cross-platform path below on this Mac.
3. `NEXT` Extract the hives/logs/artifacts you need from the image (`disk-image` skill: `icat`/`tsk_recover`/`fls`), keep read-only copies under `work/<case>/evidence/`.
4. `NEXT` Build a **UTC** super-picture: run `hayabusa csv-timeline --UTC` + `chainsaw hunt`, dump the registry with regipy, correlate by **UtcTime**, not Record ID.
5. `ACT` Answer each `scope.md` question, grade `direct|correlation|withheld`, convert every timestamp to the challenge timezone, log every command + finding to `work/<case>/timeline.md`.

## When to use / hand off
| If the artifact is really… | go to |
|----------------------------|-------|
| A raw/E01/VMDK image you must mount & carve first | `disk-image` |
| SI-vs-FN timestomping, super-timeline, wiper traces, epoch conversion | `anti-forensics-timeline` |
| Keys/passwords/processes that live only in RAM (hiberfil/pagefile) | `memory-forensics` |
| Browser history/cache, app SQLite (+WAL) | `mobile-artifacts` (Chromium/hindsight) |
| Docker/K8s/CloudTrail/Linux server logs | `linux-container-cloud` |
| An extracted EXE/DLL to reverse or a weird file | `file-format-carving` |

## Tools
- `evtx_dump` (✅) — dump a single `.evtx` to XML/JSON for grep/jq; the universal fallback parser.
- `chainsaw` (✅) — `hunt` (Sigma), `search`, `analyse shimcache|srum|gaps`, `dump`; parses EVTX, MFT, registry hives, Shimcache/Amcache, SRUM/ESE.
- `hayabusa` (✅) — `csv-timeline`/`json-timeline` (Sigma-scored), `logon-summary`, `eid-metrics`, `search`, `pivot-keywords-list`, `extract-base64`.
- `regipy-dump` / `regipy-plugins-run` (✅) — cross-platform registry parsing; run plugins (amcache, shimcache, userassist, etc.).
- `target-query` / `target-shell` (✅, dissect) — parse a whole image/hive set at once (`-f mft`, `-f prefetch`, `-f amcache`, `-f runkeys`, `-f usb`).
- `mactime` (✅, Sleuth Kit) — render an MFT/fls bodyfile into a MACB timeline.
- `rip.pl` RegRipper (❌ not installed) → `git clone https://github.com/keydet89/RegRipper4.0`; **replay `.LOG1/.LOG2` with `rla.exe` first** or recent keys are missing. On Mac prefer regipy (it handles dirty hives).
- `MFTECmd` / `PECmd` / `SrumECmd` / `AppCompatCacheParser` / `AmcacheParser` / `EvtxECmd` (❌, EZ .NET) — best-in-class; run on Windows/`dotnet`. Mac fallbacks: `analyzeMFT` / `dissect` for MFT, `libpyscca` / `dissect` for Prefetch, `chainsaw analyse srum` for SRUM.

## Key Event IDs (compact — full field/pivot detail in `../../references/windows-event-ids.md`)
| Channel | ID | Meaning / pivot |
|---|---|---|
| Security | 4624 | Logon **success** — check `LogonType`: 2 console, 3 network, 7 unlock, 8 net-cleartext, 9 RunAs, **10 RDP**, 11 cached |
| Security | 4625 | Logon **failed** — bursts + WorkstationName reveal brute force / attacker host |
| Security | 4648 | Explicit creds (RunAs / pass-the-cred) — lateral movement |
| Security | 4688 | Process created (if audited) — CmdLine + parent |
| Security | 4698 / 4702 | Scheduled task created / updated (attackers reuse legit names) |
| Security | 4697 | Service installed (Security channel twin of 7045) |
| Security | 4720 / 4732 / 4728 | Account created / added to local / global group |
| Security | 1102 | **Security** audit log cleared — the definitive "logs wiped" event |
| System | 7045 | New service installed |
| System | 104 | A **non-Security** log was cleared |
| PowerShell/Operational | 4104 / 4103 | Script-block text (deobfuscated, even for IEX) / module-pipeline |
| TerminalServices-LocalSessionManager | 21/22/23/24/25 | RDP logon / shell-start / logoff / disconnect / reconnect |
| WMI-Activity/Operational | 5858 / 5861 | WMI operation error (WQL fired) / permanent event consumer registered (persistence) |

## Workflow

### Phase 0 — inventory & sanity
```bash
ls -R work/<case>/evidence            # EVTX? hives? CSV exports? whole image?
for f in *.evtx; do echo "$f"; evtx_dump -o jsonl "$f" | wc -l; done   # record counts, spot cleared logs
capinfos 2>/dev/null                  # (n/a) — for evtx use eid-metrics below
hayabusa eid-metrics -d ./evtx        # which EIDs exist, per channel
```

### Phase 1 — EVTX triage & timeline (cross-platform)
```bash
# One UTC-normalised Sigma-scored timeline across ALL channels (order by time, NOT record id):
hayabusa csv-timeline -d ./evtx -o timeline.csv --UTC -m low        # -f single file; -p super-verbose for full fields
hayabusa logon-summary -d ./evtx                                    # 4624/4625 matrix: source, type, user, success/fail
hayabusa search  -d ./evtx -k "powershell"                          # or -r "regex"
hayabusa extract-base64 -d ./evtx                                   # pulls & decodes -enc blobs

# Chainsaw: Sigma hunt + targeted search + cleared-log gap detection
chainsaw hunt ./evtx -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output hunt/
chainsaw search -t 'Event.System.EventID: =4104' ./evtx --json
chainsaw search mimikatz -i ./evtx
chainsaw analyse gaps ./evtx --json -o gaps.json                    # missing/cleared time ranges

# Raw dump for grep/jq when a rule misses:
evtx_dump -o jsonl Security.evtx | jq -c 'select(.Event.System.EventID==4624) | {t:.Event.System.TimeCreated["#attributes"].SystemTime, type:.Event.EventData.LogonType, ip:.Event.EventData.IpAddress, user:.Event.EventData.TargetUserName, ws:.Event.EventData.WorkstationName}'
```

### Phase 2 — registry (execution, persistence, devices, user activity)
```bash
# Cross-platform (this Mac): regipy handles dirty hives without manual .LOG replay
regipy-plugins-run NTUSER.DAT -o ntuser.json          # runs all applicable plugins
regipy-plugins-run SYSTEM   -o system.json
regipy-dump SYSTEM -p 'HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'   # BAM last-exec per user/SID
# RegRipper (if cloned): replay logs first, then per-plugin
# rla.exe -f NTUSER.DAT --out clean/ ; rip.pl -r clean/NTUSER.DAT -p userassist
# dissect one-shot over the whole image:
target-query image.vmdk -f runkeys,services,userassist,shimcache,amcache,usb,shellbags
```
Key paths (values, not just presence):
- **Execution:** `NTUSER\...\Explorer\UserAssist\{GUID}\Count` (**ROT13** names + run count + last run); `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (BAM/DAM last exec); `SYSTEM\...\Control\Session Manager\AppCompatCache` (**ShimCache** — presence+path, order ≈ recency); `Amcache.hve\Root\InventoryApplicationFile` (SHA-1, first-seen); `NTUSER\...\Explorer\RunMRU`.
- **Persistence:** `Run`/`RunOnce` under NTUSER and SOFTWARE; `SYSTEM\CurrentControlSet\Services`; `SOFTWARE\...\Winlogon` (Shell/Userinit); `SOFTWARE\...\Schedule\TaskCache\Tree|Tasks`.
- **Devices:** `SYSTEM\...\Enum\USBSTOR` (vendor/product/serial; first/last connect in `Properties\{83da6326-...}\0064/0066/0067`); `SYSTEM\MountedDevices`; `NTUSER\...\MountPoints2`.
- **Network:** `SOFTWARE\...\NetworkList\Profiles` (+`Signatures\Unmanaged` gateway MAC); RDP client history `NTUSER\Software\Microsoft\Terminal Server Client\Servers`.
- **User activity:** ShellBags (`NTUSER\...\Shell` + `UsrClass\...\Shell`), `RecentDocs`, `ComDlg32\OpenSavePidlMRU`+`LastVisitedPidlMRU`, `TypedPaths`, `WordWheelQuery` (Explorer search terms).
- **System context:** `SYSTEM\Select\Current` (live ControlSet), `...\Control\TimeZoneInformation` (**read this — it sets local↔UTC offset**), `SOFTWARE\...\CurrentVersion` InstallDate/ProductName, `ProfileList` (SID→user).

### Phase 3 — program-execution timeline artifacts
```bash
# Prefetch (last-run x8, run count, loaded files, volume serial): EZ PECmd on Windows:
#   PECmd.exe -d C:\Windows\Prefetch --csv out --mp --vss
# Mac fallback: dissect or libpyscca
target-query image.vmdk -f prefetch
python3 -c "import pyscca,sys; p=pyscca.open(sys.argv[1]); print(p.executable_filename, p.run_count, [p.get_last_run_time(i) for i in range(8)])" *.pf

# Amcache / ShimCache pairing (execution proof + first-seen):
chainsaw analyse shimcache ./SYSTEM --regexfile analysis/shimcache_patterns.txt --amcache ./Amcache.hve --tspair --output shimcache.csv

# SRUM (per-app network bytes, run duration) — cross-platform via chainsaw:
chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat --output srum.json     # EZ: SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv .

# Windows Timeline (ActivitiesCache.db) — SQLite, epoch (UTC):
sqlite3 ActivitiesCache.db "SELECT datetime(LastModifiedTime,'unixepoch') t, AppId, Payload FROM Activity ORDER BY t;"   # path: \Users\<u>\AppData\Local\ConnectedDevicesPlatform\<id>\ActivitiesCache.db

# Windows 11 PCA (plaintext, millisecond, LAST launch only):
cat 'C:\Windows\appcompat\pca\PcaAppLaunchDic.txt'    # <full exe path>|<last launch time>
cat 'C:\Windows\appcompat\pca\PcaGeneralDb0.txt'
```

### Phase 4 — $MFT & $RECYCLE.BIN
```bash
# $MFT SI vs FN (timestomp hunt): EZ on Windows -> MFTECmd.exe -f '$MFT' --csv .  (SI=0x10, FN=0x30)
# Mac fallback:
analyzeMFT.py -f '$MFT' -o mft.csv       # (pip install analyzeMFT)  OR
target-query image.vmdk -f mft
mactime -b mft.body -d 2020-05-21 > mft_day.csv         # render bodyfile as MACB timeline
# $RECYCLE.BIN: each deleting user -> \$RECYCLE.BIN\<SID>\ with $I (metadata: orig path,size,FILETIME) + $R (content)
# SID S-1-5-21-<A>-<B>-<C>-<RID>: A-B-C identify the MACHINE, RID the account -> differing triplets = volume touched >1 machine.
python3 -c "d=open('\$I...' ,'rb').read(); import struct; print(struct.unpack('<Q',d[16:24])[0])"   # deletion FILETIME
```

## Flag-hiding checklist (where KDFC hides the answer)
- **The one PowerShell line that differs:** among many `powershell.exe` EID-1/4688 rows, the malicious one has `-nop -w hidden -ep bypass -enc <long b64>`. Decode `-enc` = Base64 → UTF-16LE; expect **nested Base64→GZip→IEX ×2** and a secret reassembled from registry values disguised as OneDrive/Update keys (KDFC2026 #101).
- **Correlate across channels by ProcessGuid / PID, order by UtcTime.** Sysmon follow-ons (5/12/13/22) tie by ProcessGuid; PowerShell 4103/4104 tie by System/Execution PID. Record IDs are per-channel — never sort by them.
- **Execution proved by the artifact, not the log claim:** Prefetch RunCount + last-run, Amcache first-seen, ShimCache path, BAM/UserAssist per-user last-run, SRUM bytes-sent, ActivitiesCache + PcaAppLaunchDic.
- **RDP initial access:** 4624/4625 **LogonType 10** with a WorkstationName like `ATTACKER`; corroborate TerminalServices 21→22 SessionID and the source IP.
- **Persistence masquerade:** legit-sounding service/Run names (`SpeechRuntime`, `WindowsFontCache`, `FontCacheSvc`, `svchost.exe` in `\Windows\Speech`); WMI consumer (EID 5861); scheduled task in TaskCache with a plausible name.
- **Windows-11-only PCA:** `PcaAppLaunchDic.txt` gives ms-precision *last* launch; treat a run within ~1 min of an installer as the installer's auto-launch, and report the later independent launch as the real run time (KDFC2023 #102 Moo0 FileShredder).
- **$RECYCLE.BIN SID triplets** answer "connected to multiple machines"; `$I` FILETIME answers "when deleted".
- **Outlier hunt:** dump *every* timestamp/hash/cert-date/run-count of a set and find the one that differs — this cracks a large fraction of KDFC host problems.

## Pitfalls
- **PLANTED HASHES (KDFC2026 #102):** a Sysmon EID-1 `Hashes=` field is a *claim*. Always recompute the PE hash yourself (`md5 file` / `shasum -a 256 file`) and compare; if they differ, the log IOC is **unverified** — do not substitute the sample hash for it. ProcessGuid lineage in EID-3 can also be forged, so don't assert lineage when the creation-event GUID/PID doesn't match.
- **1102 absent ≠ logs were not cleared, and ≠ they were.** If you see `wevtutil cl <log>` in Sysmon/4688 but **no EID 1102 (Security)/104 (others)** and no success return, report the clear as **"attempted, success not proven"**, not "succeeded".
- **Timezone:** KDFC alternates UTC+0 and UTC+9 between problems. Read `Control\TimeZoneInformation`; run tools with `--UTC` / `-z UTC` then convert to the *asked* zone. Task XML may be in PDT (UTC-7). ActivitiesCache/SRUM/Prefetch store UTC FILETIME/epoch.
- **RegRipper `rip.pl` does NOT replay transaction logs** — run `rla.exe` (or use regipy, which handles dirty hives) or recently-written keys are missing.
- **UserAssist names are ROT13.** ShimCache order is roughly recency but is **not** proof of execution (Amcache/Prefetch are stronger).
- **EZ tools won't run on this Mac** (they're .NET/Windows). Say so and give the chainsaw/hayabusa/regipy/dissect path; only claim EZ output if run on Windows/`dotnet`.
- **Deleted-file size match ≠ byte identity.** Same size as a sample is correlation, not proof.

## Worked precedents
- **KDFC2026 #101 Ghost in the Shell** — Sysmon + PowerShell/Operational; one of 10 PS lines used `-enc` (3,712 chars); nested Base64→GZip→IEX ×2 with the flag XORed from three registry values disguised as OneDrive keys; order by UtcTime not RID. See.
- **KDFC2026 #102 Masquerade** — CSV-exported host artifacts (MFT/Security/Sysmon/Prefetch/Services/TerminalServices/USBStor); RDP type-10 from `ATTACKER`; SI/FN timestomp; masqueraded services; **planted Sysmon hashes** and 1102-absent "clear attempted". See.
- **KDFC2026 #202** — EVTX/USN/SRUM/TaskCache/Prefetch: RAT drop (USN FILE_CREATE) → run (pythonw Prefetch) → TaskCache persistence; SRUM bytes-sent; C2 honestly reported unproven at flow level. See.
- **KDFC2023 #102 File Wiper** — ActivitiesCache.db + Win11 PcaAppLaunchDic.txt cross-referenced for Moo0 FileShredder install vs real wiping run; installer auto-launch vs user run. See.
- **KDFC2023 #252/#253/#306** — standard execution/timeline stack (Prefetch, $MFT, $UsnJrnl:$J, ActivitiesCache, WMI-Activity 5858, registry MAC/MachineGuid). See.

## References
- `../../references/windows-event-ids.md` — full Event ID + logon-type + field/pivot table.
- `../../references/timestamps.md` — FILETIME/WebKit/epoch conversions and UTC↔KST.
- `../../references/magic-bytes.md` — file signatures for carved artifacts.
- 13Cubed Windows Event Log Cheat Sheet — https://cdn.13cubed.com/downloads/windows_event_log_cheat_sheet.pdf
- Chainsaw — https://github.com/WithSecureLabs/chainsaw · Hayabusa — https://yamato-security.github.io/hayabusa/
- Cyber Triage Registry cheat sheet — https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/ · ShimCache/Amcache — https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/
- SANS Windows Forensic Analysis poster — https://www.sans.org/posters/windows-forensic-analysis/ · Eric Zimmerman tools — https://ericzimmerman.github.io/
