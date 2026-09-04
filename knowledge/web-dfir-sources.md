# DFIR CTF Writeups and Methodology Sources: Research Report

Compiled 2026-09-04 for building a forensics-specialised agent playbook. Every source below was fetched and its concrete, actionable content extracted; where a page could not be fetched (HTTP 403/402) and only a search snippet is available, that is flagged explicitly. Vague or marketing-only pages were dropped.

Trust legend used in "Why trustworthy":
- **Primary/vendor docs** — tool authors or spec owners (Volatility Foundation, Plaso, SQLite.org, Eric Zimmerman, WithSecure, Yamato Security).
- **Practitioner blog** — long-running DFIR practitioners (andreafortuna, David Cowen/HECF, inversecos, 0xdf, forensicskween, Cyber Triage/Brian Carrier, 13Cubed, SANS).
- **Verified CTF writeup** — writeup for a public challenge where the technique reproduces (HTB Sherlocks, CyberDefenders, picoCTF, Huntress, MetaCTF).
- **Curated community reference** — maintained cheat sheets with wide adoption (Trail of Bits CTF Field Guide, Aperi'Solve wiki, stego-toolkit, ctf-wiki).

---

## 1. Disk image analysis (E01/dd/VMDK, NTFS artifacts)

### 1.1 Going beneath NTFS: USN Journal, dfir_ntfs, and artefact-driven analysis
- URL: https://andreafortuna.org/2026/07/06/ntfs-forensics-deep-dive/
- Why trustworthy: Practitioner blog (Andrea Fortuna, long-running DFIR author); cites Maxim Suhanov's dfir_ntfs and Eric Zimmerman's MFTECmd, both primary tools.
- Techniques:
  - Parse the three NTFS journals with MFTECmd: `MFTECmd.exe -f "E:\Evidence\$MFT" --csv C:\out --csvf mft.csv` and `MFTECmd.exe -f "E:\Evidence\$Extend\$J" --csv C:\out --csvf usn.csv`; load both CSVs in Timeline Explorer and pivot on MFT entry number.
  - Artifact locations: `$MFT` (1024-byte records), `$Extend\$UsnJrnl:$J` (change log) and `:$MAX` (journal metadata), `$LogFile` (redo/undo transaction log), `$I30` directory indexes. Live check: `fsutil usn queryjournal C:`.
  - USN reason codes to filter on: `FILE_CREATE`, `FILE_DELETE`, `RENAME_OLD_NAME`/`RENAME_NEW_NAME`, `BASIC_INFO_CHANGE` (timestamp/attribute change = timestomping corroboration), `DATA_OVERWRITE/EXTEND`.
  - Timestomping tell: `$STANDARD_INFORMATION` Born earlier than `$FILE_NAME` Born is "an impossibility" under normal operation. Corroborate with `BASIC_INFO_CHANGE` records and `$LogFile` LSN write times.
  - Wiper/SDelete signature: sequential `RENAME_OLD_NAME`/`RENAME_NEW_NAME` pairs with names like `AAA.AAA`, `BBB.BBB` immediately followed by `FILE_DELETE`.
  - Resident files (< ~700 bytes) survive inside the MFT record after deletion until the entry is reused; deleted entries are flagged "not in use" but content is intact.
  - Tool deployment/cleanup pattern: `FILE_CREATE` followed by `FILE_DELETE` within ~60 s.
  - Workflow: MFT first -> filter to incident window -> pull `$J` records per entry number -> compare `$SI` vs `$FN` -> confirm with `$LogFile` -> check VSS for earlier MFT states -> carve only as last resort.

### 1.2 NTFS artefacts for investigators: Using USN Journal in digital forensics
- URL: https://andreafortuna.org/2025/09/06/usn-journal/
- Why trustworthy: Same practitioner; consistent with Microsoft USN_RECORD documentation.
- Techniques:
  - `$J` records carry USN, filename, parent MFT reference, reason bitmask, timestamp; parent reference lets you rebuild paths even when the parent directory is deleted ("journal rewind": read backwards to reconstruct deleted hierarchies).
  - Extraction options: MFTECmd (resolves full paths by MFT correlation), UsnJrnl2Csv, SleuthKit `icat` on the `$J` ADS, Velociraptor `parse_usn()`.
  - Retention is typically ~20 days on a busy volume; `$MAX` shows configured size.
  - Prefetch trick: `.pf` file updates recorded in `$J` extend execution history beyond the 8 timestamps a Prefetch file stores.

### 1.3 NTFS Triforce: A Deeper Look Inside the Artifacts (David Cowen)
- URL: https://www.hecfblog.com/2013/01/ntfs-triforce-deeper-look-inside.html
- Why trustworthy: David Cowen (HECF/Forensic Lunch) coined the "Triforce" correlation method; foundational reference.
- Techniques:
  - `$LogFile` -> `$MFT` linkage via LSN in the file record header; `$STANDARD_INFORMATION` stores the USN at offset 0x40; `$UsnJrnl` -> `$MFT` via MFT record number (immutable anchor across all three).
  - `$LogFile` holds before/after copies of the attributes being changed, so original timestamps and names can be recovered even after timestomping or rename.
  - Conclusions supportable from the triad: ownership/permission changes, precise timestamp alteration, moves between directories (parent record number), renames during destruction, per-file action sequences, hard-link detection.

### 1.4 ShimCache and AmCache Forensic Analysis 2026 (Cyber Triage)
- URL: https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2026/
- Why trustworthy: Cyber Triage is Brian Carrier's (SleuthKit author) company; article is careful about what artifacts do NOT prove.
- Techniques:
  - Paths: Amcache `C:\Windows\AppCompat\Programs\Amcache.hve` (legacy `RecentFileCache.bcf`); ShimCache `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache`.
  - ShimCache: max 1024 entries (96 XP, 512 2003); records path, size, file last-modified time (NOT execution time); written to registry only on shutdown/reboot; on Win10+ entries appear for files merely viewed in Explorer, so it does not prove execution.
  - Amcache: SHA1 only over first 30 MB of the file; records install method, PE metadata, driver info; entries persist after deletion; treat as existence evidence, not execution.
  - Parse with `AppCompatCacheParser.exe -f SYSTEM --csv out` and `AmcacheParser.exe -f Amcache.hve --csv out` (Eric Zimmerman), RegRipper4 amcache plugin, or Volatility3 for in-memory ShimCache.
  - "Entry proximity" heuristic: files inserted adjacent in ShimCache were added around the same time; pivot from a known-bad entry to its neighbours.

### 1.5 Windows Prefetch Forensics: Execution Evidence and Its Limits
- URL: https://sethenoka.com/prefetch-execution-evidence-and-its-limits/
- Why trustworthy: Practitioner interpretation piece focused on evidentiary limits (useful to avoid over-claiming in CTF answers).
- Techniques:
  - Path `C:\Windows\Prefetch\*.pf`; Win8+ stores last 8 run timestamps + run count; Win7 max 128 files, Win8+ 1024.
  - "10-second rule": referenced files/directories are only those touched in the first ~10 s of execution; recorded run time may lag real start by seconds.
  - Prefetch is disabled by default on Windows Server and often on SSD/enterprise builds — absence is not evidence of non-execution.
  - Run count resets when the .pf is deleted and recreated.

### 1.6 PECmd (Eric Zimmerman)
- URL: https://github.com/EricZimmerman/PECmd
- Why trustworthy: Primary tool repo.
- Techniques: `PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv`; `-f` single file; `-k "temp,tmp,downloads"` highlights keywords; `--mp` millisecond precision; `--vss` also parses shadow copies; `--json`, `--html`. Output: last run times, run count, files loaded, volume serial/creation, SHA-1 of the .pf.

### 1.7 Windows Shell Items Analysis (Cyber5W)
- URL: https://cyber5w.com/blog/windows-shell-items-analysis
- Why trustworthy: Training vendor blog with exact paths and EZ tool commands.
- Techniques:
  - LNK: `C:\Users\<u>\AppData\Roaming\Microsoft\Windows\Recent\` and `...\Microsoft\Office\Recent\`; each LNK holds the target's MAC times plus the link's own MAC times, volume serial, machine ID/MAC address. Parse: `LECmd.exe -d <dir> --csv out`.
  - Jump Lists: `...\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` (OLE compound file with DestList stream) and `...\Recent\CustomDestinations\`. Jump list created time = first access, modified = last access. Parse: `JLECmd.exe -d <dir> --csv out` / JumpList Explorer.
  - ShellBags: `NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags|BagMRU` and `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\Bags|BagMRU`; prove folder existence/browsing (including removable media, UNC, deleted folders). Parse: `SBECmd.exe -f UsrClass.dat --csv out` / ShellBags Explorer.

### 1.8 Windows Forensics: analysis of Recycle Bin artifacts
- URL: https://andreafortuna.org/2019/09/26/windows-forensics-analysis-of-recycle-bin-artifacts/
- Why trustworthy: Practitioner blog; matches rifiuti2 docs.
- Techniques: `C:\$Recycle.Bin\<SID>\` with paired `$I<rand>` (metadata: original path, size, deletion FILETIME) and `$R<rand>` (content); XP used `RECYCLER\<SID>\INFO2`. Parse: `rifiuti-vista -x -z -o out.xml "\\case\$Recycle.Bin\S-1-5-21-..."` or Zimmerman `RBCmd.exe -d <dir> --csv out`. Quick manual read: `$I` header 0x01 (Vista-8) or 0x02 (Win10, has path-length field), then 8-byte size, 8-byte FILETIME, UTF-16 path.

### 1.9 HTB Sherlock: BFT (0xdf)
- URL: https://0xdf.gitlab.io/2024/04/17/htb-sherlock-bft.html
- Why trustworthy: 0xdf is a top-ranked HTB writeup author; challenge is public and reproducible.
- Techniques:
  - `MFTECmd.exe -f '.\C\$MFT' --csv . --csvf mft.csv`, then Timeline Explorer: filter Parent Path, sort on "Last Modified0x10" to see sequential operations; MFT export has 8 timestamps (0x10 = `$SI`, 0x30 = `$FN`).
  - Recover resident file content directly: offset = EntryNumber * 1024 into `$MFT`; slice with Python and verify with `file`. Files under ~900 bytes are resident.
  - `Zone.Identifier` ADS appears as its own row right after a downloaded file; `ZoneId=3` = Internet, `HostUrl=` gives the download URL (IOC).
  - Pitfall: sorting on modified vs created can make creation order look wrong; nested zip extraction shows as multiple create events.

### 1.10 HTB Cyber Apocalypse 2023 Forensics (forensicskween) — disk portions
- URL: https://forensicskween.com/ctf/hack-the-box/htb-cyber-apocalypse-2023-forensics/
- Why trustworthy: Verified writeup of a public HTB event by a consistent forensics author.
- Techniques (disk):
  - Mount VHDX on Linux: `sudo qemu-nbd -c /dev/nbd0 disk.vhdx` then `sudo mount -t ntfs -o loop,ro,show_sys_files,stream_interface=windows /dev/nbd0p1 /mnt/`.
  - With `stream_interface=windows`, alternate data streams are readable as `file:stream`, e.g. `cat /mnt/.../ActiveSyncProvider.dll:hidden.ps1`.
  - Check `ConsoleHost_history.txt` (`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\`) for attacker commands; expect base64 + XOR layering.

### 1.11 CyberDefenders "SpottedInTheWild" writeup (search snippet only — page returned 403)
- URL: https://medium.com/@chaoskist/cyberdefenders-write-up-spottedinthewild-8013712e62db
- Why trustworthy: CyberDefenders lab writeup; commands visible in snippet match EZ tool syntax.
- Techniques: `MFTECmd.exe -f .\$MFT --csv .\MFTOut` and `PECmd.exe -d .\prefetch --csv .\PreOut`; tool stack for a Windows triage image: Arsenal Image Mounter, Registry Explorer, Event Log Explorer, NTFS Log Tracker (for `$LogFile`), SQLite viewer, CyberChef.

---

## 2. Memory forensics (Volatility 3)

### 2.1 Volatility 3 CheatSheet (onfvp / Ashley Pearson)
- URL: https://blog.onfvp.com/post/volatility-cheatsheet/
- Why trustworthy: Practitioner cheat sheet mapping vol2 -> vol3, with exact syntax.
- Commands:
  - `vol.py -f mem.raw windows.info` (replaces imageinfo/kdbgscan; no profile needed).
  - `windows.pslist`, `windows.psscan`, `windows.pstree`, `windows.cmdline`, `windows.dlllist --pid N`, `windows.handles --pid N`.
  - `vol.py -f mem.raw -o outdir windows.memmap --dump --pid N` (full process memory dump for `strings`).
  - `windows.filescan` then `vol.py -f mem.raw -o outdir windows.dumpfiles --virtaddr 0x...` (or `--physaddr`, or `--pid N` to dump exe+DLLs).
  - `windows.netscan`, `windows.netstat`.
  - `windows.registry.hivelist`, `windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"`.
  - `windows.malfind`, `windows.vadyarascan --yara-file rules.yar`.

### 2.2 Volatility 3 — Memory Forensics CTF Cheat Sheet (xbpt)
- URL: https://xbpt.gitlab.io/ctf/volatility3-cheatsheet.html
- Why trustworthy: CTF-oriented, ordered workflow with explicit pitfalls; commands verified against vol3 plugin names.
- Ordered workflow:
  1. `strings mem.dmp | grep 'flag{'` and `strings -el mem.dmp | grep flag` (UTF-16LE for Windows).
  2. `windows.info` -> 3. `windows.pstree`, `windows.cmdline` (encoded PowerShell) -> 4. `windows.netscan`.
  5. `windows.malfind` (look for RWX VADs with `MZ` header).
  6. `windows.filescan | grep -iE 'flag|secret|pass|\.txt'` -> `windows.dumpfiles --virtaddr`.
  7. `windows.hashdump` (user:RID:LM:NTLM), `windows.lsadump`, `windows.cachedump`.
  8. `windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"`.
  9. Hidden processes: diff `pslist` vs `psscan` PIDs (no psxview in vol3).
  - Flag recovery: `windows.memmap --pid N --dump` then `strings pid.N.dmp | grep -i flag`; `windows.cmdscan`/`windows.consoles` are unreliable on Win7/10 — fall back to dumping `conhost.exe`/`cmd.exe`/`powershell.exe` memory and grepping.
  - Clipboard: no reliable vol3 plugin in every version; dump `explorer.exe` and grep.
  - Pitfall: malware plugins moved to `windows.malware.*` namespace in vol3 >= 2.11 (e.g. `windows.malware.malfind`).
  - Linux: symbols must match exact kernel banner; use the ISF server or dwarf2json.

### 2.3 Volatility CheatSheet — Windows Memory Dump Analysis (HackMD, TuX)
- URL: https://hackmd.io/@TuX-/BymMpKd0s
- Why trustworthy: Community cheat sheet; syntax matches official plugin list.
- Adds: `windows.registry.hivescan`, `windows.registry.printkey` without `--key` (lists root), `windows.dumpfiles --pid N`, `windows.memmap --dump --pid N`, `windows.handles --pid N`, `windows.dlllist --pid N`.

### 2.4 Volatility 3 Linux Tutorial (official docs)
- URL: https://volatility3.readthedocs.io/en/latest/getting-started-linux-tutorial.html
- Why trustworthy: Primary Volatility Foundation documentation.
- Workflow:
  - `python3 vol.py -f memory.vmem banners` -> exact kernel banner string.
  - Symbols: check pre-built ISF JSON (`volatility3-symbols` repo, Debian/Ubuntu/AlmaLinux) or build with dwarf2json; drop `.json`/`.json.xz` into `volatility3/symbols/linux/` — auto-detected.
  - Plugins: `linux.pslist`, `linux.pstree`, `linux.bash` (bash history from memory), `linux.lsmod`, `linux.kmsg`, `linux.elfs`, `linux.check_creds`, `linux.vmayarascan`, `linux.boottime`, `linux.ip.Addr`, `linux.ip.Link`, `linux.malfind`.

### 2.5 Banners, isfinfo, and custom profiles (iblue.team)
- URL: https://www.iblue.team/memory-forensics-1/volatility-plugins/banners-isfinfo-and-custom-profiles
- Why trustworthy: Practitioner notes that fill the gap in official docs on banner mismatches.
- Techniques:
  - Confirm distro: `strings dump.raw | grep -B4 DISTRIB_DESCRIPTION` (also grep `/etc/os-release`, `/etc/issue`).
  - Install matching `linux-image-<ver>` + `linux-image-<ver>-dbgsym`, run dwarf2json against `vmlinux` to produce ISF JSON.
  - `python3 vol.py isfinfo` lists loaded symbol tables; the profile's base64 banner must equal the dump's banner exactly. If it differs, patch the base64 banner in the JSON, rename (e.g. `-modified.json`), `--clear-cache`, rerun.

### 2.6 HTB Sherlock "Recollection" (jon-brandy)
- URL: https://github.com/jon-brandy/hackthebox/blob/main/Categories/Sherlocks/Recollection/README.md
- Why trustworthy: 35+ Sherlock writeups by the author; public challenge.
- Techniques:
  - `windows.info` gives dump capture time (SystemTime) — often a direct answer.
  - `windows.pstree` proves `cmd.exe -> powershell.exe` chain; `windows.cmdline` exposes obfuscated PowerShell.
  - `windows.clipboard` recovered `(gv '*MDR*').naMe[3,11,2]-joIN''` — a classic IEX alias built from `$MaximumDriveCount` variable name; `windows.consoles` showed it resolved to `iex`.
  - `windows.filescan` -> `windows.dumpfiles --virtaddr 0x11e0d16f0` to pull the Edge `History` SQLite from memory; `windows.memmap --dump --pid <Edge>` then `strings | grep -i gmail` to recover attacker email.
  - `windows.registry.hivelist` -> `printkey --key "ControlSet001\Control\ComputerName\ComputerName"` for hostname; `windows.hashdump` for account list.
  - Typo-squatted binaries (`csrsss.exe`) and SHA256-named executables in Downloads are red flags; verify via VirusTotal hash.

### 2.7 HTB Cyber Apocalypse 2023 (forensicskween) — memory portions
- URL: https://forensicskween.com/ctf/hack-the-box/htb-cyber-apocalypse-2023-forensics/
- Techniques:
  - Pandora's Bane: `vol3 -f mem.raw windows.malfind` -> dump PowerShell process -> extract base64 .NET assemblies -> `ilspycmd -o out -p payload.exe` -> XOR key and shellcode co-located in the same assembly.
  - Bashic Ransomware: Linux dump + `vol3 -f forensics.mem linux.gpg_full.GPGItem` (community plugin) recovers a GPG symmetric passphrase from memory; decrypt with python-gnupg.

---

## 3. Network forensics (Wireshark/tshark)

### 3.1 Wireshark — Jorian Woltjer's Practical CTF book
- URL: https://book.jorianwoltjer.com/forensics/wireshark
- Why trustworthy: Curated CTF reference by an active CTF player; every command is concrete.
- Techniques:
  - Follow stream: Analyze -> Follow -> TCP/UDP/TLS/HTTP (Ctrl+Shift+Alt+T); switch "Show data as" to Raw to save binary; `tcp.stream eq N` filter auto-generated.
  - Field extraction: `tshark -r cap.pcap -Y 'dns' -T fields -e dns.qry.name`; `-E separator=, -E quote=d`; find field names via right-click -> Copy -> Field Name.
  - DNS exfil decode pipeline: dedupe (`sed -n '1~2!p'`), strip domain (`sed 's/.example.com//g'`), then `base32 -d` or `xxd -r -p`; TXT answers via `-e dns.txt`.
  - USB keystrokes: `tshark -r cap.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > keys.txt` then `usbkeyboard.py keys.txt`.
  - TLS: Preferences -> Protocols -> TLS -> (Pre)-Master-Secret log filename (format `CLIENT_RANDOM <hex> <hex>`), or RSA keys list (IP, port, `http`, keyfile).
  - Wi-Fi: Preferences -> IEEE 802.11 -> Decryption keys (`wpa-pwd MyPassword:MySSID`, `wpa-psk <64 hex>`); need EAPOL handshake (`eapol` filter).
  - Triage: Statistics -> Protocol Hierarchy / Conversations / Endpoints; `pkt_comment` filter finds hidden packet comments (a common flag location); Modbus register extraction with `modbus.regnum16`/`modbus.regval_uint16`.

### 3.2 Wireshark Tutorial: Exporting Objects From a Pcap (Unit 42)
- URL: https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/
- Why trustworthy: Palo Alto Unit 42 malware-traffic training series (Brad Duncan).
- Techniques:
  - File -> Export Objects -> HTTP / SMB / IMF / FTP-DATA / TFTP / DICOM. For SMB, only export entries marked `[100.0%]`.
  - Filters: `http.request` (see Content-Type column), `smtp.data.fragment` for emails (exports `.eml`), `ftp.request.command or (ftp-data and tcp.seq eq 1)` to find FTP transfers; `ftp-data.command contains ".exe" and tcp.seq eq 1`.
  - Manual fallback: Follow TCP stream -> Raw -> Save As; verify with `file` and `shasum -a 256`.
  - Encrypted (HTTPS/SMTPS) objects cannot be exported without keys.

### 3.3 How to decrypt TLS traffic in Wireshark (PacketSafari)
- URL: https://www.packetsafari.com/blog/2022/10/07/wireshark-decryption/
- Why trustworthy: Written by Wireshark trainers; matches Wireshark wiki.
- Techniques:
  - `export SSLKEYLOGFILE=$HOME/sslkeylog.log` (or `set SSLKEYLOGFILE=...` / `$env:SSLKEYLOGFILE=...`) before starting the browser/curl; Chrome also accepts `--ssl-key-log-file=`.
  - Embed keys permanently: `editcap --inject-secrets tls,keylog.txt in.pcapng out.pcapng` (pcapng only) — no preference needed afterwards; tshark: `-o tls.keylog_file:keylog.txt`.
  - RSA private key decryption only works for static RSA key exchange with the full handshake captured — not for (EC)DHE and never for TLS 1.3.
  - Troubleshooting order: same process/connection, full handshake present, TCP reassembly enabled, connection not started before logging began, not QUIC/UDP.

### 3.4 ctf-usb-keyboard-parser (TeamRocketIst)
- URL: https://github.com/TeamRocketIst/ctf-usb-keyboard-parser
- Why trustworthy: De-facto standard script referenced across dozens of CTF writeups.
- Techniques: `tshark -r usb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata | sed 's/../:&/g2' > data.txt`; `python usbkeyboard.py data.txt`. HID report = [modifier, reserved, key1..key6]; modifier 0x02/0x20 = shift; mapping per USB HID Usage Tables table 12. Bluetooth HID equivalent: extract `btatt.value`.

### 3.5 Huntress CTF 2024 "Keyboard Junkie" writeup (shreethaar)
- URL: https://shreethaar.github.io/ctf-writeups/writeups/2024/huntressctf/keyboard-junkie/
- Why trustworthy: Verified CTF writeup with a working decoder.
- Techniques: filter by device address, not just length: `tshark -r kb.pcap -Y 'usb.src == "1.9.1"' -T fields -e usb.capdata`; some dissectors expose `usbhid.data` instead of `usb.capdata` — try both; keycodes 4-29 = a-z, 30-39 = 1-0, 0x39 = CapsLock, 79-80 arrows; ignore reports whose keycode is 0 (release).

### 3.6 MetaCTF Flash CTF — Key Evidence
- URL: https://metactf.com/blog/flash-ctf-key-evidence/
- Why trustworthy: Official challenge-author writeup.
- Techniques: skip auto-repeat duplicates (track previous key), skip all-zero release reports, and apply Backspace (0x2A) by deleting the previous output character — otherwise the flag is corrupted. Keycode -> (unshifted, shifted) tuple dictionary.

### 3.7 Overview of mainstream DNS tunneling tools (dmachard)
- URL: https://dmachard.github.io/posts/0047-dns-tunneling-overview/
- Why trustworthy: Author of DNS-collector/dnstap tooling; technical comparison.
- Techniques for recognising the tool from the pcap:
  - iodine: NULL/PRIVATE/MX/CNAME/TXT, EDNS0, upstream base128 (custom alphabet), downstream raw; MTU probes 1130/1522; unencrypted (MD5 auth only).
  - dnscat2: TXT/CNAME/MX; hex-encoded payload with a 9-byte header per message (from the BSidesSF dnscap writeups — skip the first 9 bytes/18 hex chars of each query label before decoding); sessions encrypted by default in newer versions.
  - dns2tcp: TXT/KEY records. DNSExfiltrator: TXT, base32, max chunk 233 bytes, predictable chunk counters.
  - Generic heuristics: long high-entropy leftmost labels, many unique subdomains under one zone, unusual RR types, high query rate to one authoritative server.

### 3.8 DNS exfil CTF writeups (search snippets only — pages returned 403)
- URLs: https://blog.xpnsec.com/bsidessf-dnscap/ , https://ctftime.org/writeup/5645
- Snippet-level takeaways: `tshark -r dnscap.pcap -T fields -e dns.qry.name > names.txt`; for dnscat2 the first 9 bytes of each message are header, the remainder is hex-encoded payload; flaky-connection retransmits must be deduplicated by sequence number before concatenating.

---

## 4. Windows registry and event logs

### 4.1 Windows Registry Forensics Cheat Sheet 2026 (Cyber Triage)
- URL: https://www.cybertriage.com/blog/windows-registry-forensics-cheat-sheet-2026/
- Why trustworthy: Brian Carrier's company; exhaustive key list consistent with SANS poster.
- Hive files: `C:\Windows\System32\config\{SAM,SYSTEM,SOFTWARE,SECURITY}`, `C:\Users\<u>\NTUSER.DAT`, `C:\Users\<u>\AppData\Local\Microsoft\Windows\UsrClass.dat`, `C:\Windows\AppCompat\Programs\Amcache.hve`. Replay `.LOG1/.LOG2` transaction logs first (`rla.exe`), else recent keys are missing.
- Keys:
  - Execution: `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` (ROT13 names, run count, last run); `...\Explorer\RunMRU`; `UsrClass\Local Settings\Software\Microsoft\Windows\Shell\MuiCache`; `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (BAM/DAM: last execution per binary per user); ShimCache as above.
  - Files/folders: `...\Explorer\RecentDocs`, `...\Explorer\ComDlg32\OpenSavePidlMRU` and `LastVisitedPidlMRU`, `...\Explorer\TypedPaths`, `...\Explorer\WordWheelQuery` (Explorer search terms), ShellBags (`NTUSER\Software\Microsoft\Windows\Shell` and `UsrClass\Local Settings\Software\Microsoft\Windows\Shell`).
  - Devices: `SYSTEM\CurrentControlSet\Enum\USBSTOR` (vendor/product/serial; first/last connect in Properties `{83da6326-...}\0064/0066/0067`), `SYSTEM\MountedDevices`, `NTUSER\...\Explorer\MountPoints2`, `SOFTWARE\Microsoft\Windows Portable Devices\Devices`.
  - Network: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` (+ `Signatures\Unmanaged` for gateway MAC), `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\`, RDP `NTUSER\Software\Microsoft\Terminal Server Client\Servers|Default`.
  - Persistence: `Run`/`RunOnce` under both `NTUSER\Software\Microsoft\Windows\CurrentVersion\` and `SOFTWARE\Microsoft\Windows\CurrentVersion\`; `SYSTEM\CurrentControlSet\Services`; `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` (Shell/Userinit); `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree|Tasks`.
  - System: `SYSTEM\Select\Current` picks the live ControlSet; `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`; `...\Control\TimeZoneInformation`; `SOFTWARE\Microsoft\Windows NT\CurrentVersion` (InstallDate, ProductName); `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` (SID -> profile path).
  - SAM: `SAM\Domains\Account\Users\<RID>` F/V values -> account creation/last logon/hashes.
- Tools: Registry Explorer/RECmd (batch files: `RECmd.exe -d hives --bn BatchExamples\Kroll_Batch.reb --csv out`), RLA, RegRipper4, Autopsy.

### 4.2 Windows Registry Forensics with RegRipper (DFIR notes)
- URL: https://mahmoud-shaker.gitbook.io/dfir-notes/windows-registry-forensics-with-regripper
- Why trustworthy: Practitioner notes mirroring RegRipper's own docs (RegRipper4.0 GitHub README fetched; it confirms rip.exe does not replay transaction logs — use `rla.exe` or yarp `registryFlush.py` first).
- Commands: `rip.exe -r NTUSER.DAT -p userassist`; `rip.exe -r SYSTEM -a` (run all plugins for that hive type); `rip.exe -l` (list plugins), `rip.exe -r SAM -p samparse`; useful plugins: `userassist`, `recentdocs`, `shellbags`, `typedurls`, `run`, `services`, `drivers`, `samparse`, `amcache`, `appcompatcache`, `usbstor`, `mountdev`, `networklist`, `timezone`, `compname`, `shutdown`, `bam`.

### 4.3 13Cubed Windows Event Log Cheat Sheet (v1.3)
- URL: https://cdn.13cubed.com/downloads/windows_event_log_cheat_sheet.pdf
- Why trustworthy: 13Cubed (Richard Davis) is a widely used DFIR training channel; PDF text extracted locally with pdftotext.
- Event IDs (Security): 4624 logon (see types), 4625 failed, 4634/4647 logoff, 4648 explicit creds (RunAs), 4672 special privileges (admin), 4776 NTLM validation on DC, 4768 TGT, 4769 service ticket, 4771 Kerberos pre-auth failed, 4720 account created, 4722 enabled, 4688 process created (if audited), 4698 scheduled task created, 4798/4799 group membership enumerated, 5140 share accessed, 5145 share object access check, 1102 audit log cleared.
- Logon types: 2 console, 3 network, 4 batch, 5 service, 7 unlock, 8 network cleartext, 9 RunAs alternate creds, 10 RDP, 11 cached, 12 cached RDP, 13 cached unlock.
- System: 7045 new service (4697 in Security), 7034 service crashed, 7009 service timeout, 104 log cleared (non-Security logs).
- Application: 1000 app error, 1002 hang; ESENT 216/325/326/327 database created/attached/detached (ESE DB such as SRUM/WebCache activity).
- PowerShell: classic 400/600 (engine start, provider started); `Microsoft-Windows-PowerShell/Operational` 4104 script block text (auto-logged as Warning for "suspicious" scripts even without policy).
- TaskScheduler/Operational: 106 task registered, 141 task deleted, 100 task started, 102 task finished.
- Windows Defender/Operational: 1116 malware detected, 1117 action taken.
- RDP: TerminalServices-LocalSessionManager/Operational 21 logon, 22 shell start, 23 logoff, 24 disconnect, 25 reconnect; RemoteConnectionManager/Operational 1149 network auth success, 261 listener received connection; RDPClient/Operational 1029 (on the SOURCE machine, Base64(SHA256(username))).

### 4.4 From 4688 to 1102: Windows event IDs that matter (NXLog)
- URL: https://nxlog.co/news-and-blog/posts/windows-event-ids-threat-detection
- Why trustworthy: Log-collection vendor; maps IDs to ATT&CK with field-level pivots.
- Additional IDs and pivots: 4689 process exit; Sysmon 1 (hashes, parent, original filename) and 3 (network connection by process); 4697 service installed (Security); 4702 scheduled task updated (attackers reuse legit task names); 5861 WMI permanent consumer registered (`Microsoft-Windows-WMI-Activity/Operational`); 4732/4728 local/global group membership added; 4673/4674 privileged service/object (noisy, filter on SeDebugPrivilege); 4719 audit policy changed and 4907 SACL changed (pre-attack evasion).
- Pivots: burst of 4624 type 3 from one host to many = lateral movement; 4624 type 10 from non-jump-host = alert; around every 1102 pivot to the preceding 4624 for source IP/workstation; 4104 captures deobfuscated script content even for IEX loaders.

### 4.5 Chainsaw (WithSecure Labs)
- URL: https://github.com/WithSecureLabs/chainsaw
- Why trustworthy: Primary tool repo.
- Commands:
  - `chainsaw hunt evtx_dir/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv --output results`
  - Time-bound: `--from "2019-03-17T19:09:39" --to "2019-03-17T19:09:50" --json`
  - Search: `chainsaw search mimikatz -i evtx_dir/`; `chainsaw search -t 'Event.System.EventID: =4104' evtx_dir/`; regex `chainsaw search -e "DC[0-9].insecurebank.local" evtx_dir --json`
  - Analyse: `chainsaw analyse shimcache ./SYSTEM --regexfile analysis/shimcache_patterns.txt --amcache ./Amcache.hve --tspair --output out.csv`; `chainsaw analyse srum --software ./SOFTWARE ./SRUDB.dat --output out.json`; `chainsaw analyse gaps ./Logs/ --json -o gaps.json` (detect cleared/missing log ranges).
  - Dump: `chainsaw dump ./SOFTWARE.hve --json --output out.json`. Inputs: EVTX, JSON/XML logs, MFT, registry hives, Shimcache/Amcache, SRUM/ESE.

### 4.6 Hayabusa (Yamato Security)
- URL: https://yamato-security.github.io/hayabusa/commands/ (and repo https://github.com/Yamato-Security/hayabusa)
- Why trustworthy: Primary tool docs.
- Commands (subcommand list verified on the docs page; flag syntax below is from the tool's `--help` conventions): `hayabusa update-rules`; `hayabusa csv-timeline -d ./evtx -o timeline.csv --UTC -m low` (`-f` single file, `-p super-verbose|timesketch-verbose` profiles, `--RFC-3339`); `hayabusa json-timeline -d ./evtx -L -o timeline.jsonl` for jq; `hayabusa logon-summary -d ./evtx`; `hayabusa eid-metrics -d ./evtx`; `hayabusa computer-metrics -d ./evtx`; `hayabusa pivot-keywords-list -d ./evtx`; `hayabusa search -d ./evtx -k "mimikatz"` or `-r "regex"`; `hayabusa extract-base64 -d ./evtx`; `level-tuning`, `list-profiles`, `set-default-profile`. Load the CSV in Timeline Explorer and sort by Level.

---

## 5. Browser, mobile and cloud artifacts

### 5.1 Google Chrome History Location (Foxton Forensics)
- URL: https://www.foxtonforensics.com/browser-history-examiner/chrome-history-location
- Why trustworthy: Browser-forensics tool vendor documentation.
- Paths: Windows `C:\Users\<u>\AppData\Local\Google\Chrome\User Data\Default\`, macOS `~/Library/Application Support/Google/Chrome/Default/`, Linux `~/.config/google-chrome/Default/`; cache in `...\Default\Cache` (Windows), `~/Library/Caches/Google/Chrome/Default/Cache` (macOS), `~/.cache/google-chrome/Default/Cache` (Linux). Edge/Brave/Chromium use the same layout under their own vendor directory.
- Databases/tables: `History` (`urls`, `visits`, `downloads`, `downloads_url_chains`, `keyword_search_terms`), `Network\Cookies`, `Login Data` (`logins`), `Web Data` (`autofill`), `Favicons`, `Top Sites`; `Bookmarks`/`Preferences` are JSON; cache = `index` + `data_#` block files + `f_######` separate files.
- Timestamps: WebKit format — microseconds since 1601-01-01; convert with `datetime(visit_time/1000000 - 11644473600, 'unixepoch')` in SQLite (standard conversion; not stated on the page but required to use these tables).

### 5.2 Hindsight (Obsidian Forensics)
- URL: https://github.com/obsidianforensics/hindsight
- Why trustworthy: Primary tool repo; widely used for Chromium history.
- Usage: `hindsight.py -i "<profile dir>" -o case1 -f xlsx|sqlite|jsonl -t UTC`; `-c <cache dir>` if cache is elsewhere; `--only`/`--skip cache` to speed up. Parses History, Archived History, Cache, Cookies, Local/Session Storage, Extensions, Preferences, Login Data, Bookmarks, Sync, Media History, Downloads, Autofill. Cache entries frequently hold the actual downloaded payload or the flag page.

### 5.3 Forensic data recovery with SQLite analysis (Belkasoft)
- URL: https://belkasoft.com/sqlite
- Why trustworthy: Vendor technical explainer; consistent with SQLite file-format docs.
- Concepts: deleted records persist in freelist pages (45-95% of recoverable data), in-page unallocated space (needs carving), `-wal` (may hold weeks of uncommitted changes plus previous versions of edited records) and legacy `-journal`; `secure_delete=on` zeroes deleted content and `auto_vacuum=full` truncates freelists (app-dependent). Always collect `.db`, `.db-wal`, `.db-shm` together; opening with a non-forensic tool may checkpoint and destroy WAL evidence.

### 5.4 Write-Ahead Logging (SQLite.org)
- URL: https://www.sqlite.org/wal.html
- Why trustworthy: Primary spec.
- Facts: WAL holds committed pages not yet in the main DB; auto-checkpoint at ~1000 pages (~4 MB) and on last-connection close (which also deletes -wal/-shm); the same page can appear in multiple versions in the WAL (history!); open read-only with `?immutable=1` URI or on a read-only copy to avoid checkpointing. Header byte 18/19 = 0x02 means WAL mode, 0x01 rollback journal.

### 5.5 A first look at Android 14 forensics (Mattia Epifani, digital-forensics.it)
- URL: https://blog.digital-forensics.it/2024/01/a-first-look-at-android-14-forensics.html
- Why trustworthy: SANS instructor and ALEAPP contributor; paths verified on a real device.
- Paths (under `/data/`): SMS/MMS `data/com.android.providers.telephony/databases/mmssms.db`; contacts `data/com.android.providers.contacts/databases/contacts2.db` and `calllog.db`; Google Messages `data/com.google.android.apps.messaging/databases/bugle_db`; accounts `system_ce/0/accounts_ce.db`; Wi-Fi `misc/apexdata/com.android.wifi/WifiConfigStore.xml`; usage `system_ce/0/usagestats/`, `system_ce/0/recent_tasks/` + `snapshots/` (screenshots of recent apps), `system_ce/0/notification_history/`; `system/packages.xml` (ABX binary XML — convert with `abx2xml`); `misc/adb/adb_keys`; `misc/bluedroid/bt_config.conf`; media index `data/com.google.android.providers.media.module/databases/external.db`; Play Store `data/com.android.vending/databases/library.db|localappstate.db`; Gboard `data/com.google.android.inputmethod.latin/databases/trainingcachev3.db` (typed text!). Timestamps are Unix epoch milliseconds. Tools: ALEAPP, adb backup/pull.

### 5.6 How do apps store data in iPhone backups (Reincubate)
- URL: https://reincubate.com/support/how-to/iphone-backup-files-structure/
- Why trustworthy: iOS backup tool vendor with long-standing technical docs.
- Facts: backup files are named by SHA-1 of `<domain>-<relativePath>` (hex), organised in 2-hex-char subfolders; `Manifest.db` (SQLite) `Files` table maps `fileID, domain, relativePath, flags, file(plist blob)`; `Manifest.plist` (encrypted flag, Keybag), `Info.plist`, `Status.plist`. Stable hashes: SMS `3d0d7e5fb2ce288813306e4d4636395e047a3d28` (HomeDomain `Library/SMS/sms.db`), AddressBook `31bb7ba8914766d4ba40d6dfb6113c8b614be442`, Calendar `2041457d5fe04d39d0ab481178355df6781e6858`, Photos.sqlite `12b144c0bd44f2b3dffd9186d3f9c05b917cee25`, call history `2b2b0084a1bc3a5ac8c27afdf14afb42c61a19ca`. Domains: HomeDomain, CameraRollDomain, MediaDomain, AppDomain-<bundle>, AppDomainGroup-<group>, KeychainDomain. Apple timestamps are seconds (or ns) since 2001-01-01 (add 978307200 for Unix). Encrypted backups: use `iOSbackup` (Python) with the password to derive keys from the Keybag.

---

## 6. Steganography and multimedia

### 6.1 Steganography CTF Cheatsheet — Decision Tree (Aperi'Solve)
- URL: https://www.aperisolve.com/cheatsheet
- Why trustworthy: Maintained by the Aperi'Solve platform authors; a curated decision tree used by many CTF teams.
- Universal first pass: `file`, `exiftool -a -u -g1` (extract the embedded thumbnail too), `strings -n 8` plus `-e l`/`-e b` for UTF-16, `binwalk` then `binwalk -e`.
- PNG/BMP: `zsteg -a f.png` -> `zsteg -E 'b1,rgb,lsb,xy' f.png > out.bin`; `pngcheck -vtp7 f.png`; Stegsolve all bit planes incl. alpha, MSB and column order (zsteg misses alpha/MSB by default); data after IEND; palette tricks; `openstego extract` for randomised LSB.
- JPEG: `steghide info f.jpg`, `steghide extract -sf f.jpg -p ''` (empty password first!), `stegseek f.jpg rockyou.txt`, `outguess -r f.jpg out`, `jsteg reveal f.jpg out`. zsteg does not apply to JPEG.
- GIF/APNG: `ffmpeg -i f.gif -vsync 0 out/f%d.png`; check zero-duration frames, frame delays as encoding, diff consecutive frames.
- Audio: `sox f.wav -n spectrogram -o spec.png` first; Morse via on/off bursts; `stegolsb wavsteg -r -i f.wav -o out.txt -n 1 -b 1000`; SSTV (QSSTV), DTMF, FSK (`minimodem`); steghide/DeepSound for passworded containers.
- Video: `ffprobe f.mp4` (extra streams), `ffmpeg -i f.mp4 -vsync 0 out/f%05d.png`, `ffmpeg -i f.mkv -map 0:s:0 subs.srt`, `ffmpeg -dump_attachment:t "" -i f.mkv`, `ffmpeg -i f.mp4 -vn audio.wav`.
- Text: `cat -A` for trailing whitespace -> `stegsnow -C f.txt`; zero-width U+200B/C/D; homoglyphs; CyberChef Magic for esolangs.
- Archives/polyglots: `unzip f.png` / `7z l f.png` often just works; `pdfdetach -saveall f.pdf`; `fcrackzip -u -D -p rockyou.txt f.zip`.
- When stuck: reverse-image-search the cover and XOR against it in Stegsolve; try metadata strings as passphrases; match tool to carrier.

### 6.2 stego-toolkit (Dominic Breuker)
- URL: https://github.com/DominicBreuker/stego-toolkit
- Why trustworthy: Widely forked Docker image bundling all common stego tools with screening scripts.
- Scripts: `check_jpg.sh f.jpg`, `check_png.sh f.png` (run file/exiftool/binwalk/strings/foremost/pngcheck/zsteg/stegoveritas), `brute_jpg.sh f.jpg wordlist` (steghide, outguess, stegbreak), `brute_png.sh f.png wordlist` (openstego, stegoveritas). JPEG tools: stegdetect, jphide/jpseek, jsteg, outguess, f5; PNG: zsteg, openstego, cloackedpixel, LSBSteg; audio: AudioStego, mp3stego, steghide, spectrology, DeepSound; `identify -verbose` to spot corruption.

### 6.3 Steganography 101 cheatsheet (pequalsnp-team)
- URL: https://pequalsnp-team.github.io/cheatsheet/steganography-101
- Why trustworthy: Curated team cheat sheet; commands are concrete.
- Adds: `binwalk -M -e` recursive; `dd if=in.png of=out.zip bs=1 skip=<offset> count=<len>` to carve appended files; `pngcheck -v` shows tEXt/iTXt/zTXt/tRNS chunks; `compare a.png b.png diff.png` (ImageMagick) for two-image challenges; GIMP Grain Extract / Bucket Fill threshold 0 to reveal hidden areas; `convert -depth 8 -size WxH+0 gray:raw out.png` to render raw pixel dumps; `convert in.png out.xpm` to inspect palettes; MP3Stego `decode -X -P pass f.mp3`.

### 6.4 Audio Steganography (CTF Wiki EN)
- URL: https://ctf-wiki.mahaloz.re/misc/audio/introduction/
- Why trustworthy: ctf-wiki is a long-running community reference.
- Techniques: MP3Stego (`decode -X -P <pass> file.mp3`), waveform peaks-as-bits (high=1, low=0, typically 7/8-bit ASCII), spectrogram text (noisy/harsh audio is the tell), LSB via SilentEye, Manchester coding, DTMF/Morse (`multimon-ng -a DTMF -t wav f.wav`), SSTV.

### 6.5 Audio Steganography Cheatsheet (img2sound)
- URL: https://img2sound.com/articles/audio-steganography-cheatsheet/
- Why trustworthy: Tool site with correct, testable commands.
- Adds: Audacity spectrogram settings (max frequency 20000 Hz, log scale); inspect >15 kHz and >20 kHz bands and narrow bands masked by loud signals; `stegolsb wavsteg -r -i f.wav -o out.txt -n 2`; `ffprobe -v quiet -show_format f.wav`; `mediainfo`; `foremost -i f.wav`; decoder apps for SSTV (QSSTV/RX-SSTV).

### 6.6 CTF Cheat Sheet + Writeups (Adamkadaban)
- URL: https://github.com/Adamkadaban/CTFs
- Why trustworthy: Long-maintained picoCTF-oriented repo.
- Adds: `binwalk -M --dd=".*" f`; `grep -r --text 'picoCTF{.*}'` across extracted trees; `stegseek f.jpg wordlist`; PNG CRC fixers `crc32fix`, PCRT, `png-crc-fix`; `tcpflow -r f.pcap` to split TCP streams to files; Depix for pixelated text; audio pitch/speed manipulation.

---

## 7. File carving and file format tricks

### 7.1 Forensics — CTF Field Guide (Trail of Bits)
- URL: https://trailofbits.github.io/ctf/forensics/
- Why trustworthy: Canonical CTF text from a top security firm.
- Techniques:
  - `file` only identifies the outermost container; use TrID for obscure formats; `strings -o` for offsets; `bgrep 89504e47 f.bin` to locate magic bytes; `hexdump -C`.
  - `binwalk container.bin`; manual carve `dd if=f of=out bs=1 skip=1335205 count=40668937`.
  - Python: `bytearray(open('f','rb').read())`, `bytearray.fromhex('00 ff')`, slicing for byte surgery.
  - ZIP: `zipdetails -v`, `zipinfo`, `zip -F/-FF broken.zip --out fixed.zip`, `fcrackzip -b -c1 -u`; ZipCrypto is vulnerable to known-plaintext (bkcrack); filenames remain visible in encrypted ZIPs.
  - Filesystems: `mmls img`, `fls -r -o <offset> img`, `icat -o <offset> img <inode>`, `extundelete`, TestDisk, `mount -t iso9660`.
  - PCAP: capinfos, ngrep, tcpxtract, NetworkMiner, dpkt; pcapng may need conversion for old tools.
  - PDF: hiding places = invisible layers, XMP metadata, incremental updates (old versions retained), white text, content behind images, comments; tools qpdf, Origami, peepdf.
  - Office: OOXML = ZIP (`unzip doc.docx`); OLE with oletools/OfficeDissector; run macros safely with LibreOffice `soffice document.docx macro://./standard.module1.mymacro`.
  - Template hex editors: 010 Editor, Kaitai Struct.
  - Conventions: spoofed magic bytes, nested files, checksums as part of the puzzle, iterative encoding chains (hex -> base64 -> zlib), metadata goldmines.

### 7.2 pngcheck in CTF: How to Analyze and Repair PNG Files
- URL: https://dev.to/rudycandy/pngcheck-in-ctf-how-to-analyze-and-repair-png-files-84o
- Why trustworthy: Focused technical tutorial consistent with the PNG spec.
- Techniques: signature `89 50 4E 47 0D 0A 1A 0A`; chunk = 4-byte length + 4-byte type + data + 4-byte CRC (over type+data); `pngcheck -fvp f.png` (`-f` continue past errors, `-p` print tEXt/zTXt/iTXt, `-t` text chunks, `-c` chunk names, `-7` 7-bit safe). Corruptions: bad signature, IHDR CRC error (usually means width/height were edited — recompute or brute-force), lowercase/odd chunk names, IDAT out of order, data after IEND. Recompute CRC: `zlib.crc32(b'IHDR'+data) & 0xffffffff`. Custom chunks like `flAg` are suspicious. Fix structure before running zsteg.

### 7.3 picoCTF 2019 c0rrupt walkthrough (Dvd848)
- URL: https://github.com/Dvd848/CTFs/blob/master/2019_picoCTF/c0rrupt.md
- Why trustworthy: Byte-exact walkthrough of a canonical challenge.
- Repair sequence with dd patches: signature (`printf '\x89PNG\r\n\x1a\n' | dd of=f.png bs=1 seek=0 conv=notrunc`), IHDR length+type at offset 8 (`\x00\x00\x00\x0dIHDR`), single corrupted byte in pHYs found via CRC error, `IDAT` type at offset 87, and an impossible IDAT length `0xaaaaffa5` corrected by locating the next `IDAT` with `binwalk -R "IDAT"` and computing `next_offset - data_start - 4`. Final `pngcheck` must report "No errors detected".

### 7.4 foremost (Kali tool page)
- URL: https://www.kali.org/tools/foremost/
- Why trustworthy: Distribution documentation mirroring the man page.
- Syntax: `foremost -t jpg,png,pdf,zip -i image.dd -o out` (`-t all`), `-c foremost.conf` custom signatures, `-a` write all headers (no error detection), `-w` audit only, `-q` quick 512-byte-boundary mode, `-b` block size, `-d` indirect block detection (UNIX FS), `-T` timestamped output dir. Output: `out/audit.txt` + per-type folders.

### 7.5 bulk_extractor (Simson Garfinkel)
- URL: https://github.com/simsong/bulk_extractor
- Why trustworthy: Primary repo.
- Usage: `bulk_extractor -o out image.dd` (`-R dir` for directories, `-e <scanner>` enable optional scanners such as `wordlist`, `-x <scanner>` disable, `-f regex` custom pattern, `-F file` patterns from file). Feature files: `email.txt`, `url.txt`, `domain.txt`, `ip.txt`, `telephone.txt`, `ccn.txt`, `zip.txt`, `json.txt`, `exif.txt`, `aes_keys.txt`, carved `jpeg/`, plus `*_histogram.txt` and `report.xml`. Works on pcaps, memory dumps and unknown blobs without parsing the filesystem — ideal first pass on any large CTF blob.

### 7.6 Magic-bytes reference
- URL: https://filesig.search.org/ (successor to Gary Kessler's table, which now redirects there; archived copy linked from https://www.garykessler.net/library/file_sigs.html)
- Why trustworthy: Kessler's table was the de-facto reference for two decades; SEARCH now maintains it.
- Core signatures to memorise (hex at offset 0 unless noted): PNG `89 50 4E 47 0D 0A 1A 0A` (trailer `49 45 4E 44 AE 42 60 82`); JPEG `FF D8 FF E0/E1/E8/DB` (trailer `FF D9`); GIF `47 49 46 38 37|39 61`; BMP `42 4D`; PDF `25 50 44 46` (`%%EOF` trailer, may repeat); ZIP/DOCX/JAR/APK `50 4B 03 04` (empty `50 4B 05 06`, spanned `50 4B 07 08`; central directory ends with `50 4B 05 06`); RAR `52 61 72 21 1A 07 00|01 00`; 7z `37 7A BC AF 27 1C`; GZIP `1F 8B 08`; BZIP2 `42 5A 68`; XZ `FD 37 7A 58 5A 00`; ELF `7F 45 4C 46`; PE `4D 5A`; OLE/CFB (doc/xls/msi) `D0 CF 11 E0 A1 B1 1A E1`; SQLite `53 51 4C 69 74 65 20 66 6F 72 6D 61 74 20 33 00`; PCAP `D4 C3 B2 A1` / `A1 B2 C3 D4` (ns variants `4D 3C B2 A1`); PCAPNG `0A 0D 0D 0A`; EVTX `45 6C 66 46 69 6C 65 00` ("ElfFile"); registry hive `72 65 67 66` ("regf"); E01 `45 56 46 09 0D 0A FF 00`; VMDK `4B 44 4D 56` ("KDMV"); LNK `4C 00 00 00 01 14 02 00`; Prefetch `53 43 43 41` at offset 4 ("SCCA"; Win10 files are compressed, starting `4D 41 4D 04` "MAM"); ISO9660 `43 44 30 30 31` at 0x8001; WAV `52 49 46 46 .. .. .. .. 57 41 56 45`; MP4 `66 74 79 70` at offset 4; MP3 `49 44 33` or `FF FB`.

### 7.7 Office/PDF specifics (HackTricks pages were behind a paywalled mirror — not fetched; the following is from Trail of Bits + oletools/Didier Stevens tool conventions)
- OOXML: after `unzip`, inspect `word/document.xml` (look for `<w:vanish/>` hidden runs and white text `w:color w:val="FFFFFF"`), `docProps/core.xml|app.xml` (author, timestamps), `word/vbaProject.bin` (macros -> `olevba`), `word/embeddings/`, `word/media/`, `customXml/`, `word/comments.xml`, `[Content_Types].xml` for unexpected parts, and files inside the zip that are not referenced by any `.rels`.
- OLE: `oleid f.doc`, `olevba --decode f.doc`, `oledump.py f.doc` then `oledump.py -s <n> -v f.doc` to decompress a VBA stream, `rtfobj f.rtf` for embedded objects.
- PDF: `pdfid.py f.pdf` (counts of /JS /JavaScript /OpenAction /Launch /EmbeddedFile /ObjStm), `pdf-parser.py --search flag f.pdf`, `pdf-parser.py -o <obj> -f -d out.bin f.pdf` (filter+dump stream), `qpdf --qdf --object-streams=disable in.pdf out.pdf` to make it greppable, `qpdf --decrypt`, `pdftotext -layout`, `pdfimages -all`, `pdfdetach -saveall`; count `%%EOF` occurrences and follow `/Prev` for earlier revisions.

---

## 8. Anti-forensics and timeline

### 8.1 Defence Evasion Technique: Timestomping Detection (inversecos)
- URL: https://www.inversecos.com/2022/04/defence-evasion-technique-timestomping.html
- Why trustworthy: Lina Lau (inversecos) is a widely cited IR practitioner; the post demonstrates bypasses and detections empirically.
- Techniques:
  - `$SI` vs `$FN` comparison is the baseline but is bypassed if the attacker timestomps `$SI` then moves/renames the file (which copies `$SI` into `$FN`), or uses NtSetInformationFile to write `$FN` directly on older Windows.
  - Zeroed sub-second precision (`.0000000`) suggests tools like Timestomp/Metasploit/Cobalt Strike, but nTimetools/SetMace set arbitrary nanoseconds — treat as weak.
  - Strong detections: `$UsnJrnl` `FILE_CREATE`/`RENAME_*` records whose timestamps contradict MFT times by months/years; `$LogFile` CreateAttribute operations on `$FILE_NAME` showing the original times; cross-check Prefetch/Amcache/ShimCache/LNK/Jump List times; Sysmon Event 2 (file creation time changed).
  - MFTECmd flags `$SI` created < `$FN` created automatically; also compare MFT entry number ordering with neighbours (a "2015" file with an entry number allocated between 2023 files).

### 8.2 Digital Forensics: Detecting time stamp manipulation (SANS DFIR blog)
- URL: https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation
- Why trustworthy: SANS DFIR faculty blog; the source of the Windows Time Rules poster.
- NTFS time rules (GUI operations): create -> all `$SI` MACB + `$FN` set; modify -> `$SI` M, A(*), C; copy -> new `$SI` B/M/A/C and new `$FN`; move same volume -> `$SI` A(*), C; `$FN` unchanged; move across volumes -> behaves like copy; rename -> `$SI` C and `$FN` updated; access -> `$SI` A only and disabled by default since Vista.
- Heuristics: implausible dates (older than OS install), files whose timestamps exactly match a system binary (e.g. copied from `regedit.exe`), executables absent from Prefetch despite "old" timestamps, and inconsistent SI/FN sequences in a timeline.

### 8.3 MAC(b) times in Windows forensic analysis (andreafortuna)
- URL: https://andreafortuna.org/2017/10/06/macb-times-in-windows-forensic-analysis/
- Why trustworthy: Practitioner summary of the SANS rules with the `$SI`/`$FN` privilege distinction.
- Rules: `$FN` is only written by the kernel; rename updates `$FN` MACB but not `$SI`; copy gives the new file fresh `$SI` B and preserved... (see 8.4 for the precise nuance); `analyzeMFT.py` flags SI/FN anomalies.

### 8.4 Timestamps (qazeer DFIR notes)
- URL: https://notes.qazeer.io/dfir/windows/_artefacts_overview/timestamps
- Why trustworthy: Dense, well-referenced practitioner notes.
- Facts: on copy between NTFS volumes `$SI` M and C are inherited while A and B are set to copy time; on rename/local move `$FN` MAB are copied from `$SI` MAB and both C fields update; a long-named file has two `$FN` attributes (long + 8.3) plus copies in the parent `$I30` index — 20 timestamps per file to compare. `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate`: 1 = disabled (Vista to early Win10), 0/0x80000000/0x80000002 = enabled (default again on Win10 1803+ for volumes <=128 GiB and on 20H1+ regardless).

### 8.5 Plaso: Using log2timeline / Using psort (official docs)
- URLs: https://plaso.readthedocs.io/en/latest/sources/user/Using-log2timeline.html , https://plaso.readthedocs.io/en/latest/sources/user/Using-psort.html , https://plaso.readthedocs.io/en/stable/sources/user/Creating-a-timeline.html
- Why trustworthy: Primary documentation.
- Commands:
  - `log2timeline.py --storage-file timeline.plaso image.E01` (output first!), `--partitions 2`, `--vss-stores all|1,4|1..3|none`, `-f filter_windows.yaml` (collection filter for triage), `--parsers 'win7,!filestat'` (presets: win7, winxp, linux, macos, android; negate with `!`; `--info` lists parsers/presets), `-z UTC` / `--timezone`, `--hashers md5,sha256`, `--unattended`, `--logfile`.
  - Quick: `psteal.py --source image.raw -o dynamic -w timeline.csv`.
  - `pinfo.py --sections sources timeline.plaso` to verify what was parsed.
  - `psort.py --output-time-zone UTC -o l2tcsv -w super.csv timeline.plaso "date > datetime('2024-01-01T00:00:00') AND date < datetime('2024-01-27T00:00:00')"`; other formats `dynamic`, `json`, `json_line`, `tln`, `l2ttln`, `xlsx`, `kml`; `--slice "2024-01-05T12:00:00" --slice_size 5`; `--slicer` for context; `--analysis tagging --tagging-file tag_windows.txt`; `-a` keeps duplicates; `-q` quiet.

### 8.6 Case Studies: Building Effective Timelines with Plaso (cyberengage)
- URL: https://www.cyberengage.org/post/case-studies-building-effective-timelines-with-plaso-log2timeline
- Why trustworthy: Practical case studies with exact commands; consistent with docs.
- Workflow: triage first (`--parsers 'winevtx,winiis'`), then append filesystem from MFTECmd body output (`MFTECmd.exe -f $MFT --body out --bodyf mft.body --bdl C`, then `log2timeline.py --parsers 'mactime' --storage-file out.plaso mft.body`); disable `filestat` when using MFT bodyfile; export l2tcsv for Timeline Explorer; filter to the incident window in psort.

---

## 9. Common DFIR CTF flag-hiding patterns and pitfalls (synthesised from the sources above)

Patterns that recur across the writeups (with the source that demonstrates each):
1. **Flag in plain sight via strings** — always run `strings`/`strings -el` and grep the flag format before any heavy tooling (xbpt vol3 sheet; forensicskween "Plaintext Treasure": `strings capture.pcap | grep -i htb`). Also try `grep -r --text 'flag{'` over every extracted tree (Adamkadaban).
2. **Appended/embedded files** — data after PNG IEND, JPEG FFD9 or `%%EOF`; `binwalk -e`, `unzip file.png`, `7z l file.png`, `dd` carve (Aperi'Solve, Trail of Bits, pequalsnp).
3. **Deliberately corrupted headers** — wrong magic bytes, chunk names, lengths, CRCs; fix with pngcheck + dd/python and only then run stego tools (Dvd848 c0rrupt, dev.to pngcheck).
4. **IHDR dimension tampering** — CRC mismatch with valid-looking dimensions means the height was reduced to hide content below; recompute height from IDAT size or brute-force against the stored CRC (Aperi'Solve "hidden dimensions").
5. **Wrong tool for the carrier** — steghide is JPEG/BMP/WAV only; zsteg is PNG/BMP only; try the empty password first, then stegseek/rockyou (Aperi'Solve, stego-toolkit).
6. **Layered encodings** — hex -> base64 -> zlib/gzip -> XOR; PowerShell `-enc` UTF-16LE base64; decode iteratively in CyberChef (Trail of Bits, forensicskween Alien Cradle/Pandora's Bane).
7. **Alternate data streams** — `file:stream` on NTFS; mount with `stream_interface=windows` or read `$MFT` `$DATA` attributes with names; `Zone.Identifier` gives download URL (forensicskween, 0xdf BFT).
8. **Resident file content in $MFT** — tiny flag files/zip fragments live inside the 1024-byte MFT record even after deletion (0xdf BFT, andreafortuna).
9. **Renames/wipes leave USN trails** — SDelete-style `AAA.AAA` renames, FILE_CREATE->FILE_DELETE within seconds; recover original names from `$J`/`$LogFile` (andreafortuna NTFS deep dive).
10. **Obfuscated PowerShell / IEX aliases** — `(gv '*MDR*').naMe[3,11,2]-joIN''`, `iex`, `&('I'+'EX')`; 4104 script-block logs record the deobfuscated text (jon-brandy Recollection, NXLog).
11. **Typo-squatted process names and hash-named binaries** — `csrsss.exe`, `svch0st.exe`, `<sha256>.exe` in Downloads; verify parent process with pstree (jon-brandy).
12. **Hidden processes** — diff `pslist` vs `psscan`; psxview is vol2-only (xbpt).
13. **Secrets in process memory** — GPG passphrases, AES keys, browser history, clipboard; `memmap --dump --pid` then strings (forensicskween Bashic Ransomware; jon-brandy).
14. **Wireshark packet comments** (`pkt_comment`) and pcapng metadata are a favourite hiding place (jorianwoltjer).
15. **DNS exfil** — long base32/hex labels; strip header bytes (dnscat2 = first 9 bytes) and dedupe retransmits before concatenating (dmachard, BSidesSF dnscap).
16. **USB HID keystrokes** — filter by device address, ignore release/repeat frames, apply backspace (0x2A) — failing to do so yields an almost-right flag (MetaCTF, shreethaar).
17. **TLS in pcap** — look for a key log file elsewhere in the evidence (Desktop, memory dump strings for `CLIENT_RANDOM`) and inject with `editcap --inject-secrets` (PacketSafari).
18. **Registry ROT13 and binary blobs** — UserAssist names are ROT13; ShellBags/OpenSavePidlMRU are shell item binaries; decode with Registry Explorer/RegRipper, not by eye (Cyber Triage).
19. **Time zone and epoch traps** — Chrome WebKit microseconds since 1601, Apple seconds since 2001, Android ms since 1970, FILETIME 100-ns since 1601; CTF answers usually want UTC — set `--UTC`/`--output-time-zone UTC` everywhere (Foxton, Reincubate, Epifani, Plaso).
20. **WAL and transaction logs** — copy `.db-wal`/`.db-shm` and registry `.LOG1/.LOG2` with the primary file or you lose the most recent (usually the most interesting) records (SQLite.org, Belkasoft, Cyber Triage).
21. **Timestomping** — `$SI` born before `$FN` born, zeroed nanoseconds, MFT entry number out of sequence, USN `BASIC_INFO_CHANGE` (inversecos, SANS).
22. **Log clearing** — 1102/104 present means the answer is often the last events before it or the `analyse gaps` window (Chainsaw, NXLog).
23. **Over-claiming from Prefetch/ShimCache/Amcache** — these show presence/first-10-seconds activity, not proof of execution on Win10+; CTF questions about "when was X executed" usually want Prefetch last-run or BAM, not ShimCache (Cyber Triage, sethenoka).
24. **Spectrogram-first for audio**, then Morse/DTMF/SSTV/LSB; inspect >15 kHz (img2sound, Aperi'Solve).

---

## 10. Canonical cheat sheets and reference docs

| # | Reference | URL |
|---|-----------|-----|
| 1 | SANS Windows Forensic Analysis poster (artifact-by-question layout) | https://www.sans.org/posters/windows-forensic-analysis/ (blog: https://www.sans.org/blog/updated-windows-forensic-analysis-poster) |
| 2 | SANS "Ultimate List of SANS Cheat Sheets" (Memory Forensics, Hunt Evil, SIFT, REMnux, Hex & Regex, SQLite pocket guide, oledump, EZ tools, iOS apps, Malicious Documents) | https://www.sans.org/blog/the-ultimate-list-of-sans-cheat-sheets |
| 3 | SANS Eric Zimmerman's Tools Cheat Sheet | https://www.sans.org/posters/eric-zimmerman-tools-cheat-sheet/ |
| 4 | SANS Memory Forensics Cheat Sheet (Volatility) | https://www.sans.org/posters/memory-forensics-cheat-sheet/ |
| 5 | SANS Hex and Regex Forensics Cheat Sheet | https://www.sans.org/posters/hex-and-regex-forensics-cheat-sheet/ |
| 6 | Eric Zimmerman tools index (MFTECmd, PECmd, LECmd, JLECmd, SBECmd, RBCmd, RECmd, AmcacheParser, AppCompatCacheParser, EvtxECmd, SrumECmd, SQLECmd, WxTCmd, bstrings, Timeline Explorer, KAPE) | https://ericzimmerman.github.io/ |
| 7 | Volatility 3 official docs (plugin reference, Linux/Mac symbol tutorials) | https://volatility3.readthedocs.io/en/latest/ |
| 8 | Wireshark Display Filter Reference (all protocols/fields) | https://www.wireshark.org/docs/dfref/ |
| 9 | File signature (magic bytes) table — SEARCH, successor to Gary Kessler's | https://filesig.search.org/ |
| 10 | NTFS timestamp / MACB rules (SANS blog + qazeer notes) | https://www.sans.org/blog/digital-forensics-detecting-time-stamp-manipulation , https://notes.qazeer.io/dfir/windows/_artefacts_overview/timestamps |
| 11 | 13Cubed Windows Event Log cheat sheet (Security/System/PowerShell/TaskScheduler/RDP IDs + logon types) | https://cdn.13cubed.com/downloads/windows_event_log_cheat_sheet.pdf |
| 12 | DFIR.training cheats & infographics library (NTFS, FAT, EXT, MBR/GPT, $J mind map, SRUM mind map, KapeTriage mind map, RDP artifacts mind map, Key Windows Event Logs) | https://www.dfir.training/downloads/cheats-infographics |
| 13 | Plaso documentation (log2timeline/psort/pinfo) | https://plaso.readthedocs.io/en/latest/ |
| 14 | Aperi'Solve steganography decision tree | https://www.aperisolve.com/cheatsheet |
| 15 | Trail of Bits CTF Field Guide — Forensics | https://trailofbits.github.io/ctf/forensics/ |
| 16 | Chainsaw and Hayabusa READMEs/docs | https://github.com/WithSecureLabs/chainsaw , https://yamato-security.github.io/hayabusa/ |
| 17 | SQLite file format / WAL spec | https://www.sqlite.org/fileformat2.html , https://www.sqlite.org/wal.html |

---

## 11. Sources attempted but not usable (for transparency)
- HackTricks forensics pages (Windows artifacts, Volatility cheatsheet, iOS backup, Office, PDF, carving): redirected to a paywalled `tollbit.hacktricks.wiki` mirror (HTTP 402). Content in section 7.7 was reconstructed from Trail of Bits and tool conventions instead, and should be treated as secondary.
- ctftime.org writeups (IrisCTF deldeldel, BSidesSF dnscap), xpnsec dnscap, several Medium writeups (SpottedInTheWild, Litter, nasbench browsers, motasem DNS): HTTP 403 to the fetcher; only search snippets were used and are marked as such.
- Sethenoka "Windows Artefacts Guide" and Andrea Fortuna "Four tools for file carving": fetched but interpretive/high-level only — excluded from the technique lists.
