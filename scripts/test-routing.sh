#!/usr/bin/env bash
# test-routing.sh — regression: hint -> expected PRIMARY route id.
# Add a case every time routing surprised you.  Run in CI.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
pass=0; fail=0
while IFS='|' read -r expected hint; do
  [ -z "$expected" ] && continue
  case "$expected" in \#*) continue;; esac
  got=$("$ROOT/scripts/route.sh" --json "$hint" | python3 -c 'import json,sys; print(json.load(sys.stdin)["primary"]["id"])')
  if [ "$got" = "$expected" ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL  want $expected got $got  <- $hint"; fi
done <<'CASES'
# expected | hint
R1|KimPC_64GB_NVME.E01 EWF/Expert Witness/EnCase image file format
R1|PartitionFinder.7z contains a raw disk image, find all deleted partitions
R1|draft_server.001 ReFS volume, which files were renamed and deleted
R1|toy_story.vmdk mount read only and pull the flask app
R1|vault.img LUKS2 encrypted header, password fails
R2|memory.7z memdump of the exodus wallet process, find the password
R2|DFC2026_L.vmem 1GiB VMware suspend memory, run aeskeyfind
R2|ramdump from Pixel 3 recover FBE master keys
R2|memdump.14836 ELF core file of node process
R2|analyse this hiberfil.sys and pagefile.sys
R3|evidence1.pcap bluetooth HCI capture with mouse HID reports
R3|capture.pcapng follow the tcp stream and export the http objects
R3|usb keyboard pcap decode keystrokes
R4|Sysmon-Operational.evtx and PowerShell-Operational.evtx find the suspicious powershell -enc
R4|when was the file wiping tool installed and run on this Windows 11 machine, check ActivitiesCache.db and PcaAppLaunchDic.txt
R4|NTUSER.DAT UserAssist and ShellBags for user activity
R4|Prefetch and Amcache to prove execution
R4|Security.evtx 4624 logon type 10 from external IP
R5|webserver.tar docker save and webserver_ts.tar docker export find the dropped malware
R5|cloudtrail.json guardduty findings vpc flow logs which IAM access key was compromised
R5|kubernetes CRIU checkpoint dump pstree.img pages-1.img
R5|auth.log and bash_history on the ubuntu server
R6|SM-F721N_Live.zip android logical dump find accounts and wifi ssid
R6|conversations.db from the ChatGPT android app, and claude cache db in WAL
R6|Manifest.db iTunes backup sms.db
R6|Chrome History sqlite and Login Data
R7|Seoul.mp4 has a movi box inside an MP4 and equirectangular 360 video
R7|flag.png check LSB with zsteg
R7|original.wav vs modified.wav where is the fake voice inserted
R7|dashcam REC_1970_01_01.MP4 black video but audio plays, mdat size zero
R7|problem.img from a 2-channel DVR does not play, custom FourCC 00VI 00VP
R8|SI and FN timestamps mismatch on wmiapsvr.exe, timestomping?
R8|build a super timeline with plaso log2timeline and psort
R8|convert this 100ns FILETIME tick value 130000000000000000 to KST
R9|recover TRON wallet from leaked mnemonic on nile testnet, why can't withdraw usdt
R9|Sepolia upgradeable proxy upgradeTo rug pull, which selector drains funds
R9|trace the ETH from 0x0000000000000000000000000000000000001234 on etherscan
R11|outlook.ost from AppData Local Microsoft Outlook, find the ransom email
R11|readpst the suspect.pst and list sender recipient of every extortion mail
R11|recover deleted emails from the pst mailbox
R10|start a new case for kdfc 2026 problem 151
R10|write up the report and review the evidence chain
R0|final-final-problem.img is just 'data' according to file, avi chunks with wrong sizes
R0|corrupted zip archive, fix the header
R0|presentation.pptx is actually a PE, and Files.zip contains two exe with rich headers
R0|hwp document with embedded ole object
CASES
echo "routing tests: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
