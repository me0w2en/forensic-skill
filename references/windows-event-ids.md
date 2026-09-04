# Windows event IDs that matter (DFIR CTF)

Source: 13Cubed Windows Event Log cheat sheet + NXLog. Order events by **UTC time**, never by
Record ID (each channel numbers independently — a hard trap in KDFC2026 #101/#102).

## Security (`Security.evtx`)
| ID | Meaning |
|----|---------|
| 4624 | Successful logon (see logon types below) |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff / user-initiated logoff |
| 4648 | Logon with explicit credentials (RunAs, lateral movement) |
| 4672 | Special privileges assigned (admin logon) |
| 4688 | Process created (if command-line auditing on) |
| 4689 | Process exit |
| 4697 | Service installed (Security channel equivalent of 7045) |
| 4698 / 4702 | Scheduled task created / updated |
| 4720 / 4722 / 4726 | User account created / enabled / deleted |
| 4728 / 4732 | Member added to global / local group |
| 4768 / 4769 / 4771 | Kerberos TGT / service ticket / pre-auth failed |
| 4776 | NTLM validation (on DC) |
| 4719 / 4907 | Audit policy changed / SACL changed (evasion prep) |
| 4798 / 4799 | User's / group's membership enumerated (recon) |
| 5140 / 5145 | Network share accessed / detailed object check |
| 1102 | **Security audit log cleared** (anti-forensics) |

### Logon types (field of 4624/4625)
2 console · 3 network · 4 batch · 5 service · 7 unlock · 8 network cleartext ·
9 RunAs alternate creds · **10 RDP** · 11 cached · 12 cached RDP · 13 cached unlock.
Type 10 from a non-jump host, or a burst of type 3 from one host to many = lateral movement.

## System (`System.evtx`)
| ID | Meaning |
|----|---------|
| 7045 | New service installed (ImagePath is the payload) |
| 7034 / 7009 | Service crashed / start timeout |
| 104 | Event log cleared (non-Security logs) |

## PowerShell
- Classic `Windows PowerShell.evtx`: 400/600 engine/provider start.
- `Microsoft-Windows-PowerShell/Operational`: **4104 script block text** (auto-logged as Warning
  for "suspicious" scripts even without logging policy — deobfuscated content lands here),
  4103 module/pipeline. Watch for `-nop -w hidden -ep bypass -enc <base64 UTF-16LE>` then nested
  `Base64 → Gunzip → IEX`.

## Scheduled Tasks (`Microsoft-Windows-TaskScheduler/Operational`)
106 registered · 140 updated · 141 deleted · 100 started · 102 finished · 200/201 action run/completed.

## RDP
- `TerminalServices-LocalSessionManager/Operational`: 21 logon · 22 shell start · 23 logoff · 24 disconnect · 25 reconnect.
- `TerminalServices-RemoteConnectionManager/Operational`: 1149 network auth ok · 261 listener got connection.
- `TerminalServices-RDPClient/Operational` (SOURCE box): 1029 = Base64(SHA256(username)).

## WMI (`Microsoft-Windows-WMI-Activity/Operational`)
5857/5858 operation (5858 fired when malware's `MSAcpi_ThermalZoneTemperature` anti-VM WQL ran — KDFC2023 #253) · 5860/5861 permanent event consumer registered (fileless persistence).

## Windows Defender/Operational
1116 malware detected · 1117 action taken.

## Cross-platform tooling on this host
```bash
evtx_dump --format json Security.evtx | jq 'select(.Event.System.EventID==4624)'
chainsaw hunt evtx_dir/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/ --csv -o out
chainsaw search -t 'Event.System.EventID: =4104' evtx_dir/
chainsaw analyse gaps ./evtx --json -o gaps.json     # find cleared/missing ranges
hayabusa csv-timeline -d ./evtx -o timeline.csv --UTC -m low
hayabusa logon-summary -d ./evtx
```
Windows-only (run via Windows VM or `dotnet`): EvtxECmd, MFTECmd, PECmd, Registry Explorer/RECmd, SrumECmd.
