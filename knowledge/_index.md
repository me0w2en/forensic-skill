# Knowledge base index

Distilled, reusable forensic-CTF knowledge. **Grep this corpus for your artifact type before
you start a case** — most challenge shapes have a precedent here.

## Files
> `kdfc-*.md` below are **local-only, git-ignored** (private distilled writeups). The skills work without them; see `knowledge/README.md`.

- **kdfc-2023-part1.md** — KDFC 2023 challenges 101–202, distilled (team kimbabasaksaksak).
  Dashcam MP4/DVR carving, PE Rich Header/PDB, audio STFT diff, Bluetooth HID/A2DP, Android live,
  DVR FourCC walker, lost-partition + format-time derivation, ReFS `$Logfile` differential method.
- **kdfc-2023-part2.md** — KDFC 2023 challenges 251–401. Dropbox `config.dbx` inode key, KeePass
  CVE-2023-32784, multi-stage stealer RE (Amadey/Lumma/Vidar/Raccoon), APK repackaging + AES-CBC,
  MP4/VR + movi-in-mp4 + what3words, Google Workspace leak, Exodus wallet in memory + Etherscan
  tracing, Android FBE (fbekeyfind + AES-XTS).
- **kdfc-2026.md** — KDFC 2026 (team Hspace 야호~). Fileless PowerShell + registry XOR, IIS/MSSQL
  intrusion with planted hashes, Docker save-vs-export diffing, AI-service app forensics (ChatGPT/
  Firefly/Claude), LUKS2 key from VMEM (aeskeyfind), TRON honeypot multisig, AWS IR log correlation,
  CRIU/K8s checkpoint + PostgreSQL page carving, Python eval-injection + SQLite freelist, Ethereum
  proxy rug pull. **Read the "what changed" section: 2026 leans heavily to cloud/container/Linux/blockchain.**
- **web-dfir-sources.md** — ~50 trustworthy external sources across 9 categories, each with concrete
  commands/paths/event IDs, plus 24 flag-hiding patterns and 17 canonical cheat sheets. SANS, 13Cubed,
  andreafortuna, 0xdf, inversecos, Volatility/Plaso/SQLite docs, Aperi'Solve, Trail of Bits.
- **journal.md** — your own case write-backs (append after every case via case-ops).

- **journal.md** now includes the KDFS-2023 end-to-end test (see `email-clients` skill, added from that gap).

## Cross-cutting meta-heuristics (from all four)
1. **Verify hashes first**, work on copies, originals read-only.
2. **Timezone per problem** — KDFC toggles UTC±9; read the prompt every time.
3. **Outlier hunting** — dump every timestamp/size/cert-date/hash of a set, find the one that differs.
4. **Cross-corroborate** every key fact with a second artifact (Timeline+PCA, Prefetch+USN, SI+FN).
5. **Header before extension** — a `.pptx`/`.png` starting `MZ` is a PE.
6. **Wrong box for the container** = hidden data (AVI `movi` in MP4; `mdat` without `moov`).
7. **Secrets live in RAM** more reliably than on disk (wallet/LUKS/FBE/KeePass keys, passwords).
8. **Config-first for loaders** — decode the malware's own JSON/XOR config for URLs, keys, anti-VM lists.
9. **Don't trust logged IOCs** — recompute PE hashes; a logged Sysmon hash can be planted (KDFC2026 #102).
10. **Grade evidence** direct / correlation / withheld; stating a limit is a valid answer.
11. **Ground-truth replication** — for undocumented formats (ReFS `$Logfile`, vendor DVR), reproduce
    events in a VM and diff.
12. **Memory-first & structure-aware carving** — 2026 secrets often only exist in VMEM/pagefile/CRIU pages.
