---
name: memory-forensics
description: |
  RAM and volatile-state forensics: Windows/Linux memory images (.raw/.mem/.dmp/.lime/.vmem/.vmss),
  VMware suspend sets, hiberfil/pagefile, ELF core dumps, CRIU pages-*.img. Volatility 3 process/network/
  injection/registry/credential analysis, plus NON-volatility key recovery — LUKS2/AES-XTS volume keys and
  Android FBE master keys pulled straight out of RAM with aeskeyfind/fbekeyfind, and passwords that only ever
  live in process memory (KeePass, Exodus wallet, GPG passphrase). Use when the answer is a process, injected
  code, a socket, or a secret/key that exists only in volatile memory.
  Trigger keywords: memory, RAM, 메모리, 메모리 포렌식, volatility, vol3, .mem, .raw, .dmp, .vmem, .vmss, .lime,
  hiberfil.sys, pagefile.sys, ELF core, CRIU, pages-1.img, malfind, netscan, hashdump, lsadump, aeskeyfind,
  fbekeyfind, LUKS2, AES-XTS, FBE, KeePass, CVE-2023-32784, Exodus wallet, GPG passphrase, dwarf2json, banners.
---

# Memory & Volatile-State Forensics

## ACTION REQUIRED
1. `NOW` Confirm you came through `forensics-router` and `work/<case>/` exists (hashes verified, answer **timezone** recorded in `scope.md`). If not → `case-ops`/`forensics-router` first.
2. `NOW` Read `../../tool-index.md`. Primary is `vol` (Volatility 3, installed as `vol` — not `vol.py`). Note missing tools you may need: `aeskeyfind`, `fbekeyfind`, `dwarf2json`, `crit` — see Tools for install/fallback.
3. `NEXT` Identify the dump: `file dump.*`; `strings -a dump | head`. Windows → `vol -f dump windows.info`. Linux → `vol -f dump banners.Banners`. `.vmss/.vmem` pair → analyze the `.vmem`, **never boot the VM** (discarding suspend state destroys the RAM).
4. `NEXT` Pick the branch: Windows triage / Linux triage / raw-key recovery (aeskeyfind/fbekeyfind) / structure carving (ELF core, CRIU pages). A "won't open by passphrase" crypto volume from `disk-image` with a matching RAM image lands here.
5. `ACT` Run the workflow; dump artifacts into `work/<case>/mem-out/`; log every command + finding to `work/<case>/timeline.md`. Convert every timestamp to the challenge timezone.

## When to use / hand off
| If the artifact is really… | Go to |
|----------------------------|-------|
| A disk/volume image (E01/dd/vmdk), not the RAM | `disk-image` |
| A LUKS/BitLocker container to mount once you have the key | `disk-image` (mount read-only) |
| CRIU checkpoint *container/pod structure* (spec.dump, crit object graph) | `linux-container-cloud` (but raw page carving below is yours) |
| Android `userdata.img` decryption once FBE keys are recovered | `mobile-artifacts` / `disk-image` (ext4-fbe TSK) |
| A pcap / USB-HID / Bluetooth capture | `network-forensics` |
| A dumped file that won't parse (PE, SQLite, asar) | `file-format-carving` |
| Blockchain address/tx tracing after you extract a wallet password | `blockchain-forensics` |

## Tools
- `vol` (memory) — Volatility 3 CLI. `vol -f <img> <plugin>`; `-o <dir>` sets dump output dir; `--clear-cache` after adding symbols. Plugin help: `vol -f img <plugin> --help`.
- `volshell` (memory) — interactive Volatility shell for ad-hoc struct/address walking.
- `strings` + `xxd` (triage) — `strings -el` = UTF-16LE (Windows widechar); `strings -a -t x` = print byte offsets.
- `bulk_extractor` (carving) — `bulk_extractor -o out img` runs on raw RAM too; `aes_keys.txt` scanner finds AES key schedules, `email.txt`/`url.txt`/`json.txt` catch secrets. Good first pass on any blob.
- `photorec` / `binwalk` (carving) — carve embedded files (PE/SQLite/JPEG) out of a memory dump or an ELF core.
- `yara` (malware) — `vol ... windows.vadyarascan --yara-file r.yar` / `linux.vmayarascan`; standalone `yara r.yar dump`.
- **`aeskeyfind`** — MISSING on this host. Recovers AES key schedules from a RAM image (LUKS volume key, FBE material). Build: `git clone https://github.com/makomk/aeskeyfind && cd aeskeyfind && make` (needs a Linux/WSL/Docker box; `docker run --rm -v "$PWD":/d -w /d ubuntu bash -lc 'apt update && apt install -y build-essential libssl-dev && make'`).
- **`fbekeyfind`** — MISSING. Android FBE master-key finder (FAU "One Key to Rule Them All"): `curl -O https://faui1-files.cs.fau.de/public/one_key_to_rule/fbekeyfind.tar.gz` then build (Linux). Pair with the **ext4-fbe TSK fork** (`faui1-gitlab.cs.fau.de/tobias.gross/sleuthkit-ext4-fbe`).
- **`dwarf2json`** — MISSING. Builds Volatility 3 Linux ISF symbols from a `vmlinux`+dbgsym: `git clone github.com/volatilityfoundation/dwarf2json` (Go). Alternative: pre-built JSON from the `volatilityfoundation/volatility3-symbols` repo.
- **`crit`** (CRIU) — MISSING. `crit show pages-1.img`/`crit x <dir> ps`. Install `pip install crit` (part of `criu`). For the container object graph hand off to `linux-container-cloud`; raw page carving here needs only Python.
- `python3` with `pycryptodome` is MISSING (used for XTS/PBKDF2 validation) — `uv pip install pycryptodome` into a throwaway venv, or use `openssl`/`cryptsetup` to validate.

## Workflow

### Phase 0 — Identify & preserve
```bash
file dump.*                                     # 'data' is normal for raw RAM
xxd -l 32 dump.raw                              # LiME header 'EMiL'; ELF core '\x7fELF'; MS crashdump 'PAGEDU64'
# VMware suspend set: DO NOT boot. Analyze the .vmem (raw guest RAM). .vmss holds CPU/dev state.
strings -a -t x guest.vmss | grep -E 'cleanShutdown|checkpoint.vmState'   # confirm live suspend preserved
vol -f guest.vmem windows.info                  # vol reads .vmem directly; or convert: none needed
# Windows crash/hiber: vol handles hiberfil.sys and crashdumps natively.
```

### Phase 1 — Windows triage (Volatility 3)
```bash
vol -f mem.raw windows.info                     # build, arch, SystemTime = capture time (a common answer)
vol -f mem.raw windows.pslist                   # live EPROCESS list (PID/PPID/create time/exit)
vol -f mem.raw windows.psscan                   # pool scan — finds exited/hidden procs
vol -f mem.raw windows.pstree                   # parent/child; spot cmd.exe->powershell.exe, lolbins
vol -f mem.raw windows.cmdline                  # full command lines (encoded PowerShell -enc)
vol -f mem.raw windows.netscan                  # sockets/connections (owner PID, remote IP:port) — C2
vol -f mem.raw windows.netstat                  # alt; netscan is more reliable for CTF dumps
vol -f mem.raw windows.dlllist --pid N
vol -f mem.raw windows.handles --pid N | grep -iE 'flag|\.txt|\.kdbx|mutant'
```
Timezone: `windows.info` SystemTime is UTC — convert to the challenge tz before answering.

### Phase 2 — Injected / hidden code
```bash
# NOTE: in vol3 >= 2.11 malware plugins moved to the windows.malware.* namespace.
vol -f mem.raw windows.malware.malfind          # (older vol: windows.malfind) RWX VADs, look for 'MZ'
vol -f mem.raw windows.malware.malfind --dump -o mem-out   # dump the injected regions
vol -f mem.raw windows.vadyarascan --yara-file rules.yar --pid N
# Hidden processes: pslist (live) vs psscan (pool) diff — no psxview in vol3.
comm -13 <(vol -f mem.raw windows.pslist | awk '{print $1}' | sort -u) \
         <(vol -f mem.raw windows.psscan | awk '{print $1}' | sort -u)   # PIDs only psscan sees
```

### Phase 3 — Files & full-process memory
```bash
vol -f mem.raw windows.filescan | grep -iE 'flag|secret|pass|\.txt|\.kdbx|wallet|seed'
vol -f mem.raw -o mem-out windows.dumpfiles --virtaddr 0x11e0d16f0     # pull one file object
vol -f mem.raw -o mem-out windows.dumpfiles --pid N                    # exe + loaded DLLs
vol -f mem.raw -o mem-out windows.memmap --dump --pid N               # ENTIRE process memory
strings -a mem-out/*.dmp | grep -i flag
strings -el mem-out/*.dmp | grep -i flag                              # UTF-16LE variant
```
`cmdscan`/`consoles` are unreliable on Win7/10 — instead dump `conhost.exe`/`cmd.exe`/`powershell.exe` with `memmap --dump` and grep. Clipboard: dump `explorer.exe` and grep.

### Phase 4 — Registry & credentials
```bash
vol -f mem.raw windows.registry.hivelist
vol -f mem.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
vol -f mem.raw windows.registry.printkey --key "ControlSet001\Control\ComputerName\ComputerName"
vol -f mem.raw windows.hashdump              # user:RID:LM:NTLM  -> john/hashcat
vol -f mem.raw windows.lsadump               # LSA secrets (DPAPI, service creds)
vol -f mem.raw windows.cachedump             # domain cached creds
```

### Phase 5 — Linux triage
```bash
vol -f mem.lime banners.Banners              # exact kernel banner string (identifies the build)
strings mem.lime | grep -B4 DISTRIB_DESCRIPTION   # distro fallback; also /etc/os-release, /etc/issue
# Symbols: drop matching ISF JSON into <vol_pkg>/symbols/linux/ (auto-detected), then:
vol -f mem.lime --clear-cache linux.pslist
# No prebuilt ISF? build one: install linux-image-<ver>+dbgsym, dwarf2json linux --elf vmlinux > x.json
vol -f mem.lime isfinfo.IsfInfo             # list loaded symbol tables; banner must match EXACTLY
vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash                  # bash history straight from RAM (frequent flag source)
vol -f mem.lime linux.pslist ; vol -f mem.lime linux.lsof ; vol -f mem.lime linux.malfind
vol -f mem.lime linux.ip.Addr ; vol -f mem.lime linux.kmsg
# Community plugin: GPG symmetric passphrase in RAM
vol -f mem.lime linux.gpg_full.GPGItem      # then: gpg --batch --passphrase <recovered> -d file.gpg
```

### Phase 6 — Secrets that only live in process memory
The theme: an app holds a plaintext password/passphrase in its heap. Anchor the search on a **stable nearby string** and grep both ASCII and UTF-16.
```bash
# Exodus wallet unlock password (KDFC2023 #306): anchor on the asar resource path.
strings -a mem.raw | grep -n 'app.asar/src/static/wallet.html'   # password sits near this line
# ...dump the Exodus PID and inspect around the anchor. NB the password may be Korean-IME gibberish
#    (a Latin-looking gibberish string can be a Hangul-keyboard-layout password) — do NOT dismiss it as noise.

# KeePass master key (KDFC2023 #252, CVE-2023-32784): leaked from a KeePass process dump,
# but the FIRST character is always missing and the 2nd is ambiguous.
#   git clone https://github.com/CMEPW/keepass-dump-masterkey
#   python3 keepass-dump-masterkey.py KeePass.DMP   # -> ●^_^@digitalforensicchallenge2023!@#123
# Brute-force the leading char against the .kdbx (john/keepass2john or the KeePass GUI).
```

### Phase 7 — RAW KEY RECOVERY (non-Volatility): keys that live only in RAM
This is what makes memory decisive. When a crypto volume can't be opened by passphrase but the host RAM was captured while the volume was **mounted/unlocked**, the raw symmetric key is in RAM.

**7a. LUKS2 / dm-crypt AES-XTS volume key from VMEM (KDFC2026 #151).** The volume key is two AES-256 keys (512-bit XTS). Confirm the volume was open at capture, then recover the key with `aeskeyfind` and validate against the LUKS2 PBKDF2 digest.
```bash
# 0. Confirm the container was open at suspend (strings in the VMEM):
strings -a -t x guest.vmem | grep -E 'aes-xts-plain64|logon:cryptsetup|CRYPT-LUKS2|dm create'
# 1. Get the LUKS2 metadata (from disk-image side) to validate candidates:
cryptsetup luksDump vault.img                 # cipher aes-xts-plain64, keyslot Argon2id
cryptsetup luksDump --dump-json-metadata vault.img   # salt, iterations, digest for the volume-key check
# 2. Harvest AES key schedules from RAM:
aeskeyfind -v -q guest.vmem                    # prints AES-256 candidate keys (schedules)
# 3. Try every ordered pair of candidate 32-byte halves; PBKDF2-HMAC-SHA256 with the LUKS salt/iterations
#    must reproduce the stored digest. Only one ordered 64-byte key matches. (validate half ORDER — XTS
#    key1||key2 != key2||key1). Then direction-check with cryptsetup:
cryptsetup open --type luks2 --test-passphrase --volume-key-file key64.bin vault.img   # exit 0 = correct
# 4. Decrypt read-only and hand the mapped device to disk-image:
sudo cryptsetup open --readonly --type luks2 --volume-key-file key64.bin vault.img v_ro
sudo mount -t ext4 -o ro,noload /dev/mapper/v_ro /mnt/v   # noload = no journal replay (evidence-safe)
```

**7b. Android FBE master keys from a kernel ramdump (KDFC2023 #401).** Pixel/Samsung File-Based Encryption keys live in RAM, not on disk.
```bash
# Pre-req: build aeskeyfind AND the ext4-fbe TSK fork; get fbekeyfind (FAU toolkit).
fbekeyfind ramdump > fbe.candidates            # per Key Descriptor, take the TOP-2 most-frequent keys
# fbe.keys lines: <descriptor>:<key-a>:<key-b>  e.g. ec34dd2d7a20bf2e:a45d06ab...:6b65d320...
fls  -K fbe.keys -rF -f ext4 userdata.img       # decrypted filenames (ext4-fbe fork only)
istat -K fbe.keys -f ext4 userdata.img <inode>  # FBE xattrs: Content Mode(1=AES-256-XTS), Nonce, Descriptor
# Per-file DEK = AES-128-ECB encrypt(MasterKey) using the file's 16-byte Nonce AS THE AES KEY:
python3 - <<'PY'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
def derive(master, nonce):   # nonce is the AES key, master is the plaintext
    e=Cipher(algorithms.AES(nonce),modes.ECB()).encryptor(); return e.update(master)+e.finalize()
PY
# Decrypt content with AES-256-XTS; TWEAK = logical block number (starts 0, +1/block), 16 bytes LITTLE-ENDIAN.
# blkcat -f ext4 userdata.img <physblk> feeds ciphertext; truncate to file size at the end.
```
Master keys are chosen by **occurrence frequency** in RAM (top-2 per descriptor), then validated by a successful decrypt. The XTS tweak is the *logical* block index (LE 16 bytes), not the physical block id.

### Phase 8 — ELF core dumps & CRIU pages (structure-aware carving)
For Kubernetes/CRIU checkpoints, the container/pod object graph belongs to `linux-container-cloud` (`crit show spec.dump`, the `pstree→core→mm→files` chain, and the `memfd/pagemap-shmem/files` chain that attributes a raw `pages-N.img` to a process). Your job is the raw memory carving of the identified page file.
```bash
# ELF core: carve embedded artifacts and grep secrets
binwalk -e app.core ; photorec /d out app.core
strings -a app.core | grep -iE 'flag|BEGIN .*PRIVATE KEY|password'
# CRIU: once linux-container-cloud proves pages-1.img is (e.g.) PostgreSQL shared memory —
# base64-blob scan across byte alignments (C2 addr, ransom text often live as DB tuples):
python3 - <<'PY'
import re
d=open('pages-1.img','rb').read()
for shift in range(4):
    for m in re.finditer(rb'[A-Za-z0-9+/]{200,}={0,2}', d[shift:]):
        import base64
        try: dec=base64.b64decode(m.group())
        except Exception: continue
        if sum(32<=c<127 for c in dec)/max(1,len(dec))>0.9:
            print(shift, m.start()+shift, dec[:120])
PY
# Reverse-verify a hypothesis (e.g. an IP:port) by encoding it and grepping the raw page:
printf ' <attacker-ip>:<port>' | base64 | tr -d '=\n'   # then grep -aob -F <b64> pages-1.img
```
PostgreSQL page structure (to recover a tuple, not just string-match): 8K page, PageHeader `<QHHHHHHI` with `version==0x2004`, validate `24<=lower<=upper<=special<=8192`; HeapTupleHeader `hoff` at +22; varlena length `>>2`. Verify a carved offset sits in a single CRIU present-range (`pagemap-shmem-*.img`) before trusting it.

## Flag-hiding checklist
- Capture time itself is often an answer — `windows.info` SystemTime / `linux.boottime` (convert tz).
- `strings -el` (UTF-16LE) before anything heavy; Windows secrets are widechar. Also plain `strings | grep -i flag`.
- Hidden/terminated process only in `psscan` (not `pslist`) — diff them.
- Injected code: RWX VAD with an `MZ` header via `windows.malware.malfind`.
- `windows.cmdline` for base64/`-enc` PowerShell; decode it.
- Sockets to attacker infra in `windows.netscan` (owner PID → dump that process).
- Passwords in a specific app's heap: KeePass master key (minus 1st char, CVE-2023-32784), Exodus wallet password near the `app.asar/.../wallet.html` string, GPG passphrase via `linux.gpg_full`.
- Bash history (`linux.bash`) — commands the attacker typed.
- Raw crypto keys: LUKS2/AES-XTS volume key (`aeskeyfind` over VMEM) and Android FBE master keys (`fbekeyfind` over ramdump) — the volume/disk was **never crackable by passphrase**; the key was in RAM.
- Secrets carved from CRIU `pages-*.img` / ELF core as base64 blobs or DB tuples.
- `bulk_extractor` `aes_keys.txt`, `url.txt`, `json.txt`, `email.txt` on the raw dump.

## Pitfalls
- **Never boot a VMware suspend set** — resuming/discarding state overwrites the `.vmem` and destroys the only copy of the key. Copy the `.vmem`/`.vmss` and analyze offline.
- vol3 renamed malware plugins to `windows.malware.*` (>=2.11). If `windows.malfind` errors, try `windows.malware.malfind`. Check `vol --help | grep malfind`.
- Linux symbols must match the **exact** kernel banner; a near-miss silently yields empty/garbage output. Verify with `isfinfo.IsfInfo`; patch the base64 banner in the ISF JSON and `--clear-cache` if it differs.
- AES-XTS key is TWO AES-256 keys; **half order matters** — validate both orderings with `cryptsetup --test-passphrase --volume-key-file` (exit 0 vs 2).
- FBE XTS tweak is the *logical* block number (LE, 16 bytes), NOT the physical block id used to `blkcat` the ciphertext.
- KeePass CVE-2023-32784 leak always misses char 1 and blurs char 2 — you MUST brute-force, don't submit the partial.
- Don't assume a `pages-N.img` is a given process's memory — prove it via the memfd/shmid chain (linux-container-cloud) before carving.
- Mount recovered filesystems `-o ro,noload`/`norecovery` — journal replay mutates evidence.
- `cmdscan`/`consoles`/`clipboard` are version-flaky on modern Windows — dump the process and grep instead.
- SystemTime and all vol timestamps are UTC. Convert to the challenge timezone before answering.

## Worked precedents
- **KDFC2026 #151 Pull the Plug** — LUKS2 AES-XTS volume key recovered from a VMware `.vmem` with `aeskeyfind`, ordered key-half pair validated against the LUKS2 PBKDF2-SHA256 digest; do NOT boot the VM. See.
- **KDFC2023 #401 Find an illegally filmed image** — Android FBE master keys from a Pixel 3 kernel ramdump via `fbekeyfind`+`aeskeyfind`; per-file DEK = `AES-ECB(masterkey, key=nonce)`, decrypt AES-256-XTS with LE logical-block tweak. See.
- **KDFC2023 #306 Coin Chaser** — Exodus wallet unlock password recovered in cleartext from process memory, anchored on the `app.asar/.../wallet.html` path string (password was Hangul-IME gibberish). See.
- **KDFC2023 #252 Password Stealer** — KeePass master key leaked from a memory dump via CVE-2023-32784 (missing first char), brute-forced to full key. See.
- **KDFC2026 #201 (raw carving portion)** — C2 address and ransom note carved from a CRIU PostgreSQL `pages-1.img` as base64 / HeapTuple structures. See.

## References
- `../../knowledge/web-dfir-sources.md` §2 (Volatility 3 cheat sheets, Linux ISF/dwarf2json, GPG-in-RAM, malware namespace) and §9 (flag-hiding patterns #11–#14).
- `../../references/*.md` (magic-bytes, timestamps) if present.
- Volatility 3 docs: https://volatility3.readthedocs.io/en/latest/
- vol3 CTF cheat sheet: https://xbpt.gitlab.io/ctf/volatility3-cheatsheet.html
- onfvp vol3 cheat sheet: https://blog.onfvp.com/post/volatility-cheatsheet/
- aeskeyfind (AES key schedules from RAM): https://citp.princeton.edu/our-work/memory/ ; FAU FBE toolkit "One Key to Rule Them All".
- SANS Memory Forensics cheat sheet: https://www.sans.org/posters/memory-forensics-cheat-sheet/
