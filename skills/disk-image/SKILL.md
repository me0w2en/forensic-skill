---
name: disk-image
description: |
  Disk and volume forensics: acquire/mount forensic images read-only, enumerate partitions and
  filesystems, recover deleted files and lost partitions, derive per-filesystem format time, attribute
  a volume to one-or-many machines, and open crypto containers. Enter when handed a whole-disk or
  volume image (E01/dd/raw/vmdk/vhd/vhdx/ad1), a partition dump, or a LUKS/BitLocker container, and the
  question is about deleted/renamed files, partition recovery, format/creation time, filesystem
  journaling, or which user/machine touched a volume.
  Trigger keywords: disk image, 디스크 이미지, E01, EWF, dd, raw, vmdk, vhd, vhdx, ad1, partition, 파티션,
  mmls, fls, icat, istat, tsk_recover, sleuthkit, $MFT, $UsnJrnl, $LogFile, NTFS, FAT, exFAT, ext4, ReFS,
  APFS, recycle bin, SID, format time, testdisk, photorec, carving, LUKS, BitLocker, cryptsetup, 복구.
---

# Disk & Volume Image Forensics

You were handed a disk/volume image or a crypto container. Mount nothing read-write. Enumerate the
layout, answer from filesystem metadata first, carve only as last resort.

## ACTION REQUIRED (do now, do not stop to confirm)

1. `NOW`  Confirm you arrived via `forensics-router` and a `work/<case>/` exists: `scope.md` has the
   asked question, `answer_format`, and **timezone** recorded; provided MD5/SHA256 were recomputed and
   `verified: true`. If not, go back to the router (`scripts/case-init.sh`, `scripts/identify.sh`).
2. `NOW`  Read `../../tool-index.md`; pick the available variant (Sleuth Kit, libewf, testdisk/photorec
   are ✅ on this host; `qemu-nbd`/`cryptsetup`/`aeskeyfind` need Linux/WSL — see Tools).
3. `NEXT` Identify the container: `ewfinfo`/`qemu-img info`/`file`, then `mmls` the image to get the
   partition table and per-partition **start sector** (you pass it to every later `-o`).
4. `NEXT` Answer from metadata: `fls`/`istat`/`icat` for files+timestamps; derive format time per FS;
   `$RECYCLE.BIN\<SID>` for machine attribution. Recover deleted/lost data only when asked.
5. `ACT`  Extract, hash, convert every timestamp to the challenge timezone, and log each command +
   finding to `work/<case>/timeline.md`. Grade each conclusion `direct|correlation|withheld`.

## When to use / hand off

| If the artifact is really… | Go to |
|---|---|
| Deep Windows analysis of $MFT/$UsnJrnl/$LogFile, EVTX, registry, Prefetch | `skills/windows-artifacts/` (this skill is only the entry point) |
| The crypto key "may be in RAM" — VMEM/hiberfil/pagefile present alongside the container | `skills/memory-forensics/` (aeskeyfind/volatility recover the key, then come back) |
| A single odd file, archive, OOXML/HWP/PDF, PE-in-disguise, polyglot, magic-byte repair | `skills/file-format-carving/` |
| Media that "won't play", stego in an image/audio/video | `skills/multimedia-stego/` |
| Timestomping / super-timeline / wiper questions | `skills/anti-forensics-timeline/` |
| Android/iOS logical dump, app SQLite | `skills/mobile-artifacts/` |

## Tools (install-name from tool-index.md → what it's for)

- `ewfinfo` ✅ — EWF/E01 metadata (acquisition hash, chunk size, media size). Verify the stored hash.
- `ewfmount` ✅ — expose an E01 as a raw `ewf1` file via FUSE (needs macFUSE on macOS). TSK can also read
  `.E01` directly, so mounting is often unnecessary.
- `ewfexport` ✅ — convert E01 → raw/dd (`ewfexport -t out image.E01`).
- `qemu-img` ✅ — inspect/convert vmdk/vhd/vhdx/qcow2: `qemu-img info x.vmdk`, `qemu-img convert -O raw`.
- `qemu-nbd` (ships with qemu; **Linux/WSL only** — needs the `nbd` kernel module) — read-only block
  device for vmdk/vhd so `mmls`/`mount` see it live. macOS fallback: `qemu-img convert -O raw` then run TSK on the raw.
- `mmls` ✅ — partition table + start sectors (DOS/GPT/BSD/Mac). First command on any whole disk.
- `fls` ✅ — list files/dirs (incl. deleted, `-d`) with inode/MFT numbers; `-r -p` recursive full paths.
- `icat` ✅ — copy file contents out by inode/MFT number.
- `istat` ✅ — dump one inode's metadata incl. all MAC timestamps.
- `blkls` ✅ — dump unallocated (slack/free) blocks for carving (`blkls img > unalloc.dd`).
- `tsk_recover` ✅ — bulk-export allocated (`-a`) or deleted (default) files to a directory.
- `mactime` ✅ — turn an `fls -m` / `ils -m` bodyfile into a sorted timeline.
- `testdisk` ✅ — recover lost/deleted partitions, rebuild boot sectors (the FOSS "Scan For Lost Partitions").
- `photorec` ✅ — signature-based file recovery when the filesystem is gone.
- `cryptsetup` (**Linux/WSL only**; not on this host) — LUKS/LUKS2 dump & open. macOS fallback: WSL/Linux VM or `docker run` a Linux image with the container bind-mounted.
- `aeskeyfind` (**Linux; memory tool**) — recover AES keys from a RAM image → hand off to memory-forensics.
- BitLocker: `dislocker` (Linux/brew) or Windows `manage-bde`; the FVEK may be in RAM (hand off).

## Workflow

### Phase 1 — Identify & verify the container
```bash
cd work/<case>
ewfinfo evidence/disk.E01          # media size, stored MD5/SHA256, acquiry date
file evidence/*                    # raw/dd/ad1/vmdk fingerprint
qemu-img info evidence/disk.vmdk   # vmdk/vhd/vhdx: virtual size, backing files, snapshots
# Recompute the acquisition hash and compare to ewfinfo / the challenge text:
sha256sum evidence/disk.E01 | tee -a timeline.md
```
TSK reads E01 directly (built with libewf). For vmdk/vhd either NBD (Linux) or convert:
```bash
qemu-img convert -p -O raw evidence/toy.vmdk work/toy.raw     # macOS-safe
# Linux/WSL read-only block device instead of converting:
sudo modprobe nbd max_part=16
sudo qemu-nbd --read-only --format=vmdk --connect=/dev/nbd0 evidence/toy.vmdk
sudo blockdev --getro /dev/nbd0    # must print 1
```

### Phase 2 — Partition table & filesystem map
```bash
mmls evidence/disk.E01             # note Start sector of each partition (the -o value)
# For each partition, identify the FS and read the volume/boot record:
fsstat -o 4462592 evidence/disk.E01        # FS type, volume serial, cluster size, $MFT/journal info
```
Keep the **start sector** for every partition; every `fls/icat/istat/blkls` below needs `-o <start>`.

### Phase 3 — Enumerate files & timestamps (answer from metadata first)
```bash
fls -r -p -o 4462592 evidence/disk.E01                 # recursive, full paths, allocated + deleted
fls -r -p -o 4462592 evidence/disk.E01 | grep -i '\*'  # '*' marks deleted entries
istat -o 4462592 evidence/disk.E01 2009                # all MAC times for one inode/MFT record
icat  -o 4462592 evidence/disk.E01 2009 > out/vault.img
# Bodyfile → timeline (then convert TZ):
fls -r -m / -o 4462592 evidence/disk.E01 > bodyfile
mactime -b bodyfile -d -z UTC 2023-07-01..2023-08-01 > fs_timeline.csv
```
NTFS entry points (hand deep parsing to `windows-artifacts`): `$MFT` (SI vs FN times),
`$Extend/$UsnJrnl:$J` (change journal), `$LogFile` (redo/undo), `$I30` dir index.
Extract them with `icat`, e.g. MFT is inode 0: `icat -o <s> img 0 > MFT`.

### Phase 4 — Derive format / creation time per filesystem
"Formatted time" is not one field — take the earliest system-created object:
- **NTFS**: creation (`crtime`) of `$MFT` (inode 0), or boot-sector volume serial at offset 0x48.
- **FAT16/exFAT (Win10)**: creation time of `System Volume Information` (Windows makes it right after format).
- **ext4**: superblock `s_mkfs_time` (offset 0x108) — `dumpe2fs -h /dev/nbdXpN | grep -i 'created\|UUID'`; or the `.journal` inode ctime. **ext2** has no journal/`mkfs_time` → format time may be **unknown** (say so, don't guess).
- **ext**: report the 16-byte superblock **UUID** (offset 0x68), not a fake "serial".
- **ReFS**: no simple field — see the `$Logfile` journaling method in Worked precedents (KDFC #201).
```bash
istat -o <ntfs_start> img 0 | grep -i created     # NTFS $MFT crtime
fls -o <fat_start> img | grep -i 'System Volume'   # then istat that inode
```

### Phase 5 — Recover deleted files & lost partitions
```bash
tsk_recover -o 4462592 evidence/disk.E01 out/recovered/     # deleted files (default)
tsk_recover -a -o 4462592 evidence/disk.E01 out/allfiles/   # allocated too
testdisk evidence/disk.raw          # interactive: Analyse → Quick/Deeper Search → recover partitions
photorec evidence/disk.raw          # signature carve when the FS is destroyed
# Manual raw carve of a known region:
dd if=evidence/disk.raw of=out/blob bs=1 skip=1335205 count=40668937
blkls -o <start> evidence/disk.E01 > out/unalloc.dd && foremost -t all -i out/unalloc.dd -o out/fm
```
Lost-partition scans yield duplicates (primary + backup boot sector for NTFS/exFAT) — **de-duplicate by start sector**.

### Phase 6 — Machine attribution via $RECYCLE.BIN
```bash
fls -r -p -o <ntfs_start> evidence/disk.E01 | grep -i '\$RECYCLE.BIN'
```
Each deleting user gets `$RECYCLE.BIN\S-1-5-21-<A>-<B>-<C>-<RID>`. The triplet `<A>-<B>-<C>` is the
**machine** identifier; the final RID is the account. A volume with two SID folders whose triplets
differ was mounted on **more than one machine**. `$I<rand>` = metadata (orig path/size/FILETIME delete),
`$R<rand>` = content.

### Phase 7 — Crypto containers (LUKS2 / BitLocker)
Detect: `xxd -l 16 container` — LUKS = `4C 55 4B 53 BA BE` (`LUKS`+magic), version byte at 0x06
(`02`=LUKS2); BitLocker = `-FVE-FS-` at offset 3. Then (Linux/WSL):
```bash
cryptsetup luksDump vault.img                       # cipher, keyslots, PBKDF, data offset
cryptsetup luksDump --dump-json-metadata vault.img
printf '%s' 'PASSPHRASE' | cryptsetup open --type luks2 --test-passphrase --tries 1 --key-file - vault.img
# If the passphrase fails but a RAM image exists, the raw volume key is in memory:
#   → hand off to skills/memory-forensics (aeskeyfind over the VMEM), get the 64-byte key back, then:
cryptsetup open --readonly --type luks2 --volume-key-file KEY vault.img vol_ro   # exit 0 verifies direction
mount -t ext4 -o ro,noload /dev/mapper/vol_ro /mnt   # noload = skip journal replay (read-only!)
```
BitLocker: `dislocker -r -V disk.raw -p<recovery-key> -- /mnt/bde` then mount `/mnt/bde/dislocker-file`
read-only; if only the running-system FVEK is available, recover it from RAM (memory-forensics).

## Flag-hiding checklist (where the answer usually hides on a disk)
- **Deleted / lost partitions** a signature scan (testdisk / X-Ways) recovers but `mmls` does not list.
- **Backdated format time** — a volume whose derived format time is an outlier (e.g. a 2010 NTFS among 2023 volumes) is planted.
- **`$RECYCLE.BIN\<SID>`** — machine-triplet diversity proves multi-machine use; `$I` files hold original path + delete time.
- **NTFS journals** — `$UsnJrnl:$J` (renames/deletes with parent refs), `$LogFile` (before/after images survive timestomping), `$I30` slack (deleted dir entries).
- **ReFS `$Logfile`** — occurrence-count signatures encode create/rename/permanent-delete + the delete FILETIME.
- **Unallocated / file slack** — carve `blkls` output; deleted-but-not-overwritten files via `tsk_recover`.
- **ADS / hidden attrs** — alternate data streams (`fls` shows them), Hidden/System-flagged files.
- **Crypto containers** whose passphrase is absent but the mounting host's RAM was captured (key in VMEM).
- **VMDK snapshots / backing chains** — the interesting delta may be in a child `-000001.vmdk`; hint may be "discard saved state".

## Pitfalls
- **Never** mount or open a container read-write. Always `-o ro,noload` / `--readonly` / `qemu-nbd --read-only` / `ewfmount` (FUSE is RO). Journal replay on mount *writes* to the image.
- Re-hash the image yourself; a hash inside a log or in the challenge text is a claim, not proof.
- Every `fls/icat/istat` needs the correct `-o <start sector>` — reading the whole image (offset 0) as one FS silently fails or misparses.
- Lost-partition scans produce backup-boot-sector duplicates → de-duplicate by start sector.
- ext2 has no reliable format time; report "unknown" rather than inventing one. ext has a UUID, not a serial.
- NTFS serials are 8 bytes (boot 0x48, on-disk byte order); FAT/exFAT are 4 bytes — don't conflate.
- Timestamps: NTFS/ReFS are 64-bit FILETIME (UTC 100ns), ext are Unix (UTC). Convert to the challenge TZ (KDFC alternates UTC+0 and UTC+9). Beware SI-vs-FN mismatch = timestomping.
- Recycle-Bin `$R`-renames are not user renames and not permanent deletions — classify correctly.
- macOS: `qemu-nbd`/`cryptsetup` are Linux — use WSL/Linux VM/docker, or `qemu-img convert -O raw` + TSK. APFS: TSK support is limited; use `apfs-fuse` (Linux) or a macOS mount `-o rdonly,nobrowse` off a raw image.
- Mounting `mount -t ntfs -o ro,show_sys_files,stream_interface=windows` exposes `$MFT` etc. via ntfs-3g on Linux.

## Worked precedents (see ../../knowledge/)
- **KDFC2023 #153 Partition Finder** — 11 lost-partition hits → 10 unique after de-dup; format time from `$MFT` crtime / `System Volume Information` / ext journal; a 2010 NTFS is the backdated outlier; Q2 solved by `$RECYCLE.BIN\S-1-5-21-*` machine-triplet diversity.
- **KDFC2023 #201 Log and Found** — ReFS volume; extract `$Logfile`, build a Windows Server 2022 VM test bed, generate known create/rename/delete events, diff journals → signatures (10=create, 11=renamed, 14=permanent-delete; delete FILETIME sits in the record after the last name reference).
- **KDFC2026 #151 Pull the Plug** — LUKS2 (`luksDump`: aes-xts-plain64, PBKDF2 258015 iters); passphrase fails, so recover the 64-byte volume key from VMEM via `aeskeyfind`, brute-force the ordered half-pairs against the LUKS PBKDF2 digest, then `cryptsetup open --volume-key-file` (exit 0 confirms half-order), mount `ext4 ro,noload`.
- **KDFC2026 #202 Toy Story** — vmdk suspend set: `qemu-nbd --read-only --connect=/dev/nbd0 toy_story.vmdk`, `mmls` → root start 4462592, `fls`/`icat` extract `/root/vault.img` inode 2009, cross-check SHA-256 vs the FTK Imager copy.

## References
- `../../references/magic-bytes.md` (E01 `EVF\x09`, VMDK `KDMV`, container signatures), `../../references/timestamps.md` (FILETIME/Unix→TZ).
- Sleuth Kit / carving: https://trailofbits.github.io/ctf/forensics/
- NTFS journals deep dive: https://andreafortuna.org/2026/07/06/ntfs-forensics-deep-dive/ · Triforce: https://www.hecfblog.com/2013/01/ntfs-triforce-deeper-look-inside.html
- Recycle Bin/SID: https://andreafortuna.org/2019/09/26/windows-forensics-analysis-of-recycle-bin-artifacts/
- VHD/NBD read-only mount example: https://forensicskween.com/ctf/hack-the-box/htb-cyber-apocalypse-2023-forensics/
- testdisk/photorec: https://www.cgsecurity.org/wiki/TestDisk · bulk_extractor: https://github.com/simsong/bulk_extractor
