#!/usr/bin/env bash
# identify.sh — First-contact triage for any forensic artifact.
# Usage: scripts/identify.sh <file-or-dir> [more files...]
# Prints: type, magic bytes, size, entropy, embedded signatures, and a ROUTE hint
# that maps to a skill directory under skills/.  Never guesses — only reports.
set -u

have() { command -v "$1" >/dev/null 2>&1; }

route_for() {
  # $1 = lowercased `file -b` output, $2 = lowercased filename, $3 = first 16 hex bytes
  local desc="$1" name="$2" hex="$3"
  case "$desc$name$hex" in
    *"ewf"*|*.e01|*.ex01|*"expert witness"*)                  echo "disk-image (EWF)";;
    *"dos/mbr boot sector"*|*"gpt partition"*|*.dd|*.raw|*.img|*.vmdk|*.vhd|*.vhdx|*.qcow2|*.ad1|*.aff*) echo "disk-image";;
    *"ntfs"*|*"fat"*|*"ext[234]"*|*"apfs"*|*"hfs"*)             echo "disk-image (filesystem)";;
    *.mem|*.vmem|*.raw.mem|*.lime|*.dmp|*"hibernation"*|*"crash dump"*|*.hiberfil*|*pagefile*|*memdump*) echo "memory-forensics";;
    *"pcap"*|*"pcapng"*|*.cap|*"tcpdump"*|*.etl|*.netlog)      echo "network-forensics";;
    *"windows registry"*|*.hive|*"ntuser.dat"*|*"usrclass.dat"*|*"/sam"*|*"/system"*|*"/software"*|*"/security"*|*amcache.hve*) echo "windows-artifacts (registry)";;
    *"windows event log"*|*.evtx|*.evt)                          echo "windows-artifacts (eventlog)";;
    *.pf|*"prefetch"*|*.lnk|*"ms windows shortcut"*|*automaticdestinations*|*customdestinations*|*"\$mft"*|*"\$usnjrnl"*|*"\$logfile"*|*"\$i30"*|*srudb.dat*|*activitiescache.db*|*"\$recycle.bin"*) echo "windows-artifacts";;
    *"sqlite"*|*.db|*.sqlite*|*.db-wal|*.db-shm|*"android backup"*|*.ab|*.tar|*"ios backup"*|*manifest.db*|*.plist|*"apple binary property list"*) echo "mobile-artifacts / browser (sqlite)";;
    *"png image"*|*"jpeg image"*|*"gif image"*|*"bitmap"*|*"webp"*|*"tiff"*|*"riff (little-endian) data, wave"*|*"mpeg adts"*|*"audio file"*|*"iso media"*|*"matroska"*|*"flac"*|*"ogg"*|*.wav|*.mp3|*.mp4|*.avi|*.mkv|*.heic) echo "multimedia-stego";;
    *"zip archive"*|*"microsoft ooxml"*|*"composite document file"*|*"pdf document"*|*"hwp"*|*"hangul"*|*"rar archive"*|*"7-zip"*|*"gzip"*|*"xz compressed"*|*"bzip2"*|*.hwp|*.hwpx|*.docx|*.xlsx|*.pptx|*.doc|*.xls|*.pdf|*.zip|*.rar|*.7z) echo "file-format-carving (container/document)";;
    *"docker"*|*.tar.gz*|*"layer.tar"*|*manifest.json*|*"json data"*|*"cloudtrail"*|*.jsonl|*"journal"*|*.journal|*"systemd"*|*auth.log*|*syslog*|*wtmp*|*btmp*|*lastlog*|*.bash_history*) echo "linux-container-cloud";;
    *"data"*|*"unknown"*)                                        echo "file-format-carving (unknown/corrupted header — check magic manually)";;
    *"pe32"*|*"elf"*|*"mach-o"*|*.exe|*.dll|*.sys|*.so)           echo "malware-triage (out of scope: hand to reverse/malware skill; here only collect strings/yara/IOCs)";;
    *"ascii text"*|*"utf-8"*|*.txt|*.log|*.csv|*.xml|*.json)     echo "log/text — grep + timeline; see anti-forensics-timeline";;
    *)                                                            echo "unrouted — inspect header manually";;
  esac
}

entropy() {
  # Shannon entropy of first 1 MiB (python fallback keeps this portable)
  if have ent; then head -c 1048576 "$1" | ent -t 2>/dev/null | awk -F, 'NR==2{printf "%.3f bits/byte", $3}'
  else python3 - "$1" <<'PY'
import sys,math,collections
b=open(sys.argv[1],'rb').read(1048576); n=len(b)
if n==0: print("0 (empty)"); sys.exit()
c=collections.Counter(b); print("%.3f bits/byte"%(-sum(v/n*math.log2(v/n) for v in c.values())))
PY
  fi
}

inspect_file() {
  local f="$1"
  [ -r "$f" ] || { echo "!! unreadable: $f"; return; }
  local size desc hex name lower_desc lower_name
  # -L: follow symlinks so a linked-in large image reports its real size
  size=$(stat -Lf%z "$f" 2>/dev/null || stat -Lc%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
  desc=$(file -b "$f" 2>/dev/null)
  hex=$(head -c 16 "$f" | xxd -p | tr -d '\n')
  name=$(basename "$f")
  lower_desc=$(printf '%s' "$desc" | tr '[:upper:]' '[:lower:]')
  lower_name=$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')

  echo "================================================================"
  echo "FILE   : $f"
  echo "SIZE   : $size bytes"
  echo "TYPE   : $desc"
  echo "MAGIC  : $hex"
  echo "TAIL   : $(tail -c 16 "$f" | xxd -p | tr -d '\n')"
  echo "ENTROPY: $(entropy "$f")"
  # Hashing a multi-GB disk/memory image is slow; skip by default over 2 GiB.
  # For EWF/E01 use the stored acquisition hash (ewfinfo); otherwise hash in the background yourself.
  if [ "$size" -gt 2147483648 ]; then
    echo "MD5    : (skipped, ${size} bytes > 2GiB — run 'shasum'/'ewfinfo' out-of-band)"
    echo "SHA256 : (skipped for large image)"
  else
    if have md5sum; then echo "MD5    : $(md5sum "$f" | cut -d' ' -f1)"; else echo "MD5    : $(md5 -q "$f")"; fi
    echo "SHA256 : $(shasum -a 256 "$f" | cut -d' ' -f1)"
  fi
  echo "ROUTE  : $(route_for "$lower_desc" "$lower_name" "$hex")"

  # Cheap secondary signals that frequently decide a CTF
  if have exiftool && [ "$size" -lt 200000000 ]; then
    local ex; ex=$(exiftool -s -S -Comment -UserComment -ImageDescription -XPComment -Artist -Software -Warning "$f" 2>/dev/null | head -8)
    [ -n "$ex" ] && { echo "EXIF   :"; printf '%s\n' "$ex" | sed 's/^/         /'; }
  fi
  if have binwalk && [ "$size" -lt 500000000 ]; then
    local bw; bw=$(binwalk "$f" 2>/dev/null | awk 'NR>3 && NF' | head -12)
    [ -n "$bw" ] && { echo "BINWALK:"; printf '%s\n' "$bw" | sed 's/^/         /'; }
  fi
  local trailing; trailing=$(strings -n 8 "$f" 2>/dev/null | grep -iE 'flag\{|ctf\{|kdfc|dfc\{|password|passwd|BEGIN (RSA|OPENSSH|PGP)|http[s]?://' | head -5)
  [ -n "$trailing" ] && { echo "STRINGS: (interesting)"; printf '%s\n' "$trailing" | sed 's/^/         /'; }
}

[ $# -ge 1 ] || { echo "usage: $0 <file|dir> [...]"; exit 1; }
for target in "$@"; do
  if [ -d "$target" ]; then
    find "$target" -type f ! -name '.*' -print0 | while IFS= read -r -d '' f; do inspect_file "$f"; done
  else
    inspect_file "$target"
  fi
done
echo "================================================================"
echo "Next: open skills/<ROUTE>/SKILL.md. If ROUTE is 'unrouted', read references/magic-bytes.md."
