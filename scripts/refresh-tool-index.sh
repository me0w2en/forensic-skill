#!/usr/bin/env bash
# refresh-tool-index.sh — Detect which forensic tools exist on this host and
# regenerate tool-index.md.  Run after installing anything.  Agents read the
# generated file to decide which command variant to use (never assume a tool).
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/tool-index.md"
export PATH="$HOME/.local/bin:$HOME/.rbenv/shims:/opt/homebrew/bin:/usr/local/bin:$PATH"

# name | category | probe command | install hint
TOOLS=$(cat <<'EOF'
file|triage|file --version|coreutils
xxd|triage|xxd -v|vim
strings|triage|strings --version|binutils
binwalk|carving|binwalk --help|brew install binwalk / pip install binwalk
foremost|carving|foremost -V|brew install foremost / apt install foremost
bulk_extractor|carving|bulk_extractor -h|brew install bulk_extractor
scalpel|carving|scalpel -h|apt install scalpel (no brew formula)
photorec|carving|photorec --version|brew install testdisk
testdisk|disk|testdisk --version|brew install testdisk
mmls|disk|mmls -V|brew install sleuthkit
fls|disk|fls -V|brew install sleuthkit
icat|disk|icat -V|brew install sleuthkit
istat|disk|istat -V|brew install sleuthkit
blkls|disk|blkls -V|brew install sleuthkit
tsk_recover|disk|tsk_recover -V|brew install sleuthkit
ewfinfo|disk|ewfinfo -V|brew install libewf
ewfmount|disk|ewfmount -V|brew install libewf
ewfexport|disk|ewfexport -V|brew install libewf
qemu-img|disk|qemu-img --version|brew install qemu
7z|archive|7z --help|brew install sevenzip
unzip|archive|unzip -v|coreutils
zipdump.py|archive|zipdump.py -h|DidierStevensSuite
vol|memory|vol -h|uv tool install volatility3
volshell|memory|volshell -h|uv tool install volatility3
tshark|network|tshark -v|brew install --cask wireshark
capinfos|network|capinfos -h|wireshark
editcap|network|editcap -h|wireshark
mergecap|network|mergecap -h|wireshark
tcpflow|network|tcpflow -h|brew install tcpflow
ngrep|network|ngrep -V|brew install ngrep
zeek|network|zeek --version|brew install zeek
regipy-dump|windows|regipy-dump --help|uv tool install regipy
regipy-plugins-run|windows|regipy-plugins-run --help|uv tool install regipy
rip.pl|windows|rip.pl -h|RegRipper (git clone keydet89/RegRipper3.0)
evtx_dump|windows|evtx_dump --help|brew install evtx / cargo install evtx
chainsaw|windows|chainsaw --version|brew install chainsaw
hayabusa|windows|hayabusa help|github release Yamato-Security/hayabusa
target-query|windows|target-query --help|uv tool install dissect / brew install dissect
target-shell|windows|target-shell --help|dissect
prefetch-parser|windows|python3 -c "import windowsprefetch"|pip install windowsprefetch
LECmd|windows|LECmd --version|Eric Zimmerman tools (dotnet)
PECmd|windows|PECmd --version|Eric Zimmerman tools (dotnet)
MFTECmd|windows|MFTECmd --version|Eric Zimmerman tools (dotnet)
analyzeMFT.py|windows|analyzeMFT.py -h|pip install analyzeMFT
log2timeline|timeline|log2timeline --version|uv tool install plaso
psort|timeline|psort --version|uv tool install plaso
mactime|timeline|mactime -V|sleuthkit
hindsight.py|browser|hindsight.py -h|uv tool install pyhindsight
sqlite3|browser|sqlite3 --version|brew install sqlite
readpst|email|readpst -V|brew install libpst
pffexport|email|pffexport -h|libpff (build from source / docker)
pffinfo|email|pffinfo -h|libpff (build from source / docker)
exiftool|media|exiftool -ver|brew install exiftool
exiv2|media|exiv2 --version|brew install exiv2
ffmpeg|media|ffmpeg -version|brew install ffmpeg
ffprobe|media|ffprobe -version|brew install ffmpeg
sox|media|sox --version|brew install sox
pngcheck|media|pngcheck -h|brew install pngcheck
zsteg|stego|zsteg --help|gem install zsteg
zsteg-mask|stego|zsteg-mask --help|gem install zsteg
steghide|stego|steghide --version|apt install steghide (no ARM mac build; use docker)
stegseek|stego|stegseek --version|github RickdeJager/stegseek (linux)
stegsolve|stego|stegsolve -h|java jar
outguess|stego|outguess -h|brew install outguess
identify|media|identify -version|brew install imagemagick
convert|media|convert -version|brew install imagemagick
olevba|documents|olevba -h|uv tool install oletools
oleid|documents|oleid -h|oletools
oledump.py|documents|oledump.py -h|DidierStevensSuite
rtfobj|documents|rtfobj -h|oletools
pdfid.py|documents|pdfid.py -h|DidierStevensSuite
pdf-parser.py|documents|pdf-parser.py -h|DidierStevensSuite
qpdf|documents|qpdf --version|brew install qpdf
pdftotext|documents|pdftotext -v|brew install poppler
hwp5txt|documents|hwp5txt --help|pip install pyhwp
yara|malware|yara --version|brew install yara
xorsearch.py|malware|xorsearch.py -h|DidierStevensSuite
base64dump.py|malware|base64dump.py -h|DidierStevensSuite
john|passwords|john --help|brew install john-jumbo
hashcat|passwords|hashcat --version|brew install hashcat
zip2john|passwords|zip2john|john-jumbo
ent|analysis|ent -h|brew install ent
python3|runtime|python3 --version|brew install python
uv|runtime|uv --version|brew install uv
docker|runtime|docker --version|Docker Desktop / colima
jq|analysis|jq --version|brew install jq
rg|analysis|rg --version|brew install ripgrep
EOF
)

{
  echo "# Tool Index (auto-generated)"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ) on $(uname -s) $(uname -m) ($(hostname -s 2>/dev/null))"
  echo
  echo "Agents: consult this before choosing a command. ✅ = available, ❌ = missing (use the install hint or the fallback listed in the skill)."
  echo
  echo "Status: ✅ runs · ⚠️ present but broken (probe errored — often a missing Python dep) · ❌ missing."
  echo
  echo "| Tool | Category | Status | Path | Install hint |"
  echo "|------|----------|--------|------|--------------|"
  ok=0; miss=0; broken=0
  while IFS='|' read -r name cat probe hint; do
    [ -z "$name" ] && continue
    if p=$(command -v "$name" 2>/dev/null); then
      # actually RUN the probe (bounded) — catches "installed but broken" (e.g. missing click/tabulate)
      out=$( { eval "timeout 15 $probe"; } 2>&1 </dev/null )
      if printf '%s' "$out" | grep -qiE 'Traceback|ModuleNotFoundError|ImportError|No module named'; then
        echo "| \`$name\` | $cat | ⚠️ | \`$p\` | $hint |"; broken=$((broken+1))
      else
        echo "| \`$name\` | $cat | ✅ | \`$p\` | $hint |"; ok=$((ok+1))
      fi
    else
      echo "| \`$name\` | $cat | ❌ | — | $hint |"; miss=$((miss+1))
    fi
  done <<< "$TOOLS"
  echo
  echo "**Runs: $ok · Broken: $broken · Missing: $miss**"
  echo
  echo "## Python modules"
  echo
  for m in volatility3 regipy dissect pytsk3 pyewf yara scapy pyshark dpkt olefile oletools construct pycryptodome pillow numpy hwp5 plaso; do
    if python3 -c "import $m" 2>/dev/null || uv tool run --from "$m" python -c "import $m" 2>/dev/null; then echo "- ✅ $m"; else echo "- ❌ $m"; fi
  done
} > "$OUT"
echo "wrote $OUT ($(grep -c '✅' "$OUT") available)"
