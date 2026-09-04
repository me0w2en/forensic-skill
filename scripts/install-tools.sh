#!/usr/bin/env bash
# install-tools.sh — best-effort install of the forensic toolchain (macOS brew / Debian apt).
# Installs are individual so one missing formula doesn't abort the rest.  Re-run any time.
# After: scripts/refresh-tool-index.sh
set -u
OS=$(uname -s)
ok(){ printf '  OK   %s\n' "$1"; }; ko(){ printf '  FAIL %s\n' "$1"; }
have(){ command -v "$1" >/dev/null 2>&1; }
mkdir -p "$HOME/.local/bin"

echo "== system packages ($OS) =="
if [ "$OS" = "Darwin" ]; then
  have brew || { echo "install Homebrew first: https://brew.sh"; exit 1; }
  for f in sleuthkit libewf binwalk foremost bulk_extractor testdisk yara pngcheck qpdf poppler exiftool exiv2 imagemagick ffmpeg sox ent john-jumbo hashcat chainsaw evtx dissect tcpflow ngrep zeek qemu p7zip jq ripgrep uv python@3.12 libmagic sqlite pandoc; do
    brew list "$f" >/dev/null 2>&1 && { ok "$f (present)"; continue; }
    brew install "$f" >/dev/null 2>&1 && ok "$f" || ko "$f"
  done
  brew list --cask wireshark >/dev/null 2>&1 || brew install --cask wireshark >/dev/null 2>&1 && ok wireshark || ko wireshark
elif have apt-get; then
  sudo apt-get update -qq
  for f in sleuthkit libewf-tools ewf-tools binwalk foremost scalpel bulk-extractor testdisk yara pngcheck qpdf poppler-utils libimage-exiftool-perl exiv2 imagemagick ffmpeg sox ent john hashcat tshark tcpflow ngrep p7zip-full jq ripgrep python3-pip python3-venv steghide outguess sqlite3 pandoc cryptsetup qemu-utils; do
    sudo apt-get install -y -qq "$f" >/dev/null 2>&1 && ok "$f" || ko "$f"
  done
  have cargo && { cargo install evtx >/dev/null 2>&1 && ok evtx_dump || ko evtx_dump; }
else
  echo "unsupported package manager; install manually (see tool-index.md hints)"
fi

echo "== python tools (uv tool) =="
have uv || pip3 install --user uv >/dev/null 2>&1
for t in volatility3 oletools regipy pyhindsight dissect; do
  uv tool install "$t" >/dev/null 2>&1 && ok "$t" || ko "$t"
done
uv tool install --python 3.12 plaso >/dev/null 2>&1 && ok plaso || ko "plaso (needs py3.12)"

echo "== Didier Stevens suite =="
for s in pdfid.py pdf-parser.py oledump.py xorsearch.py base64dump.py zipdump.py emldump.py; do
  curl -fsSL "https://raw.githubusercontent.com/DidierStevens/DidierStevensSuite/master/$s" -o "$HOME/.local/bin/$s" && chmod +x "$HOME/.local/bin/$s" && ok "$s" || ko "$s"
done

echo "== ruby: zsteg =="
if have gem; then gem install zsteg >/dev/null 2>&1 && ok zsteg || ko zsteg
  Z=$(gem contents zsteg 2>/dev/null | grep 'bin/zsteg$'); [ -n "$Z" ] && ln -sf "$Z" "$HOME/.local/bin/zsteg"
fi

echo "== hayabusa (github release) =="
if ! have hayabusa; then
  ARCH=$(uname -m); case "$OS-$ARCH" in Darwin-arm64) P=mac-aarch64;; Darwin-x86_64) P=mac-x64;; Linux-x86_64) P=lin-x64-gnu;; Linux-aarch64) P=lin-aarch64-gnu;; *) P="";; esac
  if [ -n "$P" ] && have gh; then
    T=$(mktemp -d) && gh release download --repo Yamato-Security/hayabusa --pattern "*-$P.zip" -D "$T" >/dev/null 2>&1 && unzip -qo "$T"/*.zip -d "$HOME/.local/share/hayabusa" && \
      B=$(ls "$HOME/.local/share/hayabusa" | grep -E "^hayabusa-[0-9.]+-$P$") && chmod +x "$HOME/.local/share/hayabusa/$B" && ln -sf "$HOME/.local/share/hayabusa/$B" "$HOME/.local/bin/hayabusa" && ok hayabusa || ko hayabusa
  else ko "hayabusa (needs gh cli)"; fi
fi

echo "== not automated (do by hand if needed) =="
cat <<'EOF'
  - steghide / stegseek : no macOS ARM build. Use docker:  docker run --rm -v "$PWD":/d rickdejager/stegseek /d/img.jpg /d/wordlist.txt
  - Eric Zimmerman tools (MFTECmd, PECmd, LECmd, ...): dotnet 9 + https://ericzimmerman.github.io  (run on Windows or via `dotnet`)
  - RegRipper: git clone https://github.com/keydet89/RegRipper3.0 ; perl rip.pl
  - StegSolve: java -jar stegsolve.jar  (https://github.com/eugenekolo/sec-tools)
  - aeskeyfind / rsakeyfind: git clone https://github.com/makomk/aeskeyfind && make  (Linux; on mac use docker or `brew install aeskeyfind` if available)
  - Autopsy / FTK Imager / X-Ways / Magnet AXIOM: GUI, Windows-centric — optional
  - ext4-fbe Sleuth Kit fork + fbekeyfind: faui1-gitlab.cs.fau.de/tobias.gross/sleuthkit-ext4-fbe (Android FBE only)
EOF
echo; echo "now run: scripts/refresh-tool-index.sh"
