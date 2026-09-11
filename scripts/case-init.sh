#!/usr/bin/env bash
# case-init.sh — scaffold work/<case>/ with scope, timeline, evidence log; copy + hash artifacts.
#   scripts/case-init.sh <case-name> [artifact ...]
#   scripts/case-init.sh kdfc26-151 ~/Downloads/DFC2026_Lf.zip
#   scripts/case-init.sh --link kdfs23 /Volumes/ext/2023.E01   # symlink, don't copy (large disk/mem images)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LINK=0; [ "${1:-}" = "--link" ] && { LINK=1; shift; }
[ $# -ge 1 ] || { echo "usage: $0 [--link] <case-name> [artifact ...]"; exit 1; }
NAME="$1"; shift
CASE="$ROOT/work/$(date +%Y%m%d)-$NAME"
mkdir -p "$CASE"/{evidence,extracted,notes,report}
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
md5f() { if command -v md5sum >/dev/null; then md5sum "$1" | cut -d' ' -f1; else md5 -q "$1"; fi; }

ART_BLOCK=""
for a in "$@"; do
  [ -e "$a" ] || { echo "!! not found: $a"; continue; }
  b=$(basename "$a")
  asize=$(stat -Lf%z "$a" 2>/dev/null || stat -Lc%s "$a" 2>/dev/null || echo 0)
  # auto-link very large images even without --link, so we never copy 20GB+
  if [ "$LINK" = 1 ] || [ "$asize" -gt 2147483648 ]; then
    ln -sf "$(cd "$(dirname "$a")" && pwd)/$b" "$CASE/evidence/$b"
    ART_BLOCK="$ART_BLOCK
- path: $(cd "$(dirname "$a")" && pwd)/$b
  working_copy: evidence/$b   # SYMLINK (read-only analysis; large image not copied)
  size: $asize
  md5: {large image — use ewfinfo (E01) or hash out-of-band}
  sha256: {large image — hash out-of-band}
  provided_hash: {paste from challenge}
  verified: {true|false}"
    echo "linked (not copied): $b ($asize bytes)"
    continue
  fi
  cp -Rp "$a" "$CASE/evidence/$b"
  chmod -R a-w "$CASE/evidence/$b" 2>/dev/null || true
  if [ -f "$CASE/evidence/$b" ]; then
    ART_BLOCK="$ART_BLOCK
- path: $(cd "$(dirname "$a")" && pwd)/$b
  working_copy: evidence/$b
  size: $(stat -f%z "$a" 2>/dev/null || stat -c%s "$a")
  md5: $(md5f "$CASE/evidence/$b")
  sha256: $(sha "$CASE/evidence/$b")
  provided_hash: {paste from challenge}
  verified: {true|false}"
  else
    ART_BLOCK="$ART_BLOCK
- path: $a (directory, copied)
  working_copy: evidence/$b"
  fi
done

cat > "$CASE/scope.md" <<EOF
# Case Scope

## meta
- case_id: $(basename "$CASE")
- created: $NOW
- operator: ${USER:-local}
- primary_skill: {run scripts/route.sh on the artifacts}
- challenge_source: {CTF / URL}

## auth
- status: granted
- basis: ctf_public

## artifacts${ART_BLOCK:-
- path: none yet, add with case-init or by hand}

## question
- asked: |
    {paste challenge text}
- answer_format: {flag format / fields}
- timezone: {UTC+0 | UTC+9 | as stated}

## network_profile
- mode: public_lookup_ok

## signoff
- ready_for_act: false
- checklist:
  - [ ] hashes verified
  - [ ] timezone recorded
  - [ ] identify.sh run on every artifact
EOF

cat > "$CASE/timeline.md" <<EOF
# Analyst timeline (append only)

## $NOW | init
- action: case-init
- command_or_ref: scripts/case-init.sh $NAME $*
- result_summary: scaffold created, artifacts copied and hashed
- next: scripts/identify.sh $CASE/evidence/
EOF

cat > "$CASE/evidence.md" <<'EOF'
# Evidence / Findings / Answers  (see ops/evidence-finding-path.md)

## Evidence
### E-001
- title:
- observed_at:
- source_type:
- source_ref:
- repro_command: |
- raw_excerpt: |
- grade: direct | correlation | withheld

## Findings
### F-001
- title:
- evidence_ids: []
- confidence:
- alternative_explanations: |
- answer_fragment: |

## Answers
### A-001
- question:
- finding_ids: []
- submitted:
- format_check: timezone? format? units?
- status:
EOF

cat > "$CASE/workitems.md" <<'EOF'
| ID | question / task | skill | status | evidence | notes |
|----|-----------------|-------|--------|----------|-------|
| WI-001 | | | open | | |

## Coverage
- [ ] every question has a WI
- [ ] every answer has an A-record
- [ ] withheld items listed
- [ ] knowledge/ entry written
EOF

echo "case ready: $CASE"
echo "next: $ROOT/scripts/identify.sh \"$CASE/evidence\"   &&   $ROOT/scripts/route.sh \"$CASE\"/evidence/*"
