#!/usr/bin/env bash
# route.sh — Score a hint (free text and/or file paths) against config/routing.json
# and print PRIMARY + SECONDARY skills.  Pure python3 stdlib, no deps.
#
#   scripts/route.sh "why won't this mp4 play"                # text only
#   scripts/route.sh evidence/*.E01                            # files: uses `file -b` + names
#   scripts/route.sh --json "sysmon evtx powershell -enc"      # machine-readable
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
JSON=0; [ "${1:-}" = "--json" ] && { JSON=1; shift; }
[ $# -ge 1 ] || { echo "usage: $0 [--json] <hint text | files...>"; exit 1; }

HINT=""
for a in "$@"; do
  if [ -e "$a" ]; then
    HINT="$HINT $(basename "$a") $(file -b "$a" 2>/dev/null)"
  else
    HINT="$HINT $a"
  fi
done

python3 - "$ROOT/config/routing.json" "$JSON" "$HINT" <<'PY'
import json, re, sys
cfg = json.load(open(sys.argv[1], encoding="utf-8"))
as_json = sys.argv[2] == "1"
hint = sys.argv[3].lower()
scores, hits = {}, {}
for rid, route in cfg["routes"].items():
    s = 0
    for kw in route["keywords"]:
        if not re.search(kw["must"], hint, re.I):
            continue
        if any(not re.search(m, hint, re.I) for m in kw.get("mustAll", [])):
            continue
        if "exclude" in kw and re.search(kw["exclude"], hint, re.I):
            continue
        # score = number of DISTINCT alternations matched, so a hint that names
        # kubernetes+criu+checkpoint beats one that only says criu+checkpoint
        found = {m.group(0).lower() for m in re.finditer(kw["must"], hint, re.I)}
        s += len(found) * int(kw.get("weight", 1))
        hits.setdefault(rid, []).extend(sorted(found))
    if s:
        scores[rid] = s
prio = cfg["priority"]
ranked = sorted(scores, key=lambda r: (-scores[r], prio.index(r) if r in prio else 999))
if not ranked:
    ranked = [cfg["meta"]["fallbackId"]]
primary = ranked[0]
out = {
    "primary": {"id": primary, "label": cfg["routes"][primary]["label"], "skill": "skills/" + cfg["routes"][primary]["skill"], "matched": hits.get(primary, [])},
    "secondary": [{"id": r, "label": cfg["routes"][r]["label"], "skill": "skills/" + cfg["routes"][r]["skill"], "matched": hits.get(r, [])} for r in ranked[1:4]],
}
if as_json:
    print(json.dumps(out, ensure_ascii=False, indent=2))
else:
    p = out["primary"]
    print(f"PRIMARY   : {p['id']}  {p['label']}\n            -> {p['skill']}\n            matched: {', '.join(p['matched']) or '(fallback)'}")
    for s in out["secondary"]:
        print(f"SECONDARY : {s['id']}  {s['label']}  -> {s['skill']}  [{', '.join(s['matched'])}]")
PY
