# Contributing

Thanks for improving the pack. Keep it dense, runnable, and client-neutral.

## Add or edit a skill
1. Skills live in `skills/<name>/SKILL.md` (canonical). Frontmatter has only `name` (must equal the dir)
   and a keyword-dense `description`. Body < 500 lines; commands over prose; push detail to `references/`.
2. If you add a new skill, also:
   - add a route to `config/routing.json` (artifact-type signals get `"weight": 2`),
   - add a row to the table in `skills/forensics-router/SKILL.md`,
   - add at least one regression line to `scripts/test-routing.sh`.
3. Run the checks before opening a PR:
   ```bash
   scripts/test-routing.sh
   python3 -c "import json;json.load(open('config/routing.json'))"
   for s in scripts/*.sh; do bash -n "$s"; done
   ```
   CI runs the same on Ubuntu + macOS (`.github/workflows/ci.yml`).

## Do NOT commit
- **Competition writeups or their close distillations.** `knowledge/kdfc-*.md` is git-ignored on purpose.
  Write original methodology into the skills instead; credit a challenge by name in "Worked precedents"
  without embedding its flags, passwords, keys, IOCs, or answer values.
- **Real evidence / case data.** `work/` and `tool-index.md` are git-ignored (machine- and case-specific).
- **Secrets** of any kind.

## Style
- Every timestamp workflow must state converting to the challenge's required timezone.
- Prefer tools that `tool-index.md` shows as available; always list a fallback for missing ones.
- Don't invent tool flags; if unsure, say "check --help".

## Scope
Digital-forensics / DFIR for CTFs and authorized investigations. Deep binary reverse engineering beyond
IOC/config extraction is out of scope. Contributions must assume authorized use only.
