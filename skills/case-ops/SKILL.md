---
name: case-ops
description: |
  Case lifecycle for forensic work: create the work/<case>/ scaffold, verify and log artifact hashes,
  maintain the Evidence→Finding→Answer chain, produce the final writeup/report, and write back lessons to
  knowledge/. Use when starting a new challenge/case, when asked to "write up", "report", "summarise what
  we found", "review the evidence", or at the end of any forensic task. Trigger keywords: case init, new case,
  scope, evidence log, chain of custody, report, writeup, 보고서, 라이트업, review case, hash verify.
---

# Case Ops

## ACTION REQUIRED
1. `NOW` New case → `scripts/case-init.sh <name> <artifacts…>`; existing → `ls work/` and open the newest matching dir.
2. `NOW` Verify hashes: compare `scope.md → artifacts[].md5/sha256` to what the challenge provides. Mismatch = stop and tell the user (wrong/damaged download).
3. `NEXT` Confirm `question.asked`, `answer_format`, `timezone` are filled from the challenge text verbatim.
4. `ACT` Hand off to `forensics-router` (new case) or run the **Report** or **Review** procedure below.

## Templates
- `ops/scope-contract.md` — scope.md fields
- `ops/evidence-finding-path.md` — E/F/A records and grading (`direct | correlation | withheld`)
- `ops/timeline-workitem.md` — analyst timeline, work items, coverage checklist

## Review procedure (before submitting answers)
```bash
CASE=work/<case>
grep -c '^### E-' $CASE/evidence.md; grep -c '^### F-' $CASE/evidence.md; grep -c '^### A-' $CASE/evidence.md
grep -n 'grade:' $CASE/evidence.md | grep -v 'direct\|correlation\|withheld'      # ungraded evidence = fix
grep -n 'timezone' $CASE/scope.md                                                  # is every A converted?
grep -n 'status: open' $CASE/workitems.md                                          # unfinished WIs
```
Checklist:
- [ ] Each A has ≥1 F; each F has ≥1 E; `confidence: high` has ≥2 independent E.
- [ ] Every timestamp in an A is in the challenge's timezone, with the offset written next to it in the report.
- [ ] Every hash you *cite* you *computed* (or you labelled it "as logged, unverified").
- [ ] "Withheld" items are listed in the report as limits of the evidence.
- [ ] Flag format matches the regex in scope.md (`FLAG{…}`, `DFC{…}`, `[a].[b].[c]`).

## Report procedure
Write `work/<case>/report/README.md`:
1. **Summary** — one paragraph, the answers.
2. **Artifacts** — table: name, size, provided hash, computed hash, verified.
3. **Method** — per question: the command(s), the artifact, the value, the grade. Copy `repro_command` blocks verbatim.
4. **Incident timeline** — single table, UTC + stated local tz, source column, grade column.
5. **Limits** — what could not be established and why.
6. **Tools** — from `tool-index.md`, versions where known.

KDFC-style graders reward: hash verification up front, exact commands, tool versions, and explicitly separated direct/correlated evidence.

## Knowledge write-back (mandatory at the end)
Append to `knowledge/journal.md`:
```markdown
## <date> <case> — <one-line what it was>
- artifact: …   skill(s): …
- new trick: …  (or "nothing new")
- pitfall hit: …
- rule: When you see X, do Y.
```
If the trick is general, also add a bullet to the relevant `skills/<skill>/SKILL.md` "Playbook" section and a regression line to `scripts/test-routing.sh` if routing was wrong.
