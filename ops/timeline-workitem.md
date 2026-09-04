# Case timeline and work items

`work/<case>/` layout created by `scripts/case-init.sh`:

```
work/<case>/
├── scope.md          # ops/scope-contract.md
├── timeline.md       # APPEND ONLY — what the analyst did, in order
├── evidence.md       # ops/evidence-finding-path.md (E/F/A records)
├── workitems.md      # open questions / sub-tasks with status
├── evidence/         # working copies of artifacts (hash-verified)
├── extracted/        # things you pulled out: carved files, dumped processes, decoded scripts
├── notes/            # scratch
└── report/           # final writeup / answers
```

## timeline.md — analyst actions (not the incident timeline)

```markdown
## 2026-09-04T03:10:12Z | triage
- action: identify.sh on all artifacts
- command_or_ref: scripts/identify.sh work/case/evidence/
- result_summary: 2 EVTX (Sysmon, PowerShell-Operational) → windows-artifacts
- artifacts: []
- evidence_ids: []
- next: dump EID 1 / 4104
```

Append only. To correct, add a new entry with `corrects: <timestamp>`.

## Incident timeline (goes in report/, not here)

For the *incident* timeline (what the attacker did), keep one table, one timezone, and
mark the source of every row:

| UTC | Local (state tz) | Event | Source artifact | Evidence | Grade |
|-----|------------------|-------|-----------------|----------|-------|

## workitems.md

```markdown
| ID | question / task | skill | status | evidence | notes |
|----|-----------------|-------|--------|----------|-------|
| WI-001 | Q1 initial access IP | windows-artifacts | done | E-004 | LogonType 10 filter |
| WI-002 | Q3 was log clearing successful? | windows-artifacts | open | | no EID 1102 seen yet |

## Coverage
- [ ] every question in scope.md has a WI
- [ ] every submitted answer has an A-record with format_check
- [ ] "withheld" items listed explicitly in report
- [ ] knowledge/ journal entry written (what was new / non-obvious)
```
