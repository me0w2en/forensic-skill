# Evidence → Finding → Answer chain (`work/<case>/evidence.md`)

Borrowed from reverse-skill's E→F→P contract, tightened for DFIR. The point is not
bureaucracy; it is that every answer you submit can be traced to a reproducible command
and that you have graded *how sure* you are. KDFC 2026 graders explicitly rewarded
teams that separated **direct evidence** from **correlation** and said what the
artifacts *cannot* prove.

## E-nnn  Evidence (immutable observation)

```markdown
### E-001
- title: PowerShell EID 4104 script block, RID 121
- observed_at: 2026-09-04T03:12:00Z
- source_type: command | file | log | memory | network | chain | manual
- source_ref: work/case/evidence/PowerShell-Operational.evtx
- content_hash: sha256:...                     # of the artifact the command ran against
- repro_command: |
    evtx_dump --format json PowerShell-Operational.evtx | jq 'select(.Event.System.EventID==4104)'
- raw_excerpt: |
    ...redacted / truncated excerpt...
- grade: direct | correlation | withheld
```

Grades:
- **direct** — the artifact itself states the fact (a file hash you computed, a timestamp in a parsed structure, an on-chain value at a pinned block).
- **correlation** — inferred by joining two artifacts (same PID across channels, IP reuse, time proximity). Say which join.
- **withheld** — you looked and the artifacts cannot prove it. Write this down; it is worth points and it stops you fabricating.

## F-nnn  Finding (conclusion)

```markdown
### F-001
- title: Suspect process is powershell.exe PID 5140
- evidence_ids: [E-001, E-003]
- confidence: high | medium | low
- alternative_explanations: |
    ...what else could produce these observations, and why rejected...
- answer_fragment: |
    ...the exact text that will go into the flag/answer, in the requested timezone/format...
```

Rules:
- A Finding needs ≥1 Evidence; a `confidence: high` Finding needs ≥2 independent Evidence
  (e.g. Windows Timeline **and** PcaAppLaunchDic for an execution time — see KDFC 2023 #102).
- Never promote a log-recorded hash/IOC to a Finding without recomputing it from the
  sample when you have the sample (KDFC 2026 #102 planted mismatching Sysmon hashes).
- Never order events by record ID across channels; order by normalised UTC timestamp.

## A-nnn  Answer (what is submitted)

```markdown
### A-001
- question: Q2 — when was the wiper run? (UTC+0)
- finding_ids: [F-002]
- submitted: 2023-04-26 04:14:27
- format_check: timezone converted? ✅  format matches prompt? ✅  units? ✅
- status: submitted | accepted | rejected
```

If rejected, add a new A-nnn; never edit the old one (append-only, same as the timeline).
