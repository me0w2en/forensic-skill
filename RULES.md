# RULES — behaviour chain for the forensic-ai-harness skill pack

Addressed to any AI coding/agent client that loads this repository (Claude Code, Cursor, Cline,
OpenCode, Codex CLI, Windsurf, Kiro, or others). These rules bind before any skill body.

## Client boundary
The routing core, scripts, ops templates, knowledge base, and skill bodies do **not** depend on a
specific AI client. Each client loads this repo through its own mechanism (`AGENTS.md`, `CLAUDE.md`,
`.cursor/rules`, `.clinerules`, native `SKILL.md` discovery). Core scripts **MUST NOT** write
client-global configuration.

## The chain (every forensic task)
1. **Enter through the router.** Read `skills/forensics-router/SKILL.md`. Do not guess a tool from the
   file extension alone.
2. **Scope + integrity gate.** A `work/<case>/` must exist (`scripts/case-init.sh`). Hashes verified,
   answer format and **timezone** recorded from the challenge text. No scope → read-only triage only.
3. **Identify, don't assume.** Run `scripts/identify.sh` on every artifact. Route with
   `scripts/route.sh`. Read `tool-index.md` and use the tool variant that is actually present.
4. **Work on copies.** Never modify an original. Mount read-only. All output under `work/<case>/`.
5. **Execute the specialist skill**, logging each step to `work/<case>/timeline.md`.
6. **Grade and corroborate.** Every conclusion is `direct | correlation | withheld`; a `high`
   confidence finding needs ≥2 independent evidence items. Recompute any hash you cite.
7. **Answer in the required format and timezone.** Convert; never guess. `format_check` every answer.
8. **Write back.** Append a `knowledge/journal.md` entry with whatever was new.

## MUST / MUST NOT
- **MUST NOT** upload an artifact to a third-party service without explicit user approval. Public
  lookups (hash reputation, blockchain explorers, what3words, music ID) are allowed.
- **MUST NOT** run malware samples outside an isolated, no-network sandbox, and only when the task
  requires dynamic analysis. Prefer static + config decoding.
- **MUST NOT** order events across log channels by record ID. Normalise to UTC.
- **MUST NOT** promote a logged IOC/hash to a finding without recomputing it from the sample.
- **MUST** keep `config/routing.json` and the router table in sync (`scripts/test-routing.sh` in CI).
- **MUST** treat this pack as authorized-use only: CTF, own systems, lab, or written engagement.

## Scope of this pack
Digital forensics / DFIR for CTFs and authorized investigations: disk, memory, network, Windows
artifacts, Linux/container/cloud, mobile/app/browser, multimedia/stego, file-format/carving,
anti-forensics/timeline, blockchain tracing. Binary/malware **reverse engineering** beyond IOC and
config extraction is out of scope — collect strings/YARA/IOCs and hand off to a dedicated RE pack.
