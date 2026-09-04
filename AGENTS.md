# forensic-ai-harness — agent entry

A client-neutral **agent skill pack for digital-forensics CTFs and authorized DFIR**. Any agent client
(Claude Code, Cursor, Cline, OpenCode, Codex CLI, Windsurf, Kiro, …) loads this repo through its own
mechanism; the routing core, scripts, ops templates, and knowledge base do not depend on any one client.

## Read these first
1. `RULES.md` — the behaviour chain that binds before any skill.
2. `skills/forensics-router/SKILL.md` — the entry point for every task.

## What this is
Given a forensic artifact and a question, the router identifies the artifact type, enforces
hash-verification / read-only handling / timezone capture, and dispatches to one of 12 skills:

| Skill | Handles |
|-------|---------|
| `forensics-router` | entry point + routing |
| `case-ops` | case scaffold, evidence chain, report, knowledge write-back |
| `disk-image` | E01/dd/vmdk images, filesystems, deleted/lost data, crypto containers |
| `memory-forensics` | RAM/vmem/core/CRIU; Volatility 3; keys & passwords in RAM |
| `network-forensics` | pcap, USB HID, Bluetooth, DNS exfil, TLS |
| `windows-artifacts` | EVTX/registry/Prefetch/Amcache/SRUM/$MFT execution & persistence |
| `linux-container-cloud` | Docker/OCI, K8s/CRIU, AWS/Workspace logs, Linux logs |
| `mobile-artifacts` | Android/iOS, app SQLite+WAL, browser & AI-app caches |
| `multimedia-stego` | image/audio/video stego, container repair, OCR, geolocation |
| `file-format-carving` | unknown/corrupt files, archives, docs, PE-in-disguise (fallback) |
| `anti-forensics-timeline` | super-timeline, timestomping, wipers, log clearing, epochs |
| `blockchain-forensics` | wallet recovery, fund tracing, contract/DeFi incidents |

## First run
```bash
scripts/install-tools.sh          # best-effort toolchain (brew/apt/uv/gem/github)
scripts/refresh-tool-index.sh     # detect what's installed -> tool-index.md (gitignored, per-machine)
scripts/test-routing.sh           # routing regression (also runs in CI)
```

## Per-case loop
```bash
scripts/case-init.sh <name> <artifacts...>      # scaffolds work/<case>/ , copies + hashes artifacts
scripts/identify.sh work/<case>/evidence/       # type/magic/entropy/ROUTE per file
scripts/route.sh   work/<case>/evidence/* "<the question>"   # PRIMARY + SECONDARY skill
# then follow skills/<PRIMARY>/SKILL.md ; log to work/<case>/timeline.md
```

## Layout
```
AGENTS.md RULES.md README.md
skills/<name>/SKILL.md (+ references/)   canonical skill tree
.agents/skills .claude/skills .cursor/skills .cline/skills .opencode/skills  -> symlinks to skills/
ops/           scope / evidence-finding-path / timeline templates
config/routing.json   routing single-source-of-truth
scripts/       identify, route, case-init, refresh-tool-index, install-tools, test-routing
references/    magic-bytes, timestamps, windows-event-ids
knowledge/     distilled KDFC 2023/2026 + web DFIR sources + journal (+ _index.md)
work/          per-case artifacts (gitignored)
tool-index.md  generated per machine (gitignored)
```

## Authorization
CTF, own systems, lab, or written engagement only. Do not upload artifacts to third-party services
without explicit approval; run malware only in an isolated no-network sandbox when dynamic analysis is
required. Binary reverse engineering beyond IOC/config extraction is out of scope.
