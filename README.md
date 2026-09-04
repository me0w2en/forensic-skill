<p align="center">
  <h1 align="center">🔬 forensic-ai-harness</h1>
  <h3 align="center">Digital Forensics Skills Router · 디지털 포렌식 스킬 라우터</h3>
  <p align="center"><i>Hand your agent a forensic artifact and a question — it finds the right tool, not a guess.</i></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
  <a href="https://github.com/me0w2en/forensic-skill/actions/workflows/ci.yml"><img src="https://github.com/me0w2en/forensic-skill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/skills-12-blue.svg" alt="12 skills">
  <img src="https://img.shields.io/badge/routing%20tests-43%20passing-brightgreen.svg" alt="43 routing tests">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg" alt="platform">
</p>

<p align="center">
  <a href="#about">About</a> ·
  <a href="#getting-started">Getting Started</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#skills">Skills</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="#license">License</a> ·
  <a href="README_ko.md">🌐 한국어</a>
</p>

---

## About

**forensic-ai-harness** is a client-neutral **agent-skill pack for digital-forensics CTFs and authorized
DFIR**. Point any AI coding agent (Claude Code, Cursor, Cline, OpenCode, Codex CLI, …) at this repo. When
you hand it a forensic artifact and a question, it identifies the artifact type, enforces sound handling
(verify hashes, work read-only, capture the answer's timezone), and drives one of **12 specialist
skills** — each a dense, runnable playbook with a flag-hiding checklist and pitfalls.

> **If you are an AI agent:** do not guess a tool from the file extension. Enter through
> `skills/forensics-router/SKILL.md`, run `scripts/identify.sh` and `scripts/route.sh`, then follow the
> PRIMARY skill. `RULES.md` binds before any skill.

CTF forensics wastes time on "which tool for this file?". This pack answers it deterministically:

```
artifact + question
        │
        ▼
 forensics-router ──▶ identify.sh (magic/entropy) ──▶ routing.json ──▶ specialist skill
        │                                                                    │
   verify hash · read-only · capture timezone                     runnable playbook
        │                                                                    │
        ▼                                                                    ▼
  work/<case>/  ◀── Evidence → Finding → Answer (graded direct/correlation/withheld) ──▶ report
```

<p align="right"><a href="#about">back to top</a></p>

## Built with

Wraps the standard open-source DFIR toolchain behind one router: **Sleuth Kit · libewf · Volatility 3 ·
Wireshark/tshark · Plaso · Chainsaw · Hayabusa · RegRipper/regipy · binwalk · foremost · bulk_extractor ·
zsteg · exiftool · ffmpeg · oletools · Didier Stevens Suite · Hindsight · bip_utils**. A per-machine
`tool-index.md` (generated, git-ignored) records what is actually installed so skills pick a variant that
exists and name a fallback for what does not.

<p align="right"><a href="#about">back to top</a></p>

## Getting Started

### Prerequisites

| Requirement | Notes |
|-------------|-------|
| macOS (Homebrew) or Debian/Ubuntu (apt) | Windows-only tools (Eric Zimmerman suite) are noted with cross-platform fallbacks |
| `python3`, `uv`, `git` | `uv` installs the Python tools (Volatility 3, Plaso, oletools, …) |
| An agent client | Claude Code · Cursor · Cline · OpenCode · Codex CLI — all supported |

### Installation

```bash
git clone git@github.com:me0w2en/forensic-skill.git && cd forensic-skill
scripts/install-tools.sh        # best-effort toolchain (brew/apt/uv/gem/gh); re-runnable
scripts/refresh-tool-index.sh   # detect installed tools -> tool-index.md (per-machine, git-ignored)
scripts/test-routing.sh         # sanity check (43-case routing regression)
```

Skills live in `skills/<name>/SKILL.md` and are symlinked into every client's native directory
(`.agents/skills`, `.claude/skills`, `.cursor/skills`, `.cline/skills`, `.opencode/skills`), so one
canonical tree serves them all. Codex/OpenCode/Cursor also read `AGENTS.md` at the repo root.

| Client | Discovery |
|--------|-----------|
| Claude Code | `.claude/skills/` · `.agents/skills/` · `CLAUDE.md`/`AGENTS.md` |
| Cursor 2.4+ | `.cursor/skills/` · `.agents/skills/` · `.cursor/rules` |
| Cline | `.cline/skills/` · `.clinerules` |
| OpenCode | `.opencode/skills/` · `.claude/skills/` · `.agents/skills/` · `AGENTS.md` |
| Codex CLI | `.agents/skills/` · `AGENTS.md` |

<p align="right"><a href="#about">back to top</a></p>

## Usage

```bash
scripts/case-init.sh mycase ~/Downloads/challenge.E01     # scaffold work/<case>/ , copy + hash artifacts
scripts/identify.sh work/*mycase/evidence/                # type / magic / entropy / ROUTE per file
scripts/route.sh   work/*mycase/evidence/* "when was the wiper run?"   # PRIMARY + SECONDARY skill
# then follow skills/<PRIMARY>/SKILL.md ; answers land in work/<case>/report/
```

Or just ask your agent in natural language ("analyze this memory dump and find the injected process") —
the router keywords and `route.sh` steer it to the right skill.

### Key files

| File | Purpose |
|------|---------|
| `skills/forensics-router/SKILL.md` | entry point: identify artifact → route → enforce hygiene |
| `config/routing.json` | routing single source of truth (kept in sync by `scripts/test-routing.sh`) |
| `ops/` | scope contract · Evidence→Finding→Answer chain · timeline templates |
| `references/` | magic bytes · timestamp epochs + NTFS MACB rules · Windows event IDs |
| `knowledge/` | public-source bibliography + your case journal (see `knowledge/README.md`) |

### Repository layout

```
AGENTS.md RULES.md README.md README_ko.md CONTRIBUTING.md LICENSE
skills/<name>/SKILL.md (+ references/)     canonical skill tree
.agents .claude .cursor .cline .opencode   per-client skills/ symlinks
config/routing.json                        routing single source of truth
scripts/       identify · route · case-init · refresh-tool-index · install-tools · test-routing
ops/           scope-contract · evidence-finding-path · timeline-workitem
references/    magic-bytes · timestamps · windows-event-ids
knowledge/     _index · web-dfir-sources bibliography · journal
work/          per-case artifacts (git-ignored)
tool-index.md  generated per machine (git-ignored)
```

<p align="right"><a href="#about">back to top</a></p>

## Skills

| Skill | Handles |
|-------|---------|
| `forensics-router` | entry point: identify artifact → route + enforce hygiene |
| `case-ops` | case scaffold, Evidence→Finding→Answer chain, report, knowledge write-back |
| `disk-image` | E01/dd/vmdk images, filesystems, deleted/lost data, format time, crypto containers |
| `memory-forensics` | RAM/vmem/core/CRIU; Volatility 3; keys & passwords recovered from RAM |
| `network-forensics` | pcap triage, stream/object export, USB HID, Bluetooth, DNS exfil, TLS |
| `windows-artifacts` | EVTX/registry/Prefetch/Amcache/SRUM/$MFT — execution, persistence, lateral movement |
| `linux-container-cloud` | Docker/OCI, K8s/CRIU checkpoints, AWS/Workspace logs, Linux server logs |
| `mobile-artifacts` | Android/iOS, app SQLite (+WAL), browser & AI-app caches, MediaStore |
| `multimedia-stego` | image/audio/video stego, container repair, spectrograms, OCR, geolocation |
| `file-format-carving` | unknown/corrupt files, archives, OOXML/HWP/PDF, PE-in-disguise (fallback) |
| `anti-forensics-timeline` | super-timeline, timestomping, wipers, log clearing, epoch conversion |
| `blockchain-forensics` | wallet recovery, fund tracing, proxy/DeFi incidents, mining IOCs |

<p align="right"><a href="#about">back to top</a></p>

## Knowledge & attribution

The skills are **self-contained**: every technique is written as general methodology. `knowledge/` holds a
public-source bibliography (`web-dfir-sources.md`) and your own case journal.

**Competition writeups are not redistributed.** The maintainer's distilled notes from specific challenges
(`knowledge/kdfc-*.md`) are **git-ignored** and never published — they are derivative of other people's
writeups. Skills credit a challenge by name in "Worked precedents" but contain no flags, passwords, keys,
IOCs, or answer values from any challenge. See [`knowledge/README.md`](knowledge/README.md).

<p align="right"><a href="#about">back to top</a></p>

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). In short: add a skill under `skills/`, wire it into
`config/routing.json` + the router table + a `test-routing.sh` case, keep it under 500 lines and dense,
and never commit competition writeups or real case data.

```bash
scripts/test-routing.sh
python3 -c "import json;json.load(open('config/routing.json'))"
for s in scripts/*.sh; do bash -n "$s"; done
```

<p align="right"><a href="#about">back to top</a></p>

## License

Distributed under the [MIT License](LICENSE). External tools and cited sources keep their own licenses;
`knowledge/web-dfir-sources.md` credits each source inline.

## Acknowledgments

- **[zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)** — the direct inspiration.
  This project borrows its "identify → route → specialist skill" pattern (a `routing.json` single source of
  truth with a regression suite, a generated tool-index, and an `ops/` combat-contract layer) and re-centres
  it on forensic **artifacts** instead of reverse-engineering tasks.
- The DFIR community whose public work is cited in `knowledge/web-dfir-sources.md` — SANS, 13Cubed, the
  Volatility/Plaso/SQLite maintainers, Eric Zimmerman, and many practitioner bloggers.

## Disclaimer

For **authorized use only**: CTFs, your own systems, a lab, or a written engagement. Public lookups (hash
reputation, blockchain explorers, what3words, music ID) are fine; **do not upload an artifact to a
third-party service without approval**. Run malware only in an isolated, no-network sandbox. Deep binary
reverse engineering beyond IOC/config extraction is out of scope. You are responsible for how you use this.

<p align="right"><a href="#about">back to top</a></p>
