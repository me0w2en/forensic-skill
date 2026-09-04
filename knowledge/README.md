# knowledge/

Reference knowledge that backs the skills. **What ships in this repo vs. what stays local:**

## Shipped (in git)
- **`_index.md`** — meta-heuristics and how to use this corpus.
- **`web-dfir-sources.md`** — a bibliography of public DFIR sources (SANS, 13Cubed, Volatility/Plaso/
  SQLite docs, practitioner blogs, community cheat sheets). Each entry is a URL + attribution + a short
  summary of the public technique it teaches. This is a "further reading" list, like any project's
  references section — not a reproduction of anyone's article.
- **`journal.md`** — your own anonymised case write-backs, added over time via the `case-ops` skill.

## NOT shipped (git-ignored, local-only)
- **`kdfc-*.md`** — distilled notes from specific competition writeups (Korea Digital Forensics Challenge
  2023 & 2026). These are derivative of other people's writeups and of a private challenge collection, so
  they are **deliberately kept out of the published repo** (`.gitignore`: `knowledge/kdfc-*.md`). They
  remain on the maintainer's machine as private study notes.

The **skills themselves are self-contained**: every technique they teach is written as general
methodology (commands, artifact locations, decision trees). Where a skill's "Worked precedents" section
names a challenge, it credits it as a public reference and does **not** embed the challenge's flags,
passwords, keys, IOCs, or solution values — those were scrubbed. You can use every skill without the
local `kdfc-*.md` files.

If you (the maintainer) want to publish a precedent as a full case study, write a fresh, original
write-up of a challenge you are permitted to publish and add it here as a normal tracked file — do not
commit the `kdfc-*.md` distillations.
