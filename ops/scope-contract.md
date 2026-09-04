# Scope Contract (`work/<case>/scope.md`)

Every case starts with a scope file. For CTF work the gate is trivial (`basis: ctf_public`),
but the file still exists so the agent records *what* it is analysing, *which timezone the
answer must be in*, and *which artifacts are in scope*. No scope file → read-only triage only.

```markdown
# Case Scope

## meta
- case_id: {YYYYMMDD-shortname}          # e.g. 20260904-kdfc-151
- created: {ISO-8601}
- operator: {name or "local"}
- primary_skill: {from forensics-router}
- challenge_source: {CTF name / URL / "private"}

## auth
- status: granted | pending | denied
- basis: ctf_public | own_system | lab_only | written_contract
- MUST NOT run anything that touches a live third-party system unless basis permits it

## artifacts
- path: {absolute path to original, read-only}
  md5: {provided by challenge, if any}
  sha256: {computed}
  verified: true | false                 # provided hash == computed hash
- working_copy: work/<case>/evidence/    # analyse copies, never originals

## question
- asked: |
    {verbatim challenge text / questions}
- answer_format: {flag regex, "UTC+0", "[ProductID].[BuildID].[Count]", ...}
- timezone: UTC+0 | UTC+9 | as-stated    # KDFC alternates — read the prompt every time

## network_profile
- mode: offline | lab_only | public_lookup_ok
- notes: public_lookup_ok = hash lookups, blockchain explorers, what3words etc. are fine;
         never upload the artifact itself to a third-party service without asking

## signoff
- ready_for_act: false
- checklist:
  - [ ] hashes verified (or recorded as "not provided")
  - [ ] timezone for answers recorded
  - [ ] working copy created, original left untouched
  - [ ] identify.sh run on every artifact
```
