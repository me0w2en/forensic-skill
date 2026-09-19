# Case journal

Append one entry per solved case (via the `case-ops` skill). Keep it short and anonymised.

Template:
```markdown
## <YYYY-MM-DD> <case> — <one-line what it was>
- artifact: …   skill(s): …
- new trick: …  (or "nothing new")
- pitfall hit: …
- rule: When you see X, do Y.
```

---
<!-- entries below, newest first -->

## 2026-09-06 Linux ransomware memory dump — live-process recovery
- artifact: 6.4GB LiME dump (avml-acquired), Debian, no pre-built Volatility ISF for the exact kernel build. skill(s): memory-forensics, file-format-carving
- new trick: `linux.psscan` showed the encryptor still `TASK_RUNNING` (double-forked/daemonized, parked in `clock_nanosleep`) instead of exited — `linux.proc.Maps --dump` on the live PID pulled a plaintext `KEY=`/`IV=`-style debug leftover out of a COW-private `.data` page that the same binary's page-cache-based recovery showed as all-zero.
- built a custom Volatility Linux ISF from scratch: no matching pre-built symbols existed for the exact point-release kernel, so pulled the matching `-dbg` package straight from the distro's snapshot archive by exact version and ran `dwarf2json` on the extracted `vmlinux`.
- pitfall hit: spent a long time trying to fully re-execute/reverse the recovered binary before realizing ~half its code was legitimately never resident (unused static-linked library paths, not corruption) — page-cache recovery of a binary is inherently partial for anything the process didn't actually run.
- outcome: recovered the IV this way; the paired key was never found in any captured page (likely zeroized after use) — partial result, documented as a gap rather than guessed.
- rule: before reversing a "still encrypted, key unknown" scenario from a memory dump, check whether the responsible process is still alive (`psscan` state != `EXIT_DEAD`) — a live process's own address space beats page-cache reconstruction every time.

## 2026-09-06 Custom crypto tool, disk+memory dump — predictable PRNG seed
- artifact: ext4 disk image containing a small stripped ELF that ran a home-grown byte-substitution/permutation cipher in rounds. skill(s): disk-image, file-format-carving
- new trick: the binary seeded `rand()` from `time(NULL)` once at startup, then consumed the same stream for both per-round table generation and the "which operation this round" choice. Reimplementing glibc's public TYPE_3 `rand()`/`srand()` algorithm in Python (verified against the well-known seed=1 output sequence) and brute-forcing the handful of seed candidates around the ciphertext file's own nanosecond-resolution mtime recovered the exact seed for every fragment independently.
- pitfall hit: the naive fix (just re-running the forward algorithm) doesn't decrypt — had to replay the RNG call order in forward chronological order to reconstruct each round's table/choice, then apply the *inverse* of each round in *reverse* order against the ciphertext.
- rule: `srand(time())`-class seeding turns "custom unbreakable crypto" into a filesystem-timestamp lookup problem — check for this before attempting real cryptanalysis.

## 2026-09-06 OOXML doc with hidden ZIP behind an orphan image
- artifact: a `.docx` that looked like an ordinary report. skill(s): file-format-carving
- new trick: a `word/media/*.png` with zero relationship references (not in any `.rels`) carried a zip appended after its `IEND`, missing its EOCD record (rebuilt by hand — see skill Phase 4). The inner ZipCrypto password was hidden in a hand-inserted, unregistered `customXml` part as a decoy-looking value; large wordlist/rule-based brute-force on the password got nowhere because the real move was an encoding-order fix (rotate-then-decode), not a bigger dictionary.
- pitfall hit: dismissed the suspicious `customXml` string as a red herring after one direct decode attempt failed — cost significant time before reconsidering the decode *order*.
- rule: a `customXml` part with no matching `itemPropsN.xml`/`.rels` is never something Office produced on its own — decode it every way before writing it off as flavour text.

## 2026-09-05 KDFS-2023 ransomware E01 — first real end-to-end test of the pack
- artifact: 21GB E01 (Win10 Pro 22H2, user souldrag). skill(s): disk-image, windows-artifacts, mobile-artifacts, file-format-carving, blockchain-forensics, (gap) email-clients
- matched the writeup exactly: image hashes, system info (host DESKTOP-K7VGB7O, install 2023-09-11 KST), installed programs (Ledger Live, Blockstream Green), Chrome search keywords + downloads + gofile upload, Discord account via Chrome Cache, ransom.exe SHA-1 0b88dd85… (PyInstaller/py3.10/PyArmor), Ledger app.json wallet addrs.
- biggest gap: the decisive evidence (suspect's 2 Gmail accounts, loan-shark extortion mail, victims' decryptor-request mails w/ pasted BTC tx) lived only in AppData\Local\Microsoft\Outlook\*.ost. Pack had NO email-client skill -> created `email-clients` (readpst/pffexport/pypff, EML/MBOX stdlib).
- harness bugs found & fixed: identify.sh hashed a 21GB image to timeout (now skips >2GiB, follows symlinks with stat -L); case-init.sh copied artifacts (added --link + auto-link >2GiB); regipy CLI was broken out of the box (missing click/tabulate) — install-tools now injects deps, and refresh-tool-index now RUNS each probe and flags ⚠️ present-but-broken.
- blockchain-forensics: added desktop-wallet artifact paths (Ledger Live app.json, Blockstream Green, MetaMask extension LevelDB vault, Electrum).
- rule: on a disk image, always pull the Outlook OST/PST — webmail login in the browser is NOT the mail; the content is in the store.
