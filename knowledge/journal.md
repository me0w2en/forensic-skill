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

## 2026-09-05 KDFS-2023 ransomware E01 — first real end-to-end test of the pack
- artifact: 21GB E01 (Win10 Pro 22H2, user souldrag). skill(s): disk-image, windows-artifacts, mobile-artifacts, file-format-carving, blockchain-forensics, (gap) email-clients
- matched the writeup exactly: image hashes, system info (host DESKTOP-K7VGB7O, install 2023-09-11 KST), installed programs (Ledger Live, Blockstream Green), Chrome search keywords + downloads + gofile upload, Discord account via Chrome Cache, ransom.exe SHA-1 0b88dd85… (PyInstaller/py3.10/PyArmor), Ledger app.json wallet addrs.
- biggest gap: the decisive evidence (suspect's 2 Gmail accounts, loan-shark extortion mail, victims' decryptor-request mails w/ pasted BTC tx) lived only in AppData\Local\Microsoft\Outlook\*.ost. Pack had NO email-client skill -> created `email-clients` (readpst/pffexport/pypff, EML/MBOX stdlib).
- harness bugs found & fixed: identify.sh hashed a 21GB image to timeout (now skips >2GiB, follows symlinks with stat -L); case-init.sh copied artifacts (added --link + auto-link >2GiB); regipy CLI was broken out of the box (missing click/tabulate) — install-tools now injects deps, and refresh-tool-index now RUNS each probe and flags ⚠️ present-but-broken.
- blockchain-forensics: added desktop-wallet artifact paths (Ledger Live app.json, Blockstream Green, MetaMask extension LevelDB vault, Electrum).
- rule: on a disk image, always pull the Outlook OST/PST — webmail login in the browser is NOT the mail; the content is in the store.
