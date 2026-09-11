---
name: email-clients
description: |
  Desktop email-client and mailbox forensics: Outlook OST/PST, Thunderbird/mbox, and standalone EML/MSG
  messages. Extract accounts, headers, bodies, attachments, and timestamps, then build a sender/recipient
  timeline. Enter when the artifact is an .ost/.pst/.mbox/.eml/.msg file, an `AppData\Local\Microsoft\Outlook`
  or Thunderbird profile, or the question is about who emailed whom, ransom/extortion mail, or an email
  account tied to a suspect. Webmail left only in a browser (Gmail/Naver in history/cache) belongs to
  mobile-artifacts; this skill is for on-disk mail stores.
  Trigger keywords: email, 이메일, 메일, outlook, ost, pst, .ost, .pst, mbox, eml, msg, thunderbird, mapi,
  readpst, pffexport, pffinfo, pypff, libpff, libpst, extrautil, aid4mail, SysTools OST Viewer, Kernel OST,
  webcache, attachments, 첨부파일, 수신자, 발신자, ransom mail, extortion, 채무, 협박메일.
---

# Email Client & Mailbox Forensics

Desktop mail stores (Outlook OST/PST especially) are a goldmine that browser/webmail analysis misses.
Convert the store to readable messages, then answer who/when/what and pull attachments.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/` (hashes verified, timezone/format recorded).
2. `NOW`  Read `../../tool-index.md`: `readpst` (libpst) handles PST; OST needs `pffexport`/`pffinfo`
   (libpff) or `pypff`. EML/MBOX/MSG parse with Python stdlib (no install).
3. `NEXT` Locate the store: Outlook `Users\<u>\AppData\Local\Microsoft\Outlook\*.ost|*.pst`;
   Thunderbird `AppData\Roaming\Thunderbird\Profiles\*\Mail|ImapMail\**` (mbox); loose `.eml`/`.msg`.
4. `NEXT` Extract to `work/<case>/extracted/mail/`, then grep headers/bodies and build a timeline.
5. `ACT`  Convert every mail timestamp to the challenge timezone; hash attachments; log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| Gmail/Naver webmail only seen in browser history/cache | `skills/mobile-artifacts/` (Chromium history/cache) |
| The mail store is inside a disk image you haven't mounted | `skills/disk-image/` (icat the .ost/.pst out first) |
| An attachment that is malware / a wallet / a document | `skills/file-format-carving/` · `skills/blockchain-forensics/` |
| A crypto address/tx pasted in a ransom mail | `skills/blockchain-forensics/` |

## Tools (install-name → what it's for)
- `readpst` ✅ (libpst; `brew install libpst`) — PST → mbox/EML: `readpst -e -o out mailbox.pst`. Reads some OST but OST support is partial.
- `pffexport` / `pffinfo` (libpff; not in brew — build from source or docker) — the robust OST **and** PST tool.
  `pffinfo store.ost` (summary), `pffexport -f all -t out store.ost` (export items/attachments).
- `pypff` (pip `libpff-python`; builds from source) — scriptable OST/PST. Use via `uv run --with libpff-python python3 …`.
- Python stdlib — `email` (EML/MSG-ish), `mailbox` (mbox/Maildir), `extract_msg` (pip) for Outlook `.msg`.
- `strings` ✅ — quick triage of an OST when no parser is available (recovers addresses/subjects/bodies).
- GUI fallbacks (Windows): SysTools/Kernel OST Viewer, Aid4Mail, Xtraxtor — what many KDFС writeups used.

## Workflow

### Phase 1 — Locate and carve the store out of the image
```bash
# from a mounted/TSK image, pull the Outlook store (path via disk-image skill):
#   AppData\Local\Microsoft\Outlook\<account>.ost
icat -o <part_start> image.E01 <ost_inode> > work/<case>/extracted/outlook.ost
pffinfo work/<case>/extracted/outlook.ost 2>/dev/null | head        # confirm it parses
```

### Phase 2 — Convert / export
```bash
# PST (and try OST):
readpst -e -D -o work/<case>/extracted/mail work/<case>/extracted/store.pst   # -e per-message .eml, -D include deleted
# OST (robust) with libpff:
pffexport -f all -t work/<case>/extracted/pff work/<case>/extracted/outlook.ost
# scriptable (pypff) — list folders/messages, dump headers:
uv run --with libpff-python python3 - work/<case>/extracted/outlook.ost <<'PY'
import sys, pypff
pff=pypff.file(); pff.open(sys.argv[1])
def walk(f, depth=0):
    for i in range(f.number_of_sub_messages):
        m=f.get_sub_message(i)
        print(m.get_delivery_time(), '|', m.get_sender_name(), '|', m.get_subject())
    for i in range(f.number_of_sub_folders):
        walk(f.get_sub_folder(i), depth+1)
walk(pff.get_root_folder())
PY
```

### Phase 3 — Accounts, headers, timeline
```bash
# accounts / addresses seen in the store:
grep -rhoiE '[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}' work/<case>/extracted/mail | sort -u
# per-message headers (From/To/Date/Subject) for the timeline:
for f in work/<case>/extracted/mail/**/*.eml; do
  python3 - "$f" <<'PY'
import sys,email,email.utils
m=email.message_from_binary_file(open(sys.argv[1],'rb'))
print(m.get('Date'),'|',m.get('From'),'->',m.get('To'),'|',m.get('Subject'))
PY
done | sort
```

### Phase 4 — Attachments (verify, then hand off)
```bash
# libpff/readpst write attachments alongside messages; hash and identify each:
find work/<case>/extracted -type f \( -iname '*.jpg' -o -iname '*.png' -o -iname '*.exe' -o -iname '*.zip' -o -iname '*.pdf' -o -iname '*.xlsx' \) \
  -exec sh -c 'echo "$(shasum -a256 "$1" | cut -d" " -f1)  $1"; file "$1"' _ {} \;
# a ransom-note screenshot may carry a tx id / wallet address -> blockchain-forensics
```

### Phase 5 — Deleted / orphaned mail
- `readpst -D` includes deleted items; `pffexport` recovers items in the OST that Outlook hid.
- When no parser is available, `strings -e l work.ost | grep -iE '@|subject|bitcoin|btc|decrypt'` recovers a surprising amount.

## Flag-hiding checklist
- A suspect who runs a "clean" webmail account but keeps a second account in the OST for illicit use (KDFS 2023: personal vs ransom-collection Gmail, both only provable from the OST).
- Ransom / extortion mail: sender address, subject, and a pasted transaction id or wallet address in the body or a screenshot attachment.
- Deleted mail recoverable from the OST/PST that is gone from the live mailbox view.
- Attachments (xlsx trading journals, infected images, decryptor requests) hashed and pivoted to other skills.
- Multilingual ransom demands (same message in several languages) — a common extortion tell.

## Pitfalls
- OST ≠ PST: `readpst` may only partially read OST; prefer `pffexport`/`pypff` for OST.
- Convert mail timestamps (usually UTC in headers) to the challenge's timezone; state the offset.
- Do not confuse a webmail login seen in the browser with proof of mail content — the content lives in the store.
- Attachments extracted to disk inherit no MOTW; treat executables as untrusted (sandbox only).

## Worked precedents
- **KDFS 2023 ransomware case** — the decisive evidence (suspect's two Gmail accounts, the loan-shark extortion mail, victims' decryptor-request mails with pasted BTC transactions) lived only in `AppData\Local\Microsoft\Outlook\*.ost`; browser history showed the Gmail *login* but not the mail. OST parsing was required.

## References
- `../../references/timestamps.md` (header dates → timezone)
- libpst / readpst: https://www.five-ten-sg.com/libpst/
- libpff (pffexport/pffinfo, OST+PST): https://github.com/libyal/libpff
- Python `email`/`mailbox` stdlib; `extract_msg` for `.msg`: https://github.com/TeamMsgExtractor/msg-extractor
