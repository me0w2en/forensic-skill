---
name: network-forensics
description: |
  Packet-capture and protocol forensics: triage a pcap/pcapng, follow and export streams, extract fields,
  decrypt TLS, and reconstruct payloads from USB HID, Bluetooth (BLE/A2DP), DNS tunnels, and Wi-Fi. Enter
  when the artifact is a .pcap/.pcapng/.cap, a USB or Bluetooth HCI capture, or flow logs, and the question
  is about exfiltrated data, C2, transferred files, typed keystrokes, mouse drawings, or audio in traffic.
  Trigger keywords: pcap, pcapng, 패킷, 네트워크 포렌식, wireshark, tshark, capinfos, follow stream,
  export objects, usb hid, usb.capdata, keyboard, mouse, bluetooth, btatt, BLE, A2DP, RTP, SBC, morse,
  dns exfil, dns tunnel, dnscat2, iodine, sslkeylog, editcap inject-secrets, TLS, wpa, eapol, 802.11.
---

# Network / PCAP Forensics

You have traffic. Triage first (what protocols, who talks to whom), then reconstruct the payload the
question asks for. Many "network" challenges are really payload-reconstruction of HID/audio/DNS.

## ACTION REQUIRED (do now, do not stop to confirm)
1. `NOW`  Confirm router entry + `work/<case>/` (hashes verified, timezone/format recorded).
2. `NOW`  Read `../../tool-index.md`: `tshark`/`capinfos`/`editcap`/`mergecap` ✅ (Wireshark), `tcpflow`,
   `ngrep`, `python3`+`pyshark` where present.
3. `NEXT` Triage: `capinfos`, then Protocol Hierarchy / Conversations to see what matters.
4. `NEXT` Pick the reconstruction: stream/object export, field extraction, or HID/BT/DNS decode.
5. `ACT`  Save carved objects to `work/<case>/extracted/`, hash, verify with `file`, log to `timeline.md`.

## When to use / hand off
| If it's really… | Go to |
|---|---|
| A carved file that is itself an image/audio/video with stego | `skills/multimedia-stego/` |
| A carved archive/document/PE | `skills/file-format-carving/` |
| Cloud flow logs (VPC Flow), CloudTrail, GuardDuty | `skills/linux-container-cloud/` |
| TLS keys / passwords found in a disk or memory image | get them from `disk-image`/`memory-forensics`, then decrypt here |

## Tools (install-name → what it's for)
- `tshark` ✅ — CLI Wireshark: filters, field extraction, stream follow, object export.
- `capinfos` ✅ — capture summary (packet count, duration, encapsulation).
- `editcap` ✅ — slice/convert; `--inject-secrets tls,keylog.txt` embeds TLS keys into pcapng.
- `mergecap` ✅ — merge captures.
- `tcpflow` (brew) — split every TCP stream to a file: `tcpflow -r cap.pcap`.
- `ngrep` (brew) — grep packet payloads.
- Wireshark GUI — RTP Player (audio), Decode As, IO graphs; use for A2DP/RTP.
- `python3` + `pyshark`/`scapy` — programmatic decode (HID/BT reconstruction).
- `ctf-usb-keyboard-parser` (github TeamRocketIst) — USB HID keystroke decoder.

## Workflow

### Phase 1 — Triage
```bash
capinfos cap.pcapng
tshark -r cap.pcapng -q -z io,phs                 # protocol hierarchy
tshark -r cap.pcapng -q -z conv,tcp               # conversations
tshark -r cap.pcapng -Y 'frame.comment' -T fields -e frame.comment   # hidden packet comments!
```

### Phase 2 — Follow & export
```bash
tshark -r cap.pcapng -q -z follow,tcp,raw,0       # dump TCP stream 0 as hex
# Export carved objects (HTTP/SMB/SMTP/FTP-DATA/TFTP):
tshark -r cap.pcapng --export-objects http,extracted/http
# Manual file carve from a stream, then verify:
tshark -r cap.pcapng -q -z follow,tcp,raw,3 | tr -d '\n' | xxd -r -p > extracted/blob; file extracted/blob
```

### Phase 3 — Field extraction
```bash
tshark -r cap.pcapng -Y 'dns' -T fields -e dns.qry.name
tshark -r cap.pcapng -Y 'http.request' -T fields -e http.host -e http.request.uri -E separator=,
```

### Phase 4 — TLS decryption
```bash
# If a key log file was found elsewhere in the evidence (Desktop, or 'CLIENT_RANDOM' strings in a memdump):
tshark -r cap.pcapng -o tls.keylog_file:keylog.txt -Y http2 -T fields -e http2.data.data
editcap --inject-secrets tls,keylog.txt cap.pcapng cap-dec.pcapng    # permanent (pcapng only)
```
RSA-key decryption only works for static-RSA handshakes fully captured — never for (EC)DHE or TLS 1.3.

### Phase 5 — USB HID (keyboard & mouse)
```bash
# Keyboard: 8-byte reports [modifier,reserved,k1..k6]; modifier 0x02/0x20 = shift; 0x2A backspace.
tshark -r kb.pcap -Y 'usb.capdata && usb.data_len == 8' -T fields -e usb.capdata > keys.txt
python3 usbkeyboard.py keys.txt        # ctf-usb-keyboard-parser; ignore all-zero (release) frames
# Some dissectors expose usbhid.data instead of usb.capdata — try both; filter by device address (usb.src) if noisy.
```
Mouse: reports carry signed X/Y deltas; integrate deltas, plot points while a button is held → a drawing.

### Phase 6 — Bluetooth (BLE mouse / A2DP audio / BLE keyboard) — KDFC #105 pattern
```bash
# Identify the device: ATT Device Information (Manufacturer/Model strings).
# BLE mouse: btatt.value 7-byte reports, byte0 button, byte2 X, byte3 Y (signed int8) -> scatter plot.
python3 - <<'PY'
import pyshark, matplotlib.pyplot as plt
x=y=0; X=[];Y=[]
for p in pyshark.FileCapture('mouse.pcap', display_filter='btatt'):
    v=p['btatt'].get_field_value('value')
    if not v: continue
    b=v.split(':')
    if len(b)!=7: continue
    dx=int(b[2],16); dy=int(b[3],16); dx-=256 if dx>127 else 0; dy-=256 if dy>127 else 0
    x+=dx; y+=dy
    if b[0] in ('01','02'): X.append(x); Y.append(-y)   # Y inverted (screen grows down)
plt.scatter(X,Y); plt.show()
PY
```
A2DP audio: Wireshark → Telephony → RTP → RTP Streams → **RTP Player** to hear the SBC stream (often Morse
→ decode in CyberChef "From Morse Code"). BLE keyboard: ATT Handle Value Notifications carry HID reports;
map keycodes with the USB HID usage table; you can byte-scan the pcap for the fixed ATT notification prefix.

### Phase 7 — DNS exfil / tunnel
```bash
tshark -r dns.pcap -Y dns -T fields -e dns.qry.name > names.txt
# strip the zone, dedupe retransmits, decode:
sed 's/\.example\.com//' names.txt | sort -u | tr -d '\n' | base32 -d
# dnscat2: first 9 bytes of each message are header — skip 18 hex chars per label before decoding.
```

## Flag-hiding checklist
- `frame.comment` / pcapng packet comments — a favourite hiding place.
- Files transferred over HTTP/SMB/SMTP/FTP — export objects, verify with `file`.
- Keystrokes in USB HID — remember backspace (0x2A), shift modifier, ignore release frames.
- Mouse-movement handwriting — integrate signed deltas, plot only while a button is held.
- Audio in A2DP/RTP — RTP Player, expect Morse/DTMF/speech.
- DNS tunnel — long high-entropy leftmost labels; strip protocol header + dedupe before decode.
- TLS payloads — hunt for a key log file elsewhere in the evidence; inject and decrypt.
- Wi-Fi — needs the EAPOL handshake; decrypt with `wpa-pwd password:SSID`.
- Base/hex/xor chains inside a stream — CyberChef Magic.

## Pitfalls
- Signed int8 deltas: forgetting two's-complement scrambles the mouse drawing.
- USB report length/dissector varies by capture — check both `usb.capdata` and `usbhid.data`, filter by device address.
- RTP Player only appears when the stream is dissected as RTP — use Decode As if needed.
- TLS 1.3 / DHE cannot be decrypted with an RSA key — you need the session-key log.
- Deduplicate DNS retransmits before concatenating, or the payload corrupts.

## Worked precedents
- **KDFC2023 #105 BlueShark** — three Bluetooth captures: BLE mouse → drawn text, A2DP → Morse via RTP Player, BLE keyboard → HID decode.
- Web sources: USB-HID parsing, DNS-tunneling fingerprints, TLS injection — `knowledge/web-dfir-sources.md` §3.

## References
- `../../references/magic-bytes.md` (verify carved objects)
- Wireshark display filter reference: https://www.wireshark.org/docs/dfref/
- Jorian Woltjer, Practical CTF — Wireshark: https://book.jorianwoltjer.com/forensics/wireshark
- Unit 42 export objects: https://unit42.paloaltonetworks.com/using-wireshark-exporting-objects-from-a-pcap/
- ctf-usb-keyboard-parser: https://github.com/TeamRocketIst/ctf-usb-keyboard-parser
