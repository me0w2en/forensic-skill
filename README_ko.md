<p align="center">
  <h1 align="center">forensic-skill</h1>
  <h3 align="center">디지털 포렌식 스킬 라우터 · Digital Forensics Skills Router</h3>
  <p align="center"><i>아티팩트와 질문을 건네면, 에이전트가 추측 대신 알맞은 도구를 고릅니다.</i></p>
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-green.svg" alt="MIT License"></a>
  <a href="https://github.com/me0w2en/forensic-skill/actions/workflows/ci.yml"><img src="https://github.com/me0w2en/forensic-skill/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/skills-12-blue.svg" alt="12 skills">
  <img src="https://img.shields.io/badge/routing%20tests-43%20passing-brightgreen.svg" alt="43 routing tests">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey.svg" alt="platform">
</p>

<p align="center">
  <a href="#소개">소개</a> ·
  <a href="#시작하기">시작하기</a> ·
  <a href="#사용법">사용법</a> ·
  <a href="#스킬-목록">스킬 목록</a> ·
  <a href="README.md">English</a>
</p>

---

## 소개

**forensic-skill**은 디지털 포렌식 CTF와 인가된 DFIR을 위한 클라이언트 중립 에이전트 스킬 팩입니다.
어떤 AI 코딩 에이전트(Claude Code, Cursor, Cline, OpenCode, Codex CLI 등)든 이 저장소를 물리면, 아티팩트를
받아 유형을 식별하고 올바른 처리 규칙(해시 검증, 읽기 전용 작업, 답변 타임존 기록)을 강제한 뒤 12개의 전문
스킬 중 하나로 안내합니다. 각 스킬은 바로 실행 가능한 명령, 플래그 은닉 체크리스트, 함정을 담은 밀도 높은
플레이북입니다.

이 프로젝트는 [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)의 "식별, 라우팅,
전문 스킬" 패턴(회귀 테스트를 갖춘 `routing.json` 단일 진실 공급원, 생성형 tool-index, `ops/` 전투 계약 계층)을
빌려와, 리버싱 작업이 아닌 포렌식 아티팩트 중심으로 재설계했습니다.

CTF 포렌식은 "이 파일엔 어떤 도구를 써야 하지?"에서 시간을 낭비합니다. 이 팩은 그 질문에 결정적으로 답합니다.

```
아티팩트 + 질문
  -> forensics-router
  -> identify.sh (매직 / 엔트로피)
  -> routing.json
  -> 전문 스킬 (실행 가능한 플레이북)

진행 중: 해시 검증, 읽기 전용 작업, 타임존 기록.
결과물: work/<case>/ 에 증거 -> 발견 -> 답변 체인
(각 항목은 직접 / 상관 / 보류 등급)과 보고서.
```

<p align="right"><a href="#소개">맨 위로</a></p>

## 구성 도구

표준 오픈소스 DFIR 도구 체인을 하나의 라우터 뒤에 묶습니다: **Sleuth Kit · libewf · Volatility 3 ·
Wireshark/tshark · Plaso · Chainsaw · Hayabusa · RegRipper/regipy · binwalk · foremost · bulk_extractor ·
zsteg · exiftool · ffmpeg · oletools · Didier Stevens Suite · Hindsight · bip_utils**. 머신별로 생성되는
`tool-index.md`(생성물, git 제외)가 실제 설치된 도구를 기록해, 스킬이 존재하는 도구를 고르고 없는 도구는
대안을 안내합니다.

<p align="right"><a href="#소개">맨 위로</a></p>

## 시작하기

### 사전 요구사항

| 항목 | 설명 |
|------|------|
| macOS(Homebrew) 또는 Debian/Ubuntu(apt) | Windows 전용 도구(Eric Zimmerman 스위트)는 크로스플랫폼 대안을 함께 안내 |
| `python3`, `uv`, `git` | `uv`가 파이썬 도구(Volatility 3, Plaso, oletools 등)를 설치 |
| 에이전트 클라이언트 | Claude Code · Cursor · Cline · OpenCode · Codex CLI 모두 지원 |

### 설치

```bash
git clone git@github.com:me0w2en/forensic-skill.git && cd forensic-skill
scripts/install-tools.sh        # 최선 노력 도구 설치 (brew/apt/uv/gem/gh); 반복 실행 가능
scripts/refresh-tool-index.sh   # 설치된 도구 감지 -> tool-index.md (머신별, git 제외)
scripts/test-routing.sh         # 정상 동작 확인 (라우팅 회귀 43케이스)
```

스킬은 `skills/<name>/SKILL.md`에 있고, 각 클라이언트의 기본 디렉터리(`.agents/skills`, `.claude/skills`,
`.cursor/skills`, `.cline/skills`, `.opencode/skills`)로 심볼릭 링크됩니다. 하나의 정본 트리가 모든
클라이언트를 지원합니다. Codex/OpenCode/Cursor는 루트의 `AGENTS.md`도 읽습니다.

| 클라이언트 | 인식 경로 |
|-----------|-----------|
| Claude Code | `.claude/skills/` · `.agents/skills/` · `CLAUDE.md`/`AGENTS.md` |
| Cursor 2.4+ | `.cursor/skills/` · `.agents/skills/` · `.cursor/rules` |
| Cline | `.cline/skills/` · `.clinerules` |
| OpenCode | `.opencode/skills/` · `.claude/skills/` · `.agents/skills/` · `AGENTS.md` |
| Codex CLI | `.agents/skills/` · `AGENTS.md` |

<p align="right"><a href="#소개">맨 위로</a></p>

## 사용법

```bash
scripts/case-init.sh mycase ~/Downloads/challenge.E01     # work/<case>/ 생성, 아티팩트 복사 + 해시
scripts/identify.sh work/*mycase/evidence/                # 파일별 유형 / 매직 / 엔트로피 / ROUTE
scripts/route.sh   work/*mycase/evidence/* "언제 와이퍼가 실행됐나?"   # PRIMARY + SECONDARY 스킬
# 이후 skills/<PRIMARY>/SKILL.md 를 따르고, 답은 work/<case>/report/ 에 정리
```

또는 자연어로 요청해도 됩니다("이 메모리 덤프를 분석해서 인젝션된 프로세스를 찾아줘"). 라우터 키워드와
`route.sh`가 알맞은 스킬로 안내합니다.

### 핵심 파일

| 파일 | 역할 |
|------|------|
| `skills/forensics-router/SKILL.md` | 진입점: 아티팩트 식별, 라우팅, 처리 규칙 강제 |
| `config/routing.json` | 라우팅 단일 진실 공급원 (`scripts/test-routing.sh`가 동기화 검증) |
| `ops/` | 스코프 계약 · 증거-발견-답변 체인 · 타임라인 템플릿 |
| `references/` | 매직바이트 · 타임스탬프 에폭 + NTFS MACB 규칙 · Windows 이벤트 ID |
| `knowledge/` | 공개 출처 서지 + 케이스 저널 (`knowledge/README.md` 참고) |

### 저장소 구조

```
AGENTS.md RULES.md README.md README_ko.md CONTRIBUTING.md LICENSE
skills/<name>/SKILL.md (+ references/)     정본 스킬 트리
.agents .claude .cursor .cline .opencode   클라이언트별 skills/ 심링크
config/routing.json                        라우팅 단일 진실 공급원
scripts/       identify · route · case-init · refresh-tool-index · install-tools · test-routing
ops/           scope-contract · evidence-finding-path · timeline-workitem
references/    magic-bytes · timestamps · windows-event-ids
knowledge/     _index · web-dfir-sources 서지 · journal
work/          케이스별 아티팩트 (git 제외)
tool-index.md  머신별 생성물 (git 제외)
```

<p align="right"><a href="#소개">맨 위로</a></p>

## 스킬 목록

| 스킬 | 담당 |
|------|------|
| `forensics-router` | 진입점: 아티팩트 식별, 라우팅, 처리 규칙 강제 |
| `case-ops` | 케이스 스캐폴딩, 증거-발견-답변 체인, 보고서, 지식 회수 기록 |
| `disk-image` | E01/dd/vmdk 이미지, 파일시스템, 삭제/유실 데이터, 포맷 시각, 암호화 컨테이너 |
| `memory-forensics` | RAM/vmem/core/CRIU; Volatility 3; RAM에서 키·비밀번호 복구 |
| `network-forensics` | pcap 분류, 스트림/객체 추출, USB HID, 블루투스, DNS 유출, TLS |
| `windows-artifacts` | EVTX/레지스트리/Prefetch/Amcache/SRUM/$MFT 실행·지속성·측면이동 |
| `linux-container-cloud` | Docker/OCI, K8s/CRIU 체크포인트, AWS/Workspace 로그, 리눅스 서버 로그 |
| `mobile-artifacts` | Android/iOS, 앱 SQLite(+WAL), 브라우저·AI앱 캐시, MediaStore |
| `multimedia-stego` | 이미지/오디오/영상 스테가노그래피, 컨테이너 복구, 스펙트로그램, OCR, 위치추정 |
| `file-format-carving` | 알 수 없는/손상 파일, 아카이브, OOXML/HWP/PDF, 위장 PE (폴백) |
| `anti-forensics-timeline` | 슈퍼 타임라인, 타임스톰핑, 와이퍼, 로그 삭제, 에폭 변환 |
| `blockchain-forensics` | 지갑 복구, 자금 추적, 프록시/DeFi 사건, 채굴 IOC |

<p align="right"><a href="#소개">맨 위로</a></p>

## 지식과 출처

스킬은 자기 완결적입니다. 모든 기법은 일반화된 방법론으로 작성돼 있습니다. `knowledge/`에는 공개 출처
서지(`web-dfir-sources.md`)와 케이스 저널만 들어 있습니다.

대회 라이트업은 재배포하지 않습니다. 특정 문제에서 증류한 관리자 개인 노트(`knowledge/kdfc-*.md`)는
git에서 제외되어 공개되지 않습니다. 타인의 라이트업에서 파생된 자료이기 때문입니다. 스킬의 "Worked
precedents"는 문제 이름만 인용할 뿐, 어떤 문제의 플래그·비밀번호·키·IOC·정답 값도 담지 않습니다. 자세한
내용은 [`knowledge/README.md`](knowledge/README.md)를 참고하세요.

<p align="right"><a href="#소개">맨 위로</a></p>

## 면책 조항

인가된 용도로만 사용하세요: CTF, 본인 소유 시스템, 랩, 서면 계약이 있는 업무. 공개 조회(해시 평판,
블록체인 익스플로러, what3words, 음악 인식)는 괜찮지만, 승인 없이 아티팩트 자체를 외부 서비스에 업로드하지
마세요. 악성코드는 격리된 무네트워크 샌드박스에서만 실행하세요. IOC/설정 추출을 넘어서는 심층 바이너리
리버싱은 범위 밖입니다. 사용에 대한 책임은 사용자에게 있습니다.

<p align="right"><a href="#소개">맨 위로</a></p>
