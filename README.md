# Revelux

*reveal + lux — 자외선(블랙라이트)이 투명 잉크를 비춰내듯, AI 문서에 숨겨진 지시문을 드러냅니다.*

AI 파이프라인에 문서가 들어오고 나가는 두 지점을 검사하는 로컬 전용 프롬프트 인젝션 스캐너입니다.
**모든 처리는 로컬에서만 이루어지고 파일/텍스트는 어디로도 전송되지 않습니다.**

- **인바운드 (`scanner.py`)** — 외부 `.md` / `.docx` / `.pptx` / `.xlsx` / `.pdf` / `.eml` 파일을 AI에게 먹이기 *전에*, 사람 눈에는 안 보이지만 텍스트 추출 시에는 나오는 "숨겨진" 콘텐츠를 스캔
- **아웃바운드 (`outbound_gate.py`)** — AI가 방금 생성/수정한 텍스트를 화면에 보여주거나 저장하거나 다음 단계로 넘기기 *직전에* 스캔 — AI가 참고한 원본 자료에 숨어있던 인젝션을 결과물에 그대로 옮겨 담지 않았는지 확인

두 도구는 같은 탐지 엔진(유니코드 트릭, HTML 은닉 기법, 지시문 패턴)을 쓰고, 같은 형태의 JSON 결과를 내서 나중에 상시 모니터링(로그 누적 + 추세 감지) 계층을 얹기 쉽게 만들어져 있습니다.

## 설치

```bash
pip install -r requirements.txt
```

(`outbound_gate.py`와 `.eml` 처리는 파이썬 표준 라이브러리만으로 동작하므로, xlsx/docx/pptx/pdf 없이 이 둘만 쓸 거라면 별도 설치가 필요 없습니다.)

## 사용법 — 인바운드

```bash
python3 scanner.py /path/to/folder
```

옵션:

```bash
# JSON 리포트도 함께 저장
python3 scanner.py /path/to/folder --json report.json

# 특정 확장자만 스캔
python3 scanner.py /path/to/folder --ext docx,pdf,xlsx,eml
```

## 사용법 — 아웃바운드

AI 응답/생성 텍스트를 stdin으로 흘려보내거나 파일로 넘깁니다:

```bash
echo "$AI_OUTPUT" | python3 outbound_gate.py
python3 outbound_gate.py --file response.md
```

종료 코드로 파이프라인에 게이트처럼 끼워 넣을 수 있습니다 (`0`=통과, `1`=경고만, `2`=차단):

```bash
ai_call.sh | python3 outbound_gate.py --quiet && send_to_user.sh
```

옵션:

```bash
# JSON 리포트 저장
python3 outbound_gate.py --file response.md --json report.json

# 스캔 결과를 한 줄씩 JSONL로 계속 누적 (모니터링/이력용)
python3 outbound_gate.py --file response.md --log scans.jsonl
```

## 무엇을 찾아내나

1. **구조적 은닉** — 정상적으로 보면 안 보이지만 텍스트 추출 시 나오는 것들
   - Word: `hidden` 서식(vanish), 흰색/거의 흰색 텍스트, 1pt 이하 극소 폰트
   - PowerPoint: 슬라이드 밖으로 벗어난 도형, 숨김 처리된 슬라이드, 대체 텍스트(alt-text) 필드, 극소 폰트
   - Excel: 숨김 시트(hidden/veryHidden), 숨김 행/열, 흰색/거의 흰색 텍스트, 1pt 이하 극소 폰트, 시트의 정상 사용 범위를 크게 벗어난 셀, 셀 코멘트
   - PDF: 흰색/투명 텍스트, 페이지 영역 밖에 배치된 텍스트, 기본적으로 꺼져 있는 레이어(OCG), 삽입된 JavaScript
   - 이메일(.eml): 받은편지함 뷰에는 안 뜨는 커스텀 헤더, HTML 대안 파트가 있을 때 클라이언트가 절대 보여주지 않는 `text/plain` 파트, HTML 본문 안의 주석/`display:none`/흰색 텍스트, **지원 포맷(md/docx/pptx/xlsx/pdf)의 첨부파일은 재귀적으로 스캔**
   - 공통(docx/pptx/xlsx): 문서 메타데이터(작성자/제목/설명/키워드 필드), 코멘트, 스피커 노트
2. **유니코드 트릭** — 제로폭 문자, 양방향 제어 문자, variation selector, 유니코드 태그 블록(ASCII 스머글링), 라틴-키릴/그리스 문자 혼용 단어
3. **지시문 패턴** — 인바운드는 위에서 찾은 "숨겨진 영역" 안에서만 "ignore previous instructions", "system prompt", URL, `curl`, `base64` 등의 패턴을 검사합니다. 문서 본문에 정상적으로 보이는 텍스트에는 이 패턴 매칭을 적용하지 않아서, 보안을 다루는 정상 문서가 오탐되지 않습니다.

아웃바운드(`outbound_gate.py`)는 여기에 하나 더 있습니다: **숨김 처리는 안 됐지만 눈에 보이는 텍스트에 지시문 패턴이 있는 경우**도 별도로 검사합니다. AI가 방금 새로 쓴 글에 이런 문구가 있는 건 그 자체로 이례적인 신호이기 때문인데, 다만 완전히 정상적인 이유(보안을 주제로 한 글 등)로도 나올 수 있어서 WARNING까지만 매기고 CRITICAL로는 자동 승격하지 않습니다 — 숨겨진 영역 안에서 발견됐을 때만 CRITICAL입니다.

## 리스크 레벨

- 🔴 **CRITICAL** — 숨겨진 영역에서 지시문 패턴이 발견됨, 또는 심각한 유니코드 은닉(태그 블록 등) 발견
- 🟡 **WARNING** — 숨겨진 영역은 있지만 뚜렷한 지시문 패턴은 없음, 또는 (아웃바운드) 가시 텍스트에 지시문 패턴만 있음 (사람이 한 번 확인할 가치는 있음)
- 🔵 **INFO** — 경미한 유니코드 이상 또는 혼용 문자만 발견
- 🟢 **CLEAN** — 특이사항 없음

`outbound_gate.py`는 이 리스크 레벨을 종료 코드로도 내보냅니다: CLEAN/INFO → `0`, WARNING → `1`, CRITICAL → `2`.

## 한계 (중요)

- 이건 휴리스틱 도구입니다. **CLEAN이라고 해서 100% 안전을 보장하지 않습니다.** 알려진 은닉 기법들을 확인할 뿐, 새로운 기법은 놓칠 수 있습니다.
- 지시문 패턴 목록(`patterns.py`)은 확장 가능하며, 새로운 공격 문구를 발견하면 추가하는 걸 권장합니다.
- 이미지 안에 삽입된 텍스트(이미지 기반 인젝션)는 다루지 않습니다 — OCR 레이어가 필요합니다.
- `.doc`, `.ppt`, `.xls` 같은 구버전 바이너리 포맷은 지원하지 않습니다(오피스 최신 XML 기반 포맷만).
- `.msg`(Outlook 바이너리 이메일)는 지원하지 않습니다 — `.eml`(RFC 822/MIME)만 지원합니다.
- Excel의 "시트 밖 먼 셀" 탐지는 슬라이드/PDF 페이지처럼 물리적 경계가 없어서 다소 느슨한 휴리스틱입니다 — 실제로 데이터가 많은 정상 스프레드시트에서 드물게 놓치거나 과하게 잡을 수 있습니다.

## 파일 구조

```
revelux/
├── scanner.py            # 인바운드 CLI 진입점 (폴더 스캔)
├── outbound_gate.py      # 아웃바운드 CLI 진입점 (stdin/파일 텍스트 스캔)
├── unicode_utils.py      # 유니코드 이상 탐지
├── patterns.py           # 지시문 패턴 정의
├── test_samples/         # 정상/인젝션 샘플 파일 (직접 테스트용)
└── parsers/
    ├── md_parser.py
    ├── docx_parser.py
    ├── pptx_parser.py
    ├── xlsx_parser.py
    ├── pdf_parser.py
    ├── eml_parser.py      # 헤더/본문/HTML 트릭 + 첨부파일 재귀 스캔
    ├── html_utils.py      # md/eml/outbound_gate 공용 HTML 은닉 탐지
    └── ooxml_common.py    # docx/pptx/xlsx 공용 메타데이터 추출
```

## 다음 단계로 고려해볼 것: 상시 모니터링

인바운드/아웃바운드는 둘 다 "이 순간 이 파일/텍스트 하나"만 판단하는 점검(point-in-time check)입니다. 에이전트 메모리가 여러 턴에 걸쳐 서서히 오염되는 것처럼, 개별로는 무해해 보여도 누적되면 악성인 패턴은 원래 못 잡습니다. `--log`로 쌓은 JSONL을 시간축으로 모아서 보는 계층(같은 발신자에게서 반복되는 WARNING, 특정 파이프라인의 위험도 추세 등)이 자연스러운 다음 단계입니다.

## 라이선스

Copyright 2026 westbrookai

[Apache License 2.0](LICENSE) — 전문은 [NOTICE](NOTICE) 참고.
