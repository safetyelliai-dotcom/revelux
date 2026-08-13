# Revelux

*reveal + lux — the way a blacklight brings out invisible ink, Revelux brings out instructions hidden in documents.*

Revelux is a local-only prompt-injection scanner for the two points where documents enter and leave an AI pipeline. **Nothing is uploaded — every file and every string is processed on your own machine.**

- **Inbound (`scanner.py`)** — scans `.md` / `.docx` / `.pptx` / `.xlsx` / `.pdf` / `.eml` files *before* you feed them to an AI, looking for content a human reader never sees but a text-extraction pipeline reads in full.
- **Outbound (`outbound_gate.py`)** — scans text an AI just wrote *before* it is displayed, saved, or passed downstream, catching injections the model copied verbatim out of poisoned source material.

Both share one detection engine (unicode tricks, HTML hiding techniques, instruction patterns) and emit the same JSON shape, so a monitoring layer can be layered on later without reworking either gate.

## Install

```bash
pip install -r requirements.txt
```

`outbound_gate.py` and `.eml` parsing rely only on the standard library, so if those are all you need, no install step is required.

## Usage — inbound

```bash
python3 scanner.py /path/to/folder
```

Options:

```bash
# also write a full JSON report
python3 scanner.py /path/to/folder --json report.json

# restrict which extensions are scanned
python3 scanner.py /path/to/folder --ext docx,pdf,xlsx,eml
```

## Usage — outbound

Pipe the AI's output in on stdin, or point it at a file:

```bash
echo "$AI_OUTPUT" | python3 outbound_gate.py
python3 outbound_gate.py --file response.md
```

Exit codes let it act as a real gate in a shell pipeline (`0` = pass, `1` = warn, `2` = block):

```bash
ai_call.sh | python3 outbound_gate.py --quiet && send_to_user.sh
```

Options:

```bash
# write a JSON report
python3 outbound_gate.py --file response.md --json report.json

# append each scan as one JSON line, for history/monitoring
python3 outbound_gate.py --file response.md --log scans.jsonl
```

## What it detects

**1. Structural hiding** — content that is invisible in normal viewing but comes straight out of text extraction:

| Format | Techniques detected |
| --- | --- |
| Word | `w:vanish` hidden-text formatting, white / near-white text, fonts ≤ 1pt |
| PowerPoint | shapes positioned off-slide, hidden slides, alt-text/description fields, tiny fonts |
| Excel | hidden sheets (`hidden` / `veryHidden`), hidden rows and columns, white / near-white text, tiny fonts, cells far outside the used range, cell comments |
| PDF | white or transparent text, text placed outside the visible page area, optional content groups (layers) off by default, embedded JavaScript |
| Email (`.eml`) | headers that never appear in an inbox view, the `text/plain` part when an HTML alternative exists (clients render the HTML, so that part is never shown), HTML comments / `display:none` / white-on-white text in the body, and **attachments scanned recursively — including forwarded `.eml` messages** |
| Shared (OOXML) | document metadata fields (author, title, description, keywords), comments, speaker notes |

**2. Unicode tricks** — zero-width characters, bidi override characters, variation selectors, the Unicode tag block (ASCII smuggling), and Latin/Cyrillic/Greek homoglyph mixing inside words.

**3. Instruction patterns** — phrases like `ignore previous instructions`, `system prompt`, URLs, `curl`, `base64`. Inbound applies these **only inside regions already identified as hidden**, never to normally visible body text, so a legitimate document *about* prompt injection does not trip the scanner.

Two refinements sit on top of that:

- **Stitched pass** — hidden fragments in a file are reassembled and re-scanned, so an instruction deliberately split across two adjacent hidden runs/cells/spans still matches.
- **Outbound visible-text check** — the outbound gate additionally scans plainly visible text, since instruction-like phrasing in freshly generated AI output is unusual on its own. Because that phrasing also has entirely legitimate causes, it is capped at WARNING and never escalates to CRITICAL on its own.

## Risk levels

- 🔴 **CRITICAL** — instruction patterns found inside a hidden region (directly or once stitched together), or severe unicode smuggling such as the tag block
- 🟡 **WARNING** — a hidden region exists but carries no clear instruction pattern, or (outbound) visible text contains instruction-like phrasing. Worth a human glance
- 🔵 **INFO** — only minor unicode anomalies or mixed-script words
- 🟢 **CLEAN** — nothing found

`outbound_gate.py` also reports these as exit codes: CLEAN/INFO → `0`, WARNING → `1`, CRITICAL → `2`.

## Limitations (important)

- This is a heuristic tool. **CLEAN does not mean the file is safe** — it means these specific checks found nothing. Novel hiding techniques will be missed.
- The instruction pattern list (`patterns.py`) is meant to be extended as new attack phrasings show up.
- Text embedded inside images is not examined; that needs an OCR layer.
- Legacy binary Office formats (`.doc`, `.ppt`, `.xls`) are unsupported — only the modern XML-based formats.
- `.msg` (Outlook's binary email format) is unsupported; only `.eml` (RFC 822 / MIME).
- Nested `.eml` attachments are scanned three levels deep. Deeper chains are reported as unscanned rather than silently dropped.
- Excel's "cell far outside the used range" check is a loose heuristic, since a spreadsheet has no physical page boundary the way a slide or PDF page does.
- No file-size or decompression limits are enforced yet, so a decompression bomb can exhaust memory on the scanning machine. Do not point Revelux at fully untrusted input without an external resource limit.

## Project layout

```
revelux/
├── scanner.py            # inbound CLI entry point (scan a folder)
├── outbound_gate.py      # outbound CLI entry point (scan stdin/file text)
├── unicode_utils.py      # unicode anomaly detection
├── patterns.py           # instruction pattern definitions + stitched pass
├── test_samples/         # clean and injected sample files for trying it out
└── parsers/
    ├── md_parser.py
    ├── docx_parser.py
    ├── pptx_parser.py
    ├── xlsx_parser.py
    ├── pdf_parser.py
    ├── eml_parser.py     # headers/body/HTML tricks + recursive attachment scan
    ├── html_utils.py     # HTML hiding detection shared by md/eml/outbound
    └── ooxml_common.py   # metadata extraction shared by docx/pptx/xlsx
```

## Trying it out

`test_samples/` ships matched clean and injected files for every supported format:

```bash
python3 scanner.py test_samples
```

Expected: 8 CRITICAL, 2 WARNING, 5 CLEAN. The clean files should never be flagged above WARNING — if they are, that is a false positive worth reporting.

## Roadmap: continuous monitoring

Both gates are point-in-time checks: each judges one file or one string in isolation. Attacks that are harmless per step but malicious in aggregate — agent memory poisoned gradually across many turns, for instance — are out of reach by construction. Aggregating the JSONL written by `--log` over time (repeat warnings from one sender, risk trends for a given pipeline) is the natural next layer.

## Security

Revelux processes deliberately hostile input, so its own parsers are part of its attack surface. If you find a way to slip an injection past it, please open an issue — evasion reports are as valuable as crash reports here.

## License

Copyright 2026 safetyelliai

[Apache License 2.0](LICENSE) — see [NOTICE](NOTICE).
