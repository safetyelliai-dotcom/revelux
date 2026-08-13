import os
import sys
import tempfile
from email import policy
from email.parser import BytesParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.html_utils import find_hidden_html
from parsers import md_parser, docx_parser, pptx_parser, pdf_parser, xlsx_parser

# headers a normal mail client shows a human reading the message; anything
# else only shows up in "view source", but a raw-MIME ingestion pipeline
# reads every header regardless
DISPLAYED_HEADERS = {"from", "to", "cc", "subject", "date"}

ATTACHMENT_PARSERS = {
    ".md": md_parser.parse,
    ".markdown": md_parser.parse,
    ".txt": md_parser.parse,
    ".docx": docx_parser.parse,
    ".pptx": pptx_parser.parse,
    ".pdf": pdf_parser.parse,
    ".xlsx": xlsx_parser.parse,
}


def _scan_attachment(filename, payload_bytes):
    ext = os.path.splitext(filename or "")[1].lower()
    parser = ATTACHMENT_PARSERS.get(ext)
    if parser is None or not payload_bytes:
        return None
    tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
    try:
        tmp.write(payload_bytes)
        tmp.close()
        return parser(tmp.name)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        os.unlink(tmp.name)


def parse(path):
    findings = {
        "file": path,
        "type": "eml",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    full_text_for_unicode_scan = []

    # 1. headers a reader never sees in their inbox view
    seen_headers = set()
    for key in msg.keys():
        if key.lower() in DISPLAYED_HEADERS or key.lower() in seen_headers:
            continue
        seen_headers.add(key.lower())
        value = str(msg.get(key, ""))
        if not value.strip():
            continue
        full_text_for_unicode_scan.append(value)
        hits = score_hidden_text(value)
        if hits or len(value) > 60:
            findings["hidden_layers"].append({
                "source": f"header ({key})",
                "text_preview": value[:200],
                "instruction_pattern_hits": hits,
            })

    # 2. walk body parts and attachments
    plain_parts, html_parts, attachments = [], [], []

    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = part.get_content_disposition()
        filename = part.get_filename()

        is_attachment = disposition == "attachment" or (
            filename and content_type not in ("text/plain", "text/html")
        )
        if is_attachment:
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            attachments.append((filename or "unnamed", payload))
            continue

        try:
            text = part.get_content()
        except Exception:
            continue
        if content_type == "text/plain":
            plain_parts.append(text)
        elif content_type == "text/html":
            html_parts.append(text)

    plain_text = "\n".join(plain_parts)
    html_text = "\n".join(html_parts)
    full_text_for_unicode_scan.append(plain_text)
    full_text_for_unicode_scan.append(html_text)

    # 2a. when an HTML alternative exists, virtually every mail client
    # renders that and never shows the plain-text part to the recipient -
    # so it's exactly as "hidden" as vanished text in a docx
    if plain_text.strip() and html_text.strip():
        hits = score_hidden_text(plain_text)
        if hits or len(plain_text.strip()) > 60:
            findings["hidden_layers"].append({
                "source": "text/plain part (message also has an HTML part - clients render that instead, so this part is never shown to the recipient)",
                "text_preview": plain_text.strip()[:200],
                "instruction_pattern_hits": hits,
            })

    # 2b. tricks hidden inside the HTML part itself
    for hidden in find_hidden_html(html_text):
        hits = score_hidden_text(hidden["text"])
        findings["hidden_layers"].append({
            "source": f"HTML body ({hidden['source']})",
            "text_preview": hidden["text"][:200],
            "instruction_pattern_hits": hits,
        })

    # 3. recurse into attachments in a supported format
    for filename, payload in attachments:
        if not payload:
            continue
        sub = _scan_attachment(filename, payload)
        if sub is None:
            continue
        if "error" in sub:
            findings["hidden_layers"].append({
                "source": f"attachment '{filename}' (could not be parsed: {sub['error']})",
                "text_preview": "",
                "instruction_pattern_hits": [],
            })
            continue
        for hl in sub.get("hidden_layers", []):
            findings["hidden_layers"].append({
                "source": f"attachment '{filename}' -> {hl['source']}",
                "text_preview": hl["text_preview"],
                "instruction_pattern_hits": hl["instruction_pattern_hits"],
            })
        findings["unicode_anomalies"].extend(sub.get("unicode_anomalies", []))
        findings["homoglyph_words"].extend(sub.get("homoglyph_words", []))

    combined = "\n".join(full_text_for_unicode_scan)
    findings["unicode_anomalies"].extend(scan_text(combined))
    findings["homoglyph_words"].extend(scan_mixed_script_homoglyphs(combined))

    return findings
