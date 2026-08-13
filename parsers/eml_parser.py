import base64
import os
import quopri
import sys
import tempfile
from email import policy
from email.parser import BytesParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.html_utils import find_hidden_html, strip_hidden_html
from parsers import md_parser, docx_parser, pptx_parser, pdf_parser, xlsx_parser
from limits import check_file_size, check_payload_size

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

# a forwarded email carrying the real payload is a normal-looking way to get
# a malicious message past a scanner that only reads the outer envelope, so
# nested .eml attachments are scanned too - bounded, since an attacker can
# otherwise nest them arbitrarily deep to burn CPU
MAX_EML_DEPTH = 3


def _scan_attachment(filename, payload_bytes, depth):
    ext = os.path.splitext(filename or "")[1].lower()
    if ext == ".eml":
        if depth >= MAX_EML_DEPTH:
            return {"error": f"nested email nesting deeper than {MAX_EML_DEPTH} levels - not scanned"}
        parser = None  # handled below via the depth-aware recursive call
    else:
        parser = ATTACHMENT_PARSERS.get(ext)
        if parser is None:
            return None
    if not payload_bytes:
        return None

    tmp = None
    try:
        check_payload_size(len(payload_bytes), f"attachment '{filename}'")
        tmp = tempfile.NamedTemporaryFile(suffix=ext, delete=False)
        tmp.write(payload_bytes)
        tmp.close()
        return parse(tmp.name, _depth=depth + 1) if ext == ".eml" else parser(tmp.name)
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    finally:
        if tmp is not None:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


def _collect_parts(part, plain_parts, html_parts, attachments):
    """Sort a message tree into body text vs attachments.

    Deliberately does NOT use Message.walk(): walk() descends straight
    through a message/rfc822 part, which would splice a forwarded email's
    body into the outer message's body text and let its payload slip by
    unexamined. Nested messages are captured whole and handed to the
    attachment scanner instead.
    """
    content_type = part.get_content_type()

    if content_type == "message/rfc822":
        payload = None
        try:
            inner = part.get_payload()
            if isinstance(inner, list) and inner:
                payload = inner[0].as_bytes()
            elif isinstance(inner, str):
                payload = inner.encode("utf-8", errors="replace")
            else:
                payload = part.get_payload(decode=True)

            # A message/rfc822 part is not supposed to carry a non-identity
            # transfer encoding, but mail in the wild (and Python's own
            # add_attachment) does it anyway - and the email module then
            # parses the still-encoded body as if it were the message,
            # handing back base64 text instead of the real one. Undo that
            # here, or the nested message is scanned as meaningless noise.
            cte = (part.get("Content-Transfer-Encoding") or "").strip().lower()
            if payload and cte == "base64":
                payload = base64.b64decode(payload, validate=False)
            elif payload and cte == "quoted-printable":
                payload = quopri.decodestring(payload)
        except Exception:
            payload = None
        name = part.get_filename() or "forwarded-message"
        if not name.lower().endswith(".eml"):
            name += ".eml"
        attachments.append((name, payload))
        return

    if part.is_multipart():
        for sub in part.get_payload():
            _collect_parts(sub, plain_parts, html_parts, attachments)
        return

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
        return

    try:
        text = part.get_content()
    except Exception:
        return
    if content_type == "text/plain":
        plain_parts.append(text)
    elif content_type == "text/html":
        html_parts.append(text)


def parse(path, _depth=0):
    findings = {
        "file": path,
        "type": "eml",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    check_file_size(path)
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
    _collect_parts(msg, plain_parts, html_parts, attachments)

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

    # 2ab. a forwarded/attached email's body is never shown in the recipient's
    # inbox view - they read the covering message and may never open this one,
    # so instructions sitting in it are payload delivered one level down. That
    # makes it worth pattern-scanning, unlike a top-level email's body text
    # (which is simply what the reader sees, and is left alone to keep false
    # positives low).
    if _depth > 0:
        for body_label, body in (("text/plain", plain_text), ("text/html", strip_hidden_html(html_text))):
            body_hits = score_hidden_text(body)
            if body_hits:
                findings["hidden_layers"].append({
                    "source": f"nested email body ({body_label})",
                    "text_preview": body.strip()[:200],
                    "instruction_pattern_hits": body_hits,
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
        sub = _scan_attachment(filename, payload, _depth)
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
