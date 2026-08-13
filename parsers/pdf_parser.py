import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text

import pymupdf

# PDF text render modes (Tr operator): 3 = invisible text (used legitimately
# for OCR text layers over scanned images, but also a known injection vector
# when it appears over *non-scanned* pages)
INVISIBLE_RENDER_MODE = 3
WHITE_RGB = (1.0, 1.0, 1.0)
NEAR_WHITE_THRESHOLD = 0.97  # each channel above this = "practically white"


def _color_is_near_white(color_int_or_tuple):
    if color_int_or_tuple is None:
        return False
    if isinstance(color_int_or_tuple, (int, float)):
        # packed sRGB int
        r = ((int(color_int_or_tuple) >> 16) & 0xFF) / 255
        g = ((int(color_int_or_tuple) >> 8) & 0xFF) / 255
        b = (int(color_int_or_tuple) & 0xFF) / 255
    else:
        r, g, b = color_int_or_tuple
    return r > NEAR_WHITE_THRESHOLD and g > NEAR_WHITE_THRESHOLD and b > NEAR_WHITE_THRESHOLD


def _analyze_page_text(page):
    hidden_spans = []
    page_rect = page.rect

    # get_text() clips to the page's own boundaries by default, which
    # means text positioned far outside the visible page (a known hiding
    # trick) would silently be skipped. Extracting against an oversized
    # clip rect instead picks up text anywhere in the content stream.
    big_clip = pymupdf.Rect(-100000, -100000, 100000, 100000)
    raw = page.get_text("dict", clip=big_clip)

    for block in raw.get("blocks", []):
        for line in block.get("lines", []):
            for span in line.get("spans", []):
                text = span.get("text", "")
                if not text.strip():
                    continue
                reasons = []

                size = span.get("size", 0)
                if size and size <= 1.0:
                    reasons.append(f"font size {round(size, 2)}pt (unreadably small)")

                color = span.get("color")
                if _color_is_near_white(color):
                    reasons.append("near-white text color (invisible on typical white background)")

                bbox = span.get("bbox")
                if bbox:
                    x0, y0, x1, y1 = bbox
                    if x1 < page_rect.x0 or x0 > page_rect.x1 or y1 < page_rect.y0 or y0 > page_rect.y1:
                        reasons.append("positioned entirely outside the visible page area")

                alpha = span.get("alpha")
                if alpha is not None and alpha < 0.05:
                    reasons.append(f"near-zero opacity (alpha={alpha}) - text is transparent")

                if reasons:
                    hidden_spans.append({"text": text, "reasons": reasons})

    return hidden_spans


def _check_embedded_javascript(doc):
    hits = []
    try:
        names = doc.xref_get_key(-1, "Names")
    except Exception:
        names = None
    # cheap heuristic pass over the raw file bytes for a JS catalog entry
    try:
        raw = doc.write()
        if b"/JavaScript" in raw or b"/JS" in raw:
            hits.append("PDF contains an embedded /JavaScript or /JS entry - PDFs should not normally run scripts")
    except Exception:
        pass
    return hits


def _check_hidden_layers(doc):
    hidden = []
    try:
        configs = doc.layer_ui_configs()
    except Exception:
        configs = []
    for cfg in configs or []:
        if cfg.get("on") is False:
            hidden.append(f"optional content layer '{cfg.get('text', '?')}' is hidden by default")
    return hidden


def parse(path):
    findings = {
        "file": path,
        "type": "pdf",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    doc = pymupdf.open(path)
    full_text_for_unicode_scan = []

    for page_num in range(len(doc)):
        page = doc[page_num]
        full_text_for_unicode_scan.append(page.get_text())

        for hidden in _analyze_page_text(page):
            hits = score_hidden_text(hidden["text"])
            findings["hidden_layers"].append({
                "source": f"page {page_num + 1}: " + "; ".join(hidden["reasons"]),
                "text_preview": hidden["text"][:200],
                "instruction_pattern_hits": hits,
            })

        for annot in page.annots() or []:
            content = (annot.info or {}).get("content", "")
            if content and content.strip():
                hits = score_hidden_text(content)
                findings["hidden_layers"].append({
                    "source": f"page {page_num + 1}: annotation ({annot.type[1]})",
                    "text_preview": content[:200],
                    "instruction_pattern_hits": hits,
                })
                full_text_for_unicode_scan.append(content)

    metadata = doc.metadata or {}
    for key, val in metadata.items():
        if val and str(val).strip():
            full_text_for_unicode_scan.append(str(val))
            hits = score_hidden_text(str(val))
            if hits or len(str(val)) > 60:
                findings["hidden_layers"].append({
                    "source": f"document metadata ({key})",
                    "text_preview": str(val)[:200],
                    "instruction_pattern_hits": hits,
                })

    for layer_note in _check_hidden_layers(doc):
        findings["hidden_layers"].append({
            "source": "optional content group (OCG)",
            "text_preview": layer_note,
            "instruction_pattern_hits": [],
        })

    for js_note in _check_embedded_javascript(doc):
        findings["hidden_layers"].append({
            "source": "embedded script",
            "text_preview": js_note,
            "instruction_pattern_hits": ["embedded JavaScript"],
        })

    doc.close()

    combined = "\n".join(full_text_for_unicode_scan)
    findings["unicode_anomalies"] = scan_text(combined)
    findings["homoglyph_words"] = scan_mixed_script_homoglyphs(combined)

    return findings
