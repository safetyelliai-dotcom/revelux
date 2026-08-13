import os
import sys
import zipfile
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.ooxml_common import extract_metadata_fields, NEAR_WHITE

W_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
CP_NS = "{http://schemas.openxmlformats.org/package/2006/metadata/core-properties}"
DC_NS = "{http://purl.org/dc/elements/1.1/}"


def _run_text(run_el):
    return "".join(t.text or "" for t in run_el.findall(f"{W_NS}t"))


def _extract_hidden_runs(document_xml_bytes):
    hidden = []
    try:
        root = ET.fromstring(document_xml_bytes)
    except ET.ParseError:
        return hidden

    for run in root.iter(f"{W_NS}r"):
        rpr = run.find(f"{W_NS}rPr")
        if rpr is None:
            continue
        text = _run_text(run)
        if not text.strip():
            continue

        reasons = []
        if rpr.find(f"{W_NS}vanish") is not None:
            reasons.append("w:vanish (Word 'hidden text' formatting)")

        color_el = rpr.find(f"{W_NS}color")
        if color_el is not None:
            val = (color_el.get(f"{W_NS}val") or "").upper()
            if val in NEAR_WHITE:
                reasons.append(f"font color {val} (near-invisible on white background)")

        sz_el = rpr.find(f"{W_NS}sz")
        if sz_el is not None:
            try:
                half_points = int(sz_el.get(f"{W_NS}val"))
                if half_points <= 2:  # <= 1pt
                    reasons.append(f"font size {half_points/2}pt (unreadably small)")
            except (TypeError, ValueError):
                pass

        if reasons:
            hidden.append({"text": text, "reasons": reasons})

    return hidden


def _extract_comments(zf):
    comments = []
    if "word/comments.xml" not in zf.namelist():
        return comments
    try:
        root = ET.fromstring(zf.read("word/comments.xml"))
    except ET.ParseError:
        return comments
    for comment in root.iter(f"{W_NS}comment"):
        text = "".join(t.text or "" for t in comment.iter(f"{W_NS}t"))
        if text.strip():
            comments.append(text.strip())
    return comments


def parse(path):
    findings = {
        "file": path,
        "type": "docx",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    with zipfile.ZipFile(path) as zf:
        full_text_for_unicode_scan = []

        if "word/document.xml" in zf.namelist():
            doc_bytes = zf.read("word/document.xml")
            full_text_for_unicode_scan.append(doc_bytes.decode("utf-8", errors="replace"))
            for hidden in _extract_hidden_runs(doc_bytes):
                hits = score_hidden_text(hidden["text"])
                findings["hidden_layers"].append({
                    "source": "hidden_run (" + "; ".join(hidden["reasons"]) + ")",
                    "text_preview": hidden["text"][:200],
                    "instruction_pattern_hits": hits,
                })

        for label, text in extract_metadata_fields(zf).items():
            full_text_for_unicode_scan.append(text)
            hits = score_hidden_text(text)
            # metadata fields are always worth flagging for a human glance,
            # even without a pattern hit, since files rarely have populated
            # core-properties fields with prose content
            if hits or len(text) > 40:
                findings["hidden_layers"].append({
                    "source": f"metadata field ({label})",
                    "text_preview": text[:200],
                    "instruction_pattern_hits": hits,
                })

        for comment in _extract_comments(zf):
            full_text_for_unicode_scan.append(comment)
            hits = score_hidden_text(comment)
            findings["hidden_layers"].append({
                "source": "document comment",
                "text_preview": comment[:200],
                "instruction_pattern_hits": hits,
            })

    combined = "\n".join(full_text_for_unicode_scan)
    findings["unicode_anomalies"] = scan_text(combined)
    findings["homoglyph_words"] = scan_mixed_script_homoglyphs(combined)

    return findings
