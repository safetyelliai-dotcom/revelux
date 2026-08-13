import os
import re
import sys
import zipfile
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.ooxml_common import extract_metadata_fields

A_NS = "{http://schemas.openxmlformats.org/drawingml/2006/main}"
P_NS = "{http://schemas.openxmlformats.org/presentationml/2006/main}"


def _shape_text(sp_el):
    return "".join(t.text or "" for t in sp_el.iter(f"{A_NS}t"))


def _get_slide_size(zf):
    if "ppt/presentation.xml" not in zf.namelist():
        return None
    try:
        root = ET.fromstring(zf.read("ppt/presentation.xml"))
    except ET.ParseError:
        return None
    sld_sz = root.find(f"{P_NS}sldSz")
    if sld_sz is None:
        return None
    try:
        return int(sld_sz.get("cx")), int(sld_sz.get("cy"))
    except (TypeError, ValueError):
        return None


def _analyze_slide(xml_bytes, slide_w, slide_h):
    hidden = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return hidden

    sld_el = root  # <p:sld>
    if sld_el.get("show") == "0":
        text = "".join(t.text or "" for t in root.iter(f"{A_NS}t"))
        if text.strip():
            hidden.append({"text": text, "reasons": ["entire slide marked hidden (show=\"0\") - skipped during presentation but still in the file"]})

    for sp in root.iter(f"{P_NS}sp"):
        text = _shape_text(sp)
        reasons = []

        # off-slide position
        xfrm = sp.find(f"{P_NS}spPr/{A_NS}xfrm")
        if xfrm is not None and slide_w and slide_h:
            off = xfrm.find(f"{A_NS}off")
            ext = xfrm.find(f"{A_NS}ext")
            if off is not None and ext is not None:
                try:
                    x, y = int(off.get("x")), int(off.get("y"))
                    cx, cy = int(ext.get("cx")), int(ext.get("cy"))
                    if x + cx < 0 or y + cy < 0 or x > slide_w or y > slide_h:
                        reasons.append(f"shape positioned off-slide (x={x}, y={y})")
                except (TypeError, ValueError):
                    pass

        # tiny font anywhere in the shape's runs
        for rpr in sp.iter(f"{A_NS}rPr"):
            sz = rpr.get("sz")
            if sz:
                try:
                    pts = int(sz) / 100
                    if pts <= 1:
                        reasons.append(f"font size {pts}pt (unreadably small)")
                        break
                except ValueError:
                    pass

        # alt text / description field - easy to overlook, rendered to
        # screen readers and often scraped verbatim by document-to-text
        # pipelines even though a sighted viewer never sees it
        cnv_pr = sp.find(f"{P_NS}nvSpPr/{P_NS}cNvPr")
        if cnv_pr is not None:
            descr = cnv_pr.get("descr")
            if descr and descr.strip():
                hidden.append({"text": descr.strip(), "reasons": ["shape alt-text/description field"]})

        if reasons and text.strip():
            hidden.append({"text": text, "reasons": reasons})

    return hidden


def _extract_notes(zf, slide_index):
    name = f"ppt/notesSlides/notesSlide{slide_index}.xml"
    if name not in zf.namelist():
        return None
    try:
        root = ET.fromstring(zf.read(name))
    except ET.ParseError:
        return None
    text = "".join(t.text or "" for t in root.iter(f"{A_NS}t"))
    return text.strip() or None


def parse(path):
    findings = {
        "file": path,
        "type": "pptx",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    with zipfile.ZipFile(path) as zf:
        slide_size = _get_slide_size(zf)
        full_text_for_unicode_scan = []

        slide_names = sorted(
            [n for n in zf.namelist() if re.match(r"ppt/slides/slide\d+\.xml$", n)],
            key=lambda n: int(re.search(r"\d+", n).group()),
        )

        for name in slide_names:
            slide_index = int(re.search(r"\d+", name).group())
            xml_bytes = zf.read(name)
            full_text_for_unicode_scan.append(xml_bytes.decode("utf-8", errors="replace"))

            for hidden in _analyze_slide(xml_bytes, *slide_size if slide_size else (None, None)):
                hits = score_hidden_text(hidden["text"])
                findings["hidden_layers"].append({
                    "source": f"slide {slide_index}: " + "; ".join(hidden["reasons"]),
                    "text_preview": hidden["text"][:200],
                    "instruction_pattern_hits": hits,
                })

            notes = _extract_notes(zf, slide_index)
            if notes:
                full_text_for_unicode_scan.append(notes)
                hits = score_hidden_text(notes)
                # speaker notes are normal, but flag when they contain
                # instruction-like phrasing - a legitimate presenter note
                # doesn't usually read like a command to an AI
                if hits:
                    findings["hidden_layers"].append({
                        "source": f"slide {slide_index}: speaker notes",
                        "text_preview": notes[:200],
                        "instruction_pattern_hits": hits,
                    })

        for label, text in extract_metadata_fields(zf).items():
            full_text_for_unicode_scan.append(text)
            hits = score_hidden_text(text)
            if hits or len(text) > 40:
                findings["hidden_layers"].append({
                    "source": f"metadata field ({label})",
                    "text_preview": text[:200],
                    "instruction_pattern_hits": hits,
                })

    combined = "\n".join(full_text_for_unicode_scan)
    findings["unicode_anomalies"] = scan_text(combined)
    findings["homoglyph_words"] = scan_mixed_script_homoglyphs(combined)

    return findings
