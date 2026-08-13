import os
import re
import sys
import zipfile
from xml.etree import ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.ooxml_common import extract_metadata_fields, color_is_near_white

S_NS = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
R_NS = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
PKG_REL_NS = "{http://schemas.openxmlformats.org/package/2006/relationships}"

# Spreadsheets have no physical page boundary like a slide or a PDF page, so
# "far away" is a much weaker signal than off-slide/off-page - these are
# deliberately conservative so a normal large data export doesn't light up.
FAR_ROW_THRESHOLD = 5000
FAR_COL_THRESHOLD = 100  # ~column CV


def _col_letters_to_index(letters):
    idx = 0
    for ch in letters:
        idx = idx * 26 + (ord(ch.upper()) - ord("A") + 1)
    return idx - 1  # 0-based


def _split_cell_ref(ref):
    m = re.match(r"([A-Z]+)(\d+)", ref)
    if not m:
        return None, None
    return _col_letters_to_index(m.group(1)), int(m.group(2)) - 1


def _load_shared_strings(zf):
    if "xl/sharedStrings.xml" not in zf.namelist():
        return []
    try:
        root = ET.fromstring(zf.read("xl/sharedStrings.xml"))
    except ET.ParseError:
        return []
    return ["".join(t.text or "" for t in si.iter(f"{S_NS}t")) for si in root.findall(f"{S_NS}si")]


def _load_styles(zf):
    """Returns (fonts, cell_xfs): fonts[i] = {"color": hex-or-None, "size": pt-or-None};
    cell_xfs[i] = fontId for the i-th cellXf (what a cell's `s` attribute indexes into)."""
    if "xl/styles.xml" not in zf.namelist():
        return [], []
    try:
        root = ET.fromstring(zf.read("xl/styles.xml"))
    except ET.ParseError:
        return [], []

    fonts = []
    fonts_el = root.find(f"{S_NS}fonts")
    if fonts_el is not None:
        for font in fonts_el.findall(f"{S_NS}font"):
            color_el = font.find(f"{S_NS}color")
            sz_el = font.find(f"{S_NS}sz")
            size = None
            if sz_el is not None and sz_el.get("val"):
                try:
                    size = float(sz_el.get("val"))
                except ValueError:
                    pass
            fonts.append({
                "color": color_el.get("rgb") if color_el is not None else None,
                "size": size,
            })

    cell_xfs = []
    xfs_el = root.find(f"{S_NS}cellXfs")
    if xfs_el is not None:
        for xf in xfs_el.findall(f"{S_NS}xf"):
            font_id = xf.get("fontId")
            cell_xfs.append(int(font_id) if font_id is not None else None)

    return fonts, cell_xfs


def _hidden_rows_cols(root):
    hidden_rows = set()
    hidden_cols = set()
    for row in root.iter(f"{S_NS}row"):
        if row.get("hidden") == "1" and row.get("r"):
            hidden_rows.add(int(row.get("r")) - 1)
    cols_el = root.find(f"{S_NS}cols")
    if cols_el is not None:
        for col in cols_el.findall(f"{S_NS}col"):
            if col.get("hidden") == "1":
                try:
                    lo, hi = int(col.get("min")), int(col.get("max"))
                    hidden_cols.update(range(lo - 1, hi))
                except (TypeError, ValueError):
                    pass
    return hidden_rows, hidden_cols


def _sheet_name_map(zf):
    """Map worksheet zip path -> (sheet_name, visibility state)."""
    mapping = {}
    if "xl/workbook.xml" not in zf.namelist():
        return mapping
    try:
        wb_root = ET.fromstring(zf.read("xl/workbook.xml"))
    except ET.ParseError:
        return mapping

    sheets = []
    sheets_el = wb_root.find(f"{S_NS}sheets")
    if sheets_el is not None:
        for sheet in sheets_el.findall(f"{S_NS}sheet"):
            sheets.append({
                "name": sheet.get("name", "?"),
                "rid": sheet.get(f"{R_NS}id"),
                "state": sheet.get("state", "visible"),
            })

    rels = {}
    if "xl/_rels/workbook.xml.rels" in zf.namelist():
        try:
            rel_root = ET.fromstring(zf.read("xl/_rels/workbook.xml.rels"))
            for rel in rel_root.findall(f"{PKG_REL_NS}Relationship"):
                rels[rel.get("Id")] = rel.get("Target")
        except ET.ParseError:
            pass

    for sheet in sheets:
        target = rels.get(sheet["rid"])
        if not target:
            continue
        # relationship targets are usually relative to xl/ (per the OOXML
        # spec, relative to the referring part's own folder), but some
        # writers (e.g. openpyxl) emit a package-absolute "/xl/..." path
        if target.startswith("/"):
            path = target.lstrip("/")
        elif target.startswith("xl/"):
            path = target
        else:
            path = f"xl/{target}"
        mapping[path] = (sheet["name"], sheet["state"])

    return mapping


def _cell_text(c_el, shared_strings):
    v_el = c_el.find(f"{S_NS}v")
    cell_type = c_el.get("t")
    if cell_type == "inlineStr":
        is_el = c_el.find(f"{S_NS}is")
        return "".join(t.text or "" for t in is_el.iter(f"{S_NS}t")) if is_el is not None else None
    if v_el is None or not v_el.text:
        return None
    if cell_type == "s":
        try:
            return shared_strings[int(v_el.text)]
        except (ValueError, IndexError):
            return None
    if cell_type == "str":
        return v_el.text
    return None  # plain numbers/booleans/dates carry no free-text risk


def parse(path):
    findings = {
        "file": path,
        "type": "xlsx",
        "hidden_layers": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    with zipfile.ZipFile(path) as zf:
        shared_strings = _load_shared_strings(zf)
        fonts, cell_xfs = _load_styles(zf)
        sheet_map = _sheet_name_map(zf)
        full_text_for_unicode_scan = []

        sheet_files = sorted(n for n in zf.namelist() if re.match(r"xl/worksheets/sheet\d+\.xml$", n))

        for sheet_path in sheet_files:
            sheet_name, state = sheet_map.get(sheet_path, (sheet_path, "visible"))
            xml_bytes = zf.read(sheet_path)
            full_text_for_unicode_scan.append(xml_bytes.decode("utf-8", errors="replace"))
            try:
                root = ET.fromstring(xml_bytes)
            except ET.ParseError:
                continue

            if state in ("hidden", "veryHidden"):
                # the whole sheet is hidden from the workbook UI - a user
                # never opens it, but a "read every sheet" ingestion pipeline
                # will, so roll all of its text into one hidden layer
                cell_texts = [_cell_text(c, shared_strings) for c in root.iter(f"{S_NS}c")]
                sheet_text = " ".join(t for t in cell_texts if t)
                if sheet_text.strip():
                    hits = score_hidden_text(sheet_text)
                    findings["hidden_layers"].append({
                        "source": f"sheet '{sheet_name}' ({state})",
                        "text_preview": sheet_text[:200],
                        "instruction_pattern_hits": hits,
                    })
                continue

            hidden_rows, hidden_cols = _hidden_rows_cols(root)

            for c_el in root.iter(f"{S_NS}c"):
                ref = c_el.get("r")
                if not ref:
                    continue
                col_idx, row_idx = _split_cell_ref(ref)
                if col_idx is None:
                    continue

                text = _cell_text(c_el, shared_strings)
                if not text or not text.strip():
                    continue

                reasons = []
                if row_idx in hidden_rows:
                    reasons.append("row hidden")
                if col_idx in hidden_cols:
                    reasons.append("column hidden")
                if row_idx >= FAR_ROW_THRESHOLD or col_idx >= FAR_COL_THRESHOLD:
                    reasons.append(f"cell {ref} far outside the sheet's normal used range")

                style_idx = c_el.get("s")
                if style_idx is not None:
                    try:
                        font_id = cell_xfs[int(style_idx)]
                        font = fonts[font_id] if font_id is not None and font_id < len(fonts) else None
                    except (ValueError, IndexError):
                        font = None
                    if font:
                        if color_is_near_white(font.get("color")):
                            reasons.append(f"font color {font['color']} (near-invisible on white background)")
                        if font.get("size") is not None and font["size"] <= 1:
                            reasons.append(f"font size {font['size']}pt (unreadably small)")

                if reasons:
                    hits = score_hidden_text(text)
                    findings["hidden_layers"].append({
                        "source": f"sheet '{sheet_name}' cell {ref}: " + "; ".join(reasons),
                        "text_preview": text[:200],
                        "instruction_pattern_hits": hits,
                    })

        # comment part naming varies by writer: real Excel uses
        # xl/comments1.xml, openpyxl uses xl/comments/comment1.xml
        for cf in (n for n in zf.namelist() if re.match(r"xl/comments.*\.xml$", n)):
            try:
                c_root = ET.fromstring(zf.read(cf))
            except ET.ParseError:
                continue
            for comment in c_root.iter(f"{S_NS}comment"):
                text = "".join(t.text or "" for t in comment.iter(f"{S_NS}t"))
                if text.strip():
                    full_text_for_unicode_scan.append(text)
                    hits = score_hidden_text(text)
                    findings["hidden_layers"].append({
                        "source": f"cell comment ({comment.get('ref', '?')})",
                        "text_preview": text[:200],
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
