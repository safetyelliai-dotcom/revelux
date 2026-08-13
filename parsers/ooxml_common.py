"""
Shared helpers for OOXML zip-based formats (docx, pptx, xlsx) - all three are
a zip of XML parts, and all three carry the same docProps/*.xml metadata
fields (author, title, description, keywords, comments) that a normal
reader never looks at but a naive "extract everything" ingestion pipeline
will.
"""

from xml.etree import ElementTree as ET

# near-white colors: pure white plus a couple of common "almost invisible on
# white background" shades some tools use to dodge naive "==FFFFFF" checks
NEAR_WHITE = {"FFFFFF", "FFFFFE", "FEFFFF", "FFFFFD"}


def extract_metadata_fields(zf):
    fields = {}
    for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        if name not in zf.namelist():
            continue
        try:
            root = ET.fromstring(zf.read(name))
        except ET.ParseError:
            continue
        for el in root.iter():
            if el.text and el.text.strip():
                tag = el.tag.split("}")[-1]
                fields[f"{name}:{tag}"] = el.text.strip()
    return fields


def color_is_near_white(hex_val):
    """hex_val may be a plain RGB ("FFFFFF") or ARGB ("FFFFFFFF", as xlsx
    styles use) hex string - compare the trailing 6 hex digits either way."""
    if not hex_val:
        return False
    return hex_val.upper()[-6:] in NEAR_WHITE
