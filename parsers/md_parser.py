import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text
from parsers.html_utils import find_hidden_html
from limits import check_file_size


def parse(path):
    check_file_size(path)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    hidden_layers = find_hidden_html(raw)

    findings = {
        "file": path,
        "type": "markdown/text",
        "hidden_layers": [],
        "unicode_anomalies": scan_text(raw),
        "homoglyph_words": scan_mixed_script_homoglyphs(raw),
    }

    for layer in hidden_layers:
        hits = score_hidden_text(layer["text"])
        findings["hidden_layers"].append({
            "source": layer["source"],
            "text_preview": layer["text"][:200],
            "instruction_pattern_hits": hits,
        })

    return findings
