#!/usr/bin/env python3
"""
Revelux - outbound gate. Scans an AI's own generated/edited text right
before it is shown, saved, or sent onward - the mirror image of
scanner.py's inbound, pre-ingestion check on files coming in.

This catches two things a file-at-rest scan can't:
  1. Hidden-in-plain-sight tricks (HTML comments, CSS display:none /
     white-on-white text, invisible unicode) that the output *inherited*
     verbatim from poisoned source material the AI was asked to
     summarize/rewrite/translate. There is no legitimate reason for an AI's
     own freshly generated markdown/HTML to contain these.
  2. Instruction-like phrasing sitting in the plainly visible text. It isn't
     hidden from a reader, so it's scored lower than (1), but it's still an
     unusual thing to find in fresh AI output and worth a glance - this is
     the "the AI's summary literally repeats the attacker's instructions"
     smell.

Usage:
    echo "$AI_OUTPUT" | python3 outbound_gate.py
    python3 outbound_gate.py --file response.md
    python3 outbound_gate.py --file response.md --json report.json
    python3 outbound_gate.py --file response.md --log scans.jsonl

Exit codes (so this composes as a real gate in a shell pipeline):
    0 = CLEAN/INFO  - safe to pass through
    1 = WARNING     - flagged for a human glance, not blocked
    2 = CRITICAL    - block / do not forward as-is
"""

import argparse
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unicode_utils import scan_text, scan_mixed_script_homoglyphs
from patterns import score_hidden_text, score_stitched_hidden
from parsers.html_utils import find_hidden_html, strip_hidden_html

RISK_EMOJI = {"CRITICAL": "\U0001F534", "WARNING": "\U0001F7E1", "INFO": "\U0001F535", "CLEAN": "\U0001F7E2"}
EXIT_CODE = {"CRITICAL": 2, "WARNING": 1, "INFO": 0, "CLEAN": 0}


def classify_risk(findings):
    has_hidden_pattern_hit = any(hl["instruction_pattern_hits"] for hl in findings["hidden_layers"])
    has_critical_unicode = any(u["severity"] == "critical" for u in findings["unicode_anomalies"])
    if has_hidden_pattern_hit or has_critical_unicode or findings["stitched_pattern_hits"]:
        return "CRITICAL"

    has_high_unicode = any(u["severity"] == "high" for u in findings["unicode_anomalies"])
    if findings["hidden_layers"] or has_high_unicode or findings["visible_pattern_hits"]:
        return "WARNING"

    if findings["unicode_anomalies"] or findings["homoglyph_words"]:
        return "INFO"

    return "CLEAN"


def scan_output(text, label="output"):
    """Scan a string of AI-generated text. Returns the same findings shape
    (file/type/hidden_layers/unicode_anomalies/homoglyph_words/risk) that
    scanner.py's file parsers produce, plus a visible_pattern_hits field,
    so inbound and outbound results can share one log/report format."""
    findings = {
        "file": label,
        "type": "ai_output_text",
        "scanned_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "direction": "outbound",
        "hidden_layers": [],
        "stitched_pattern_hits": [],
        "visible_pattern_hits": [],
        "unicode_anomalies": [],
        "homoglyph_words": [],
    }

    for hidden in find_hidden_html(text):
        hits = score_hidden_text(hidden["text"])
        findings["hidden_layers"].append({
            "source": hidden["source"],
            "text_preview": hidden["text"][:200],
            "instruction_pattern_hits": hits,
        })

    # catch instructions split across adjacent hidden blocks to dodge the
    # per-block scan above
    findings["stitched_pattern_hits"] = score_stitched_hidden(
        [hl["text_preview"] for hl in findings["hidden_layers"]],
        {h for hl in findings["hidden_layers"] for h in hl["instruction_pattern_hits"]},
    )

    # scan visible text with anything already flagged as hidden stripped
    # out, so a phrase isn't counted both as hidden and as merely-visible
    visible_text = strip_hidden_html(text)
    findings["visible_pattern_hits"] = score_hidden_text(visible_text)

    findings["unicode_anomalies"] = scan_text(text)
    findings["homoglyph_words"] = scan_mixed_script_homoglyphs(text)

    findings["risk"] = classify_risk(findings)
    return findings


def print_report(findings):
    risk = findings["risk"]
    emoji = RISK_EMOJI.get(risk, "⚪")
    print(f"{emoji} [{risk}] {findings['file']}")

    for hl in findings["hidden_layers"]:
        marker = " <-- instruction-like phrasing found here" if hl["instruction_pattern_hits"] else ""
        print(f"  hidden-in-output [{hl['source']}]{marker}")
        print(f"    preview: {hl['text_preview']!r}")
        if hl["instruction_pattern_hits"]:
            print(f"    matched: {hl['instruction_pattern_hits']}")

    if findings["stitched_pattern_hits"]:
        print("  instruction split across adjacent hidden blocks (only matches once stitched back together)")
        print(f"    matched: {findings['stitched_pattern_hits']}")

    if findings["visible_pattern_hits"]:
        print("  visible text contains instruction-like phrasing (not hidden, but unusual in fresh AI output)")
        print(f"    matched: {findings['visible_pattern_hits']}")

    for u in findings["unicode_anomalies"]:
        print(f"  unicode [{u['severity']}] {u['label']} ({u['codepoint']} {u['char_name']}) x{u['count']}")
        print(f"    context: {u['sample_context']!r}")

    if findings["homoglyph_words"]:
        print(f"  mixed-script (homoglyph) words: {findings['homoglyph_words']}")

    if risk == "CLEAN":
        print("  nothing suspicious found")
    print()


def main():
    ap = argparse.ArgumentParser(description="Scan AI-generated text output before it's shown, saved, or sent onward.")
    ap.add_argument("--file", help="Read text from this file instead of stdin")
    ap.add_argument("--json", help="Also write the full findings as JSON to this path")
    ap.add_argument("--log", help="Append this scan's findings as one JSON line to this file (for a future monitoring/history layer)")
    ap.add_argument("--quiet", action="store_true", help="Only print the one-line verdict, no detail")
    args = ap.parse_args()

    if args.file:
        with open(args.file, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
        label = args.file
    else:
        text = sys.stdin.read()
        label = "<stdin>"

    findings = scan_output(text, label=label)

    if args.quiet:
        emoji = RISK_EMOJI.get(findings["risk"], "⚪")
        print(f"{emoji} [{findings['risk']}] {findings['file']}")
    else:
        print_report(findings)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        print(f"Full JSON report written to {args.json}")

    if args.log:
        with open(args.log, "a", encoding="utf-8") as f:
            f.write(json.dumps(findings, ensure_ascii=False) + "\n")

    sys.exit(EXIT_CODE.get(findings["risk"], 0))


if __name__ == "__main__":
    main()
