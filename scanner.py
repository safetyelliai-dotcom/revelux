#!/usr/bin/env python3
"""
Revelux - inbound gate. Local prompt-injection scanner for .md, .docx,
.pptx, .xlsx, .pdf and .eml files.

Everything runs on-disk, locally - no file content ever leaves your machine.

Usage:
    python3 scanner.py <folder> [--json report.json] [--ext md,docx,pptx,xlsx,pdf,eml]

What it looks for:
  1. Structural hiding: text a normal reader would never see but a
     text-extraction pipeline still picks up - Word "hidden text"
     formatting, white-on-white runs, near-zero font sizes, off-slide
     PowerPoint shapes, hidden slides, invisible PDF text, PDF layers
     turned off by default, alt-text/description fields, document
     metadata fields, comments, and speaker notes.
  2. Unicode tricks: zero-width characters, bidi override characters,
     variation selectors, and the Unicode "tag" block (an ASCII-smuggling
     technique), plus Latin/Cyrillic/Greek homoglyph mixing inside words.
  3. Instruction-like phrasing found specifically INSIDE anything flagged
     in step 1 - not in the document's normal visible text, to keep false
     positives low.

This is a heuristic aid, not a guarantee. A CLEAN result means nothing
suspicious was found by these checks - it does not certify the file is
safe. Always sanity-check anything the tool flags before trusting or
discarding it, and treat this as one layer alongside normal caution about
where a file came from.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from parsers import md_parser, docx_parser, pptx_parser, pdf_parser, xlsx_parser, eml_parser
from patterns import score_stitched_hidden
import limits

PARSERS = {
    ".md": md_parser.parse,
    ".markdown": md_parser.parse,
    ".txt": md_parser.parse,
    ".docx": docx_parser.parse,
    ".pptx": pptx_parser.parse,
    ".pdf": pdf_parser.parse,
    ".xlsx": xlsx_parser.parse,
    ".eml": eml_parser.parse,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def add_stitched_pass(findings):
    """Re-check a file's hidden content with all fragments stitched back
    together, catching instructions deliberately split across adjacent
    hidden runs/cells/spans to dodge the per-fragment scan."""
    fragments = [hl["text_preview"] for hl in findings["hidden_layers"]]
    already_found = {h for hl in findings["hidden_layers"] for h in hl["instruction_pattern_hits"]}
    findings["stitched_pattern_hits"] = score_stitched_hidden(fragments, already_found)
    return findings


def classify_risk(findings):
    """Roll a file's raw findings up into one overall risk level."""
    has_pattern_hit = any(hl["instruction_pattern_hits"] for hl in findings["hidden_layers"])
    has_critical_unicode = any(u["severity"] == "critical" for u in findings["unicode_anomalies"])
    if has_pattern_hit or has_critical_unicode or findings.get("stitched_pattern_hits"):
        return "CRITICAL"

    has_high_unicode = any(u["severity"] == "high" for u in findings["unicode_anomalies"])
    if findings["hidden_layers"] or has_high_unicode:
        return "WARNING"

    if findings["unicode_anomalies"] or findings["homoglyph_words"]:
        return "INFO"

    return "CLEAN"


RISK_EMOJI = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵", "CLEAN": "🟢"}


def scan_folder(root, extensions):
    results = []
    for dirpath, _, filenames in os.walk(root):
        for name in filenames:
            ext = os.path.splitext(name)[1].lower()
            if ext not in extensions:
                continue
            path = os.path.join(dirpath, name)
            parser = PARSERS[ext]
            try:
                findings = parser(path)
            except Exception as e:
                findings = {
                    "file": path,
                    "type": ext.lstrip("."),
                    "hidden_layers": [],
                    "unicode_anomalies": [],
                    "homoglyph_words": [],
                    "error": f"{type(e).__name__}: {e}",
                }
            if "error" in findings:
                findings["risk"] = "ERROR"
            else:
                findings["risk"] = classify_risk(add_stitched_pass(findings))
            results.append(findings)
    return results


def print_report(results):
    total = len(results)
    counts = {}
    for r in results:
        counts[r["risk"]] = counts.get(r["risk"], 0) + 1

    print(f"\nScanned {total} file(s)")
    for level in ("CRITICAL", "WARNING", "INFO", "CLEAN", "ERROR"):
        if counts.get(level):
            emoji = RISK_EMOJI.get(level, "⚪")
            print(f"  {emoji} {level}: {counts[level]}")
    print()

    ordered = sorted(
        results,
        key=lambda r: {"ERROR": -1, "CRITICAL": 0, "WARNING": 1, "INFO": 2, "CLEAN": 3}[r["risk"]],
    )

    for r in ordered:
        if r["risk"] in ("CLEAN",):
            continue
        emoji = RISK_EMOJI.get(r["risk"], "⚪")
        print(f"{emoji} [{r['risk']}] {r['file']}")

        if r["risk"] == "ERROR":
            print(f"    could not be parsed: {r['error']}")
            continue

        for hl in r["hidden_layers"]:
            marker = " <-- instruction-like phrasing found here" if hl["instruction_pattern_hits"] else ""
            print(f"    hidden layer [{hl['source']}]{marker}")
            print(f"      preview: {hl['text_preview']!r}")
            if hl["instruction_pattern_hits"]:
                print(f"      matched: {hl['instruction_pattern_hits']}")

        if r.get("stitched_pattern_hits"):
            print("    instruction split across adjacent hidden fragments (only matches once stitched back together)")
            print(f"      matched: {r['stitched_pattern_hits']}")

        for u in r["unicode_anomalies"]:
            print(f"    unicode [{u['severity']}] {u['label']} ({u['codepoint']} {u['char_name']}) x{u['count']}")
            print(f"      context: {u['sample_context']!r}")

        if r["homoglyph_words"]:
            print(f"    mixed-script (homoglyph) words: {r['homoglyph_words']}")

        print()

    if counts.get("CLEAN"):
        print(f"({counts['CLEAN']} file(s) came back clean and are not listed above)")


def main():
    ap = argparse.ArgumentParser(description="Scan a folder for hidden prompt-injection content.")
    ap.add_argument("folder", help="Folder to scan recursively")
    ap.add_argument("--json", help="Also write full results as JSON to this path")
    ap.add_argument(
        "--ext",
        default="md,markdown,txt,docx,pptx,pdf,xlsx,eml",
        help="Comma-separated list of extensions to scan (default: md,markdown,txt,docx,pptx,pdf,xlsx,eml)",
    )
    ap.add_argument(
        "--max-file-mb",
        type=float,
        default=limits.MAX_FILE_BYTES / (1024 * 1024),
        help="Skip files larger than this on disk (default: 100)",
    )
    ap.add_argument(
        "--max-uncompressed-mb",
        type=float,
        default=limits.MAX_UNCOMPRESSED_BYTES / (1024 * 1024),
        help="Skip docx/pptx/xlsx archives expanding beyond this (default: 500)",
    )
    ap.add_argument(
        "--max-ratio",
        type=float,
        default=limits.MAX_COMPRESSION_RATIO,
        help="Skip archives whose expansion ratio exceeds this (default: 200)",
    )
    args = ap.parse_args()

    limits.configure(
        max_file_bytes=int(args.max_file_mb * 1024 * 1024),
        max_uncompressed_bytes=int(args.max_uncompressed_mb * 1024 * 1024),
        max_ratio=args.max_ratio,
    )

    extensions = {("." + e.strip().lstrip(".")) for e in args.ext.split(",") if e.strip()}
    if not os.path.isdir(args.folder):
        print(f"Not a folder: {args.folder}", file=sys.stderr)
        sys.exit(1)

    results = scan_folder(args.folder, extensions)
    print_report(results)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\nFull JSON report written to {args.json}")


if __name__ == "__main__":
    main()
