"""
Detects unicode ranges/characters that are commonly abused to hide
instructions from a human reader while remaining fully visible to an LLM
that receives the raw extracted text (zero-width chars, unicode "tag"
characters used for ASCII smuggling, bidi override characters, stray
variation selectors, etc).
"""

import re
import unicodedata

# (start, end, label, severity) - inclusive codepoint ranges
SUSPICIOUS_RANGES = [
    (0x200B, 0x200F, "zero-width / directional formatting char", "high"),
    (0x202A, 0x202E, "bidi override char (can visually reorder text)", "high"),
    (0x2060, 0x2064, "word joiner / invisible operator", "high"),
    (0x2066, 0x2069, "bidi isolate control char", "high"),
    (0xFEFF, 0xFEFF, "zero-width no-break space / BOM", "medium"),
    (0xFE00, 0xFE0F, "variation selector (can encode hidden bytes)", "medium"),
    (0xE0000, 0xE007F, "unicode TAG block (ASCII smuggling - carries hidden text)", "critical"),
    (0xE0100, 0xE01EF, "variation selector supplement (steganography)", "medium"),
    (0xE000, 0xF8FF, "private-use-area char (non-standard, rarely legitimate in prose)", "low"),
]

# common latin look-alikes from other scripts, used to sneak text past
# naive keyword filters or to make injected text look like normal text
HOMOGLYPH_SCRIPTS = ("CYRILLIC", "GREEK")


def scan_text(text: str, context_window: int = 20):
    """
    Scan a string for suspicious unicode. Returns a list of finding dicts:
    {codepoint, char_name, label, severity, count, sample_context}
    """
    if not text:
        return []

    findings = {}
    for i, ch in enumerate(text):
        cp = ord(ch)
        hit = None
        for start, end, label, severity in SUSPICIOUS_RANGES:
            if start <= cp <= end:
                hit = (label, severity)
                break
        if hit is None:
            continue
        key = (cp, hit[0])
        if key not in findings:
            lo = max(0, i - context_window)
            hi = min(len(text), i + context_window)
            ctx = text[lo:hi].replace("\n", "\\n")
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = f"U+{cp:04X}"
            findings[key] = {
                "codepoint": f"U+{cp:04X}",
                "char_name": name,
                "label": hit[0],
                "severity": hit[1],
                "count": 0,
                "sample_context": ctx,
            }
        findings[key]["count"] += 1

    return sorted(findings.values(), key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3}[f["severity"]])


def scan_mixed_script_homoglyphs(text: str, sample_limit: int = 8):
    """
    Flags words that mix Latin letters with look-alike Cyrillic/Greek
    letters - a classic trick to hide a keyword ('ignоre' with a Cyrillic о)
    from naive string-matching filters while an LLM still reads it fine.
    """
    if not text:
        return []
    findings = []
    for word in re.findall(r"\w+", text, flags=re.UNICODE):
        scripts = set()
        for ch in word:
            if ch.isalpha():
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    continue
                for s in HOMOGLYPH_SCRIPTS:
                    if name.startswith(s):
                        scripts.add(s)
                if any(c.isascii() for c in ch):
                    scripts.add("LATIN")
        if "LATIN" in scripts and len(scripts) > 1:
            findings.append(word)
            if len(findings) >= sample_limit:
                break
    return findings
