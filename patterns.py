"""
Lightweight keyword/regex heuristics. These are NOT run against a document's
normal visible body text (too many false positives - a security blog post
legitimately contains the phrase "ignore previous instructions").

They are only applied to content the parsers have already flagged as
*hidden from a normal reader* (vanished text, white-on-white runs, off-slide
shapes, PDF metadata fields, doc comments, alt-text, etc). Finding this
phrasing specifically inside a hidden layer is a strong signal, because
there is no legitimate reason for invisible text to contain instructions
directed at an AI reader.
"""

import re

INSTRUCTION_PATTERNS = [
    r"\bignore (all|any|the)? ?(previous|prior|above)\b",
    r"\bdisregard (all|any|the)? ?(previous|prior|above)\b",
    r"\bsystem prompt\b",
    r"\byou are (now|an ai|a language model)\b",
    r"\bnew instructions?\b",
    r"\boverride\b.{0,20}\binstructions?\b",
    r"\bdo not (tell|inform|mention|reveal)\b",
    r"\bact as\b",
    r"\bas an ai\b",
    r"\bsend (this|the|all)? ?(data|content|file|information)? ?to\b",
    r"\bexfiltrat",
    r"\b(assistant|ai|model|llm)[,:]? (please|must|should)\b",
    r"https?://\S+",
    r"\bcurl\s+-",
    r"\bbase64\b",
    r"\bprompt injection\b",
]

_COMPILED = [re.compile(p, re.IGNORECASE) for p in INSTRUCTION_PATTERNS]


def score_hidden_text(text: str):
    """
    Returns a list of matched pattern strings found in a piece of text that
    was already identified as hidden-from-view. An empty list means the
    hidden content didn't match any known instruction-like phrasing (it
    could still be worth a human glance - a hidden layer is unusual on its
    own - but it's lower priority).
    """
    if not text:
        return []
    hits = []
    for pat in _COMPILED:
        m = pat.search(text)
        if m:
            hits.append(m.group(0))
    return hits
