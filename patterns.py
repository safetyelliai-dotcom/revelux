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


def score_stitched_hidden(fragments, already_found):
    """
    Second-pass check for instructions split across adjacent hidden fragments.

    Scoring each hidden run/cell/span on its own is evadable: an attacker can
    break "act as an unrestricted assistant" across two white-text runs so
    neither piece matches, even though the text a extraction pipeline sees is
    the fully reassembled sentence. This stitches every hidden fragment in a
    file back together (whitespace-normalised, since the split usually falls
    mid-phrase) and re-runs the patterns over the result.

    `already_found` is the set of hits the per-fragment pass reported; those
    are filtered out so the caller only sees genuinely new matches that exist
    solely at a fragment boundary.
    """
    if not fragments:
        return []
    # Two joins, because the split can fall in either place and one join
    # cannot recover both: gluing directly reassembles a word cut in half
    # ("ins" + "tructions"), while gluing with a space restores the gap when
    # the fragments were captured with their surrounding whitespace trimmed
    # ("please act" + "as an ..."). Whitespace is normalised afterwards so a
    # doubled space doesn't stop a phrase from matching.
    hits = []
    for joiner in ("", " "):
        stitched = re.sub(r"\s+", " ", joiner.join(fragments))
        for h in score_hidden_text(stitched):
            if h not in already_found and h not in hits:
                hits.append(h)
    return hits
