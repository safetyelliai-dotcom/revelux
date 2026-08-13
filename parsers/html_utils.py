"""
Shared HTML hiding-technique detection, used by both the markdown/text
parser (a .md file can legally contain raw HTML) and the email parser (an
HTML email body is, structurally, the same thing).
"""

import re

HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)

DISPLAY_NONE_RE = re.compile(
    r"<[^>]+style=[\"'][^\"']*(display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0)[^\"']*[\"'][^>]*>(.*?)</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)

WHITE_TEXT_RE = re.compile(
    r"<[^>]+style=[\"'][^\"']*color\s*:\s*(#fff(?:fff)?|white|rgb\(\s*255\s*,\s*255\s*,\s*255\s*\))[^\"']*[\"'][^>]*>(.*?)</[^>]+>",
    re.IGNORECASE | re.DOTALL,
)


def find_hidden_html(raw):
    """Returns a list of {source, text} dicts for HTML comments, CSS
    display:none/visibility:hidden/font-size:0 blocks, and white-on-white
    text - the standard tricks for hiding an "invisible preheader" or
    injected instructions inside an HTML page or email body."""
    hidden = []

    for m in HTML_COMMENT_RE.finditer(raw):
        content = m.group(1).strip()
        if content:
            hidden.append({"source": "html_comment", "text": content})

    for m in DISPLAY_NONE_RE.finditer(raw):
        content = m.group(2).strip()
        if content:
            hidden.append({"source": "css_hidden_html", "text": content})

    for m in WHITE_TEXT_RE.finditer(raw):
        content = m.group(2).strip()
        if content:
            hidden.append({"source": "css_white_text", "text": content})

    return hidden


def strip_hidden_html(raw):
    """Remove HTML comments and CSS-hidden/white-text blocks, leaving
    (roughly) what a normal reader or renderer would actually see. Used to
    avoid double-flagging text that's already counted as a hidden layer
    when separately scanning "plainly visible" text for suspicious phrasing."""
    text = HTML_COMMENT_RE.sub(" ", raw)
    text = DISPLAY_NONE_RE.sub(" ", text)
    text = WHITE_TEXT_RE.sub(" ", text)
    return text
