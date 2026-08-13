# Revelux — working rules

Revelux scans documents for hidden prompt-injection content. People act on its
verdicts, so a false CLEAN is the worst possible failure: it tells someone a
poisoned file is safe. Everything below follows from that.

## Pushing requires a security review and the owner's approval

**Never push without both.** A `pre-push` hook enforces this (`core.hooksPath`
is set to `.githooks`), and pushing is only possible with:

```bash
REVELUX_PUSH_APPROVED=1 git push ...
```

Do not set that flag on your own initiative. The sequence is:

1. Security-review the outgoing diff, focusing on detection-evasion: can an
   attacker restructure a payload so these changes stop flagging it?
2. Re-run the detection tests and confirm no regression:
   ```bash
   python3 scanner.py test_samples   # expect 8 CRITICAL / 2 WARNING / 5 CLEAN
   echo "normal text" | python3 outbound_gate.py --quiet   # expect CLEAN
   ```
3. Report the findings to the owner and ask for approval **for that specific
   push**.
4. Only after they approve, push with the flag set.

Approval is never implied by an earlier approval, by the change being small, or
by the owner having asked for the feature.

## Claims about detection must be demonstrated, not asserted

Never state that a technique is caught, or that a bypass is fixed, without
building a file that actually exercises it and running the scanner on it.
Findings from reading code alone are hypotheses — label them that way. This has
already mattered: an XML entity-expansion bomb looked exploitable on inspection
and turned out to be blocked by the parser, while two bypasses that looked fine
in code were real and reproducible.

## Known bypasses go in the README

Any confirmed way to slip content past Revelux is documented in the README's
Limitations section as soon as it is known — before it is fixed, not after.
Users calibrate their trust from that section; an undocumented known bypass is
a misleading CLEAN waiting to happen.

## Keep false positives low

Instruction patterns are matched **only inside regions already established as
hidden**, never against normally visible body text. A document that legitimately
discusses prompt injection must not be flagged. The outbound gate is the one
exception — it does scan visible text, but caps that signal at WARNING and never
escalates to CRITICAL on its own. Preserve this split when adding detections.

## Everything stays local

No file content, no scanned text, and no findings may be sent off the machine.
Local-only processing is a core promise of the tool; do not add network calls,
telemetry, or cloud-backed detection.

## Test fixtures

`test_samples/` holds matched clean/injected pairs per format. When adding a
detection, add both an injected sample that triggers it and confirm the clean
samples still come back CLEAN. Generate fixtures with a script rather than
committing opaque binaries by hand.
