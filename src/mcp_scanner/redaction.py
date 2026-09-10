"""Literal secret redaction without changing protocol keys or rewriting markers."""
import json
import re


def redact_secrets(text, secrets):
    patterns = {}
    for secret in secrets:
        if not secret:
            continue
        for form in {secret, json.dumps(secret)[1:-1]}:
            pattern = re.escape(form)
            # Short identifiers are ambiguous substrings of ordinary words.
            # Redact exact values and delimited echoes, not letters inside words.
            if len(secret) < 8:
                pattern = r"(?<!\w)" + pattern + r"(?!\w)"
            patterns[pattern] = max(patterns.get(pattern, 0), len(form))
    if not patterns:
        return text
    # One substitution pass handles overlapping forms without reprocessing the
    # replacement. Preserve existing markers across successive output boundaries.
    pattern = r"\[redacted\]|" + "|".join(sorted(patterns, key=lambda p: (-patterns[p], p)))
    return re.sub(pattern, lambda match: "[redacted]", text)
