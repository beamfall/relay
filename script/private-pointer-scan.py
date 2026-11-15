#!/usr/bin/env python3
"""Fail when tracked files point at private, out-of-repo material.

This repository is public. Comments and docs must not cite private paths
(agent-memory notes, untracked evidence files, private sibling repos, or
private plan/ADR/evidence trees). Ticket and ADR identifiers are fine; paths
are not.

Allowed: .gitignore patterns, and code that writes to the gitignored
.agent-evidence/ output directory (output subdirectories are lowercase names
or variables; a cited evidence file starts with a ticket ID or a timestamp).

Usage: script/private-pointer-scan.py [REV]   (default: the working tree)
"""
import re
import subprocess
import sys

PATTERNS = [
    ("private-repo", re.compile(r"\b(?:core|apple|plugins|relay)-private\b")),
    ("agent-memory", re.compile(r"agent-memory/")),
    ("workspace-root", re.compile(r"\bbeamfall-workspace\b")),
    ("handoff-note", re.compile(r"\bHANDOFF-")),
    ("private-tree", re.compile(r"\bdocs/(?:plans|adr|release/evidence)/")),
    # An evidence file named by ticket ID or timestamp, at any depth, not an
    # output dir; TICKET-<X>-repair-r* is the repair-path test's placeholder.
    ("evidence-file", re.compile(r"\.agent-evidence/(?:[\w.-]*/)*(?!TICKET-[A-Z]-repair-r)[A-Z0-9]")),
]

# Files that legitimately carry these strings: ignore rules, this scanner,
# and gate tooling or fixtures that parse the patterns rather than cite them.
EXEMPT = re.compile(
    r"(^|/)\.gitignore$"
    r"|^script/private-pointer-scan\.py$"
    r"|^tools/gate/check-doc-links(_test)?\.sh$"
    r"|^script/consumer_pin_freshness_test\.py$"
)

PREFILTER = (r"-private|agent-memory/|beamfall-workspace|HANDOFF-"
             r"|docs/(plans|adr|release/evidence)/|\.agent-evidence/")


def main(argv):
    rev = argv[1:2]
    out = subprocess.run(["git", "grep", "-I", "-n", "-E", "-e", PREFILTER] + rev,
                         capture_output=True, text=True)
    if out.returncode not in (0, 1):
        sys.stderr.write(out.stderr)
        return 2
    hits = []
    for line in out.stdout.splitlines():
        if rev:
            line = line.split(":", 1)[1]
        path, _, rest = line.partition(":")
        if EXEMPT.search(path):
            continue
        lineno, _, text = rest.partition(":")
        for rule, rx in PATTERNS:
            if rx.search(text):
                hits.append(f"{path}:{lineno}: {rule}: {text.strip()[:160]}")
                break
    for hit in hits:
        print(hit)
    print(f"private-pointer-scan: {len(hits)} hit(s)", file=sys.stderr)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
