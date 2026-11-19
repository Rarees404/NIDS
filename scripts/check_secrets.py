#!/usr/bin/env python3
"""
Stop API keys and other secrets from being committed or pushed.

Used by the git hooks in ``.githooks/`` and runnable by hand:

    python3 scripts/check_secrets.py --staged        # what is about to be committed
    python3 scripts/check_secrets.py --range A..B    # commits about to be pushed
    python3 scripts/check_secrets.py --all           # every tracked file

Two checks:

* file names that hold secrets (``soc-keys.json``, ``anthropic-key``, ``.env``,
  private keys …) must not be added, even with ``git add -f``;
* added lines must not contain something shaped like a real credential.

A line that holds a deliberate fake (a test fixture, a documentation example)
can be let through by putting ``secret-scan: allow`` on that line.

Standard library only.  Exit code 1 when something is found.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from typing import Iterable, List, Optional, Tuple

ALLOW_MARKER = "secret-scan: allow"
MAX_FILE_BYTES = 2_000_000

# File names that must never be tracked (matched against the whole path).
FORBIDDEN_PATHS = [
    (re.compile(r"(^|/)\.env(\..+)?$"), "environment file"),
    (re.compile(r"(^|/)soc-keys\.json$"), "PyNIDS source API keys"),
    (re.compile(r"(^|/)[^/]*anthropic-key[^/]*$"), "Anthropic API key file"),
    (re.compile(r"(^|/)api-token$"), "PyNIDS API token"),
    (re.compile(r"(^|/)evidence/"), "submitted evidence (emails / files)"),
    (re.compile(r"(^|/)id_(rsa|dsa|ecdsa|ed25519)$"), "SSH private key"),
    (re.compile(r"\.(pem|key|p12|pfx|keystore|jks)$", re.I), "key / certificate store"),
    (re.compile(r"(^|/)(sslkeys[^/]*|[^/]*keylog[^/]*)\.log$"), "TLS key log"),
    (re.compile(r"(^|/)\.(netrc|pypirc|npmrc)$"), "credential file"),
]
# ``.env.example`` style templates are fine.
ALLOWED_PATHS = re.compile(r"(^|/)\.env\.(example|sample|template)$")

SECRET_PATTERNS = [
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("OpenAI-style API key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}")),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")),
    # VirusTotal / AbuseIPDB / … keys are plain hex, so they are only
    # recognisable when assigned to something named like a credential.
    ("Hard-coded credential", re.compile(
        r"""(?ix)
        (?:api[_-]?key|apikey|x-apikey|secret|token|passwd|password|authorization|bearer)
        ["']?\s*[:=]\s*
        ["']([A-Za-z0-9_\-/+=.]{24,})["']
        """)),
]

# Values that are published fakes, e.g. AWS's AKIAIOSFODNN7EXAMPLE.
KNOWN_FAKE = re.compile(r"EXAMPLE|PLACEHOLDER|YOUR[_-]|X{8,}|<[^>]+>", re.I)

Finding = Tuple[str, Optional[int], str, str]  # path, line number, what, excerpt


def git(*args: str) -> str:
    proc = subprocess.run(["git", *args], capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        raise SystemExit(2)
    return proc.stdout.decode("utf-8", "replace")


def redact(value: str) -> str:
    return value[:6] + "…" + f"({len(value)} chars)" if len(value) > 10 else "…"


def check_path(path: str) -> Optional[str]:
    if ALLOWED_PATHS.search(path):
        return None
    for pattern, what in FORBIDDEN_PATHS:
        if pattern.search(path):
            return what
    return None


def check_line(line: str) -> List[Tuple[str, str]]:
    if ALLOW_MARKER in line:
        return []
    hits = []
    for what, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(line):
            value = match.group(match.lastindex or 0)
            if KNOWN_FAKE.search(value):
                continue
            hits.append((what, redact(value)))
            break
    return hits


def scan_diff(diff: str) -> Iterable[Finding]:
    """Yield findings for the files and lines a unified diff adds."""
    path, lineno = "", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            target = raw[4:].strip()
            path = "" if target == "/dev/null" else target[2:] if target.startswith("b/") else target
            continue
        if raw.startswith("@@"):
            match = re.search(r"\+(\d+)", raw)
            lineno = int(match.group(1)) - 1 if match else 0
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            lineno += 1
            for what, excerpt in check_line(raw[1:]):
                yield path, lineno, what, excerpt
        elif raw.startswith(" "):
            lineno += 1


def scan_names(names: Iterable[str]) -> Iterable[Finding]:
    for name in names:
        what = check_path(name) if name else None
        if what:
            yield name, None, f"forbidden file ({what})", ""


def scan_staged() -> List[Finding]:
    names = git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z").split("\0")
    diff = git("diff", "--cached", "--diff-filter=ACMR", "-U0", "--no-color", "--no-ext-diff")
    return [*scan_names(names), *scan_diff(diff)]


def scan_range(rev_range: List[str]) -> List[Finding]:
    names = git("log", "--format=", "--name-only", "--diff-filter=ACMR", "-z", *rev_range).split("\0")
    diff = git("log", "-p", "--format=", "--diff-filter=ACMR", "-U0", "--no-color", "--no-ext-diff", *rev_range)
    return [*scan_names(sorted(set(names))), *scan_diff(diff)]


def scan_all() -> List[Finding]:
    names = [n for n in git("ls-files", "-z").split("\0") if n]
    findings = list(scan_names(names))
    for name in names:
        try:
            with open(name, "rb") as fh:
                data = fh.read(MAX_FILE_BYTES + 1)
        except OSError:
            continue
        if len(data) > MAX_FILE_BYTES or b"\0" in data:
            continue
        for lineno, line in enumerate(data.decode("utf-8", "replace").splitlines(), 1):
            for what, excerpt in check_line(line):
                findings.append((name, lineno, what, excerpt))
    return findings


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Block secrets from being committed or pushed.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--staged", action="store_true", help="scan staged changes (default)")
    mode.add_argument("--all", action="store_true", help="scan every tracked file")
    # REMAINDER so git's own flags pass through: --range A..B, --range SHA --not --remotes
    mode.add_argument("--range", nargs=argparse.REMAINDER, metavar="REV",
                      help="scan the commits in a git revision range (everything after it goes to git log)")
    args = parser.parse_args(argv)

    if args.all:
        findings = scan_all()
    elif args.range:
        findings = scan_range(args.range)
    else:
        findings = scan_staged()

    if not findings:
        return 0
    out = sys.stderr
    out.write("\nSecret check failed — nothing was committed or pushed.\n\n")
    for path, lineno, what, excerpt in findings:
        where = f"{path}:{lineno}" if lineno else path
        out.write(f"  {where}  {what}" + (f"  [{excerpt}]" if excerpt else "") + "\n")
    out.write(
        "\nRemove the secret (and revoke it if it was ever committed). Keys belong in the\n"
        "PyNIDS data directory: `sudo pynids ai set-key`, `pynids soc key set <source>`.\n"
        f"If a line is a deliberate fake, add `{ALLOW_MARKER}` on that line.\n\n"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
