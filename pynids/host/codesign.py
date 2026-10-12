"""
Code-signature checks: "who vouches for the program behind this connection?"

On macOS almost every legitimate program that talks to the network is
signed: by Apple (system daemons, Safari), with a Developer ID (Chrome,
Slack, Zoom), or through the App Store.  Malware is much more often
unsigned or *ad-hoc* signed (a signature with no identity behind it), and
it tends to run from places normal apps don't live: ``/tmp``,
``/Users/Shared``, hidden folders, or random names under
``~/Library/Application Support``.

:class:`SignatureChecker` runs ``codesign`` on a background thread and
caches the answer per (path, size, mtime), so the packet path only ever
does a dict lookup.  :func:`path_risk` is the cheap, synchronous half: it
judges the executable's location.
"""
from __future__ import annotations

import hashlib
import logging
import os
import queue
import re
import subprocess
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

_CODESIGN = "/usr/bin/codesign"

# Signature status values, most to least trustworthy.
APPLE = "apple"                # signed by Apple (part of macOS or an Apple app)
APP_STORE = "app_store"        # distributed through the Mac App Store
DEVELOPER_ID = "developer_id"  # notarisable Developer ID certificate
DEVELOPMENT = "development"    # Apple Development cert (local builds, Xcode)
ADHOC = "adhoc"                # signed, but with no identity (linker-signed, `codesign -s -`)
UNSIGNED = "unsigned"
INVALID = "invalid"            # signature present but broken (modified after signing)
UNKNOWN = "unknown"            # not checked yet, or not macOS

TRUSTED = frozenset({APPLE, APP_STORE, DEVELOPER_ID})
UNTRUSTED = frozenset({ADHOC, UNSIGNED, INVALID})

LABELS = {
    APPLE: "Signed by Apple",
    APP_STORE: "Mac App Store",
    DEVELOPER_ID: "Developer ID",
    DEVELOPMENT: "Development build",
    ADHOC: "Ad-hoc (no identity)",
    UNSIGNED: "Unsigned",
    INVALID: "Invalid signature",
    UNKNOWN: "Not checked",
}

Signature = Dict[str, Any]


def parse_codesign(output: str, returncode: int) -> Signature:
    """Turn ``codesign -dv --verbose=2`` stderr into a :data:`Signature`."""
    if "not signed at all" in output:
        return {"status": UNSIGNED}
    if returncode != 0 and "Authority=" not in output and "Signature=adhoc" not in output:
        return {"status": UNKNOWN, "error": output.strip().splitlines()[-1:] or None}
    authorities = re.findall(r"^Authority=(.+)$", output, re.M)
    team = (re.search(r"^TeamIdentifier=(.+)$", output, re.M) or [None, None])[1]
    ident = (re.search(r"^Identifier=(.+)$", output, re.M) or [None, None])[1]
    flags = (re.search(r"flags=0x[0-9a-f]+\(([^)]*)\)", output) or [None, ""])[1]
    sig: Signature = {
        "identifier": ident,
        "team_id": None if team in (None, "not set") else team,
        "authority": authorities[0] if authorities else None,
        "hardened_runtime": "runtime" in flags.split(","),
    }
    leaf = sig["authority"] or ""
    if "Signature=adhoc" in output or "adhoc" in flags.split(","):
        sig["status"] = ADHOC
    elif leaf.startswith("Developer ID Application"):
        sig["status"] = DEVELOPER_ID
    elif leaf in ("Apple Mac OS Application Signing", "Apple iPhone OS Application Signing"):
        sig["status"] = APP_STORE
    elif leaf.startswith(("Apple Development", "Mac Developer", "Apple Distribution")):
        sig["status"] = DEVELOPMENT
    elif leaf in ("Software Signing", "macOS Software Signing") or leaf.startswith("Apple "):
        sig["status"] = APPLE
    else:
        sig["status"] = UNKNOWN
    return sig


def _run_codesign(path: str) -> Signature:
    try:
        proc = subprocess.run(
            [_CODESIGN, "-dv", "--verbose=2", path],
            capture_output=True, text=True, timeout=15, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": UNKNOWN, "error": str(exc)}
    sig = parse_codesign(proc.stderr, proc.returncode)
    if sig["status"] in TRUSTED | {DEVELOPMENT, ADHOC}:
        # Displaying a signature doesn't validate it; a binary patched after
        # signing still prints its old authority.  (Not --strict: it rejects
        # harmless bundle layouts in signed apps such as Microsoft Teams.)
        try:
            verify = subprocess.run(
                [_CODESIGN, "--verify", path],
                capture_output=True, text=True, timeout=30, check=False,
            )
            if verify.returncode != 0:
                sig["status"] = INVALID
                sig["error"] = (verify.stderr.strip().splitlines() or [""])[-1]
        except (OSError, subprocess.SubprocessError):
            pass
    return sig


# ---------------------------------------------------------------------------
# Location heuristics
# ---------------------------------------------------------------------------

# Where developer tooling legitimately lives.  Binaries here are often
# ad-hoc signed (Homebrew, compilers, pip/npm-built tools), so being
# unsigned there is normal and not alerted on.
_DEV_PREFIXES = (
    "/opt/homebrew/", "/usr/local/", "/opt/local/", "/nix/", "/Library/Developer/",
    "/Applications/Xcode.app/",
)
_DEV_HOME_PARTS = (
    "/.venv/", "/venv/", "/.pyenv/", "/.nvm/", "/.cargo/", "/.rustup/", "/go/bin/",
    "/.local/bin/", "/.local/share/", "/.npm/", "/.bun/", "/.deno/", "/.volta/",
    "/node_modules/", "/.rbenv/", "/.asdf/", "/.sdkman/", "/miniconda", "/anaconda",
    "/.docker/", "/.orbstack/", "/.vscode/", "/.cursor/", "/Library/pnpm/",
)

# Where malware likes to hide.  (pattern, reason)
_SUSPICIOUS: Tuple[Tuple[str, str], ...] = (
    (r"^/(private/)?tmp/", "runs from a temporary folder"),
    (r"^/(private/)?var/tmp/", "runs from a temporary folder"),
    (r"^/(private/)?var/folders/", "runs from a per-user temporary folder"),
    (r"^/Users/Shared/", "runs from the shared Users folder"),
    (r"^/Users/[^/]+/Downloads/", "runs straight from Downloads"),
    (r"^/Library/Caches/|^/Users/[^/]+/Library/Caches/", "runs from a caches folder"),
    (r"^/Users/[^/]+/Library/(LaunchAgents|Containers/[^/]+/Data/tmp)/", "runs from an unusual Library folder"),
    (r"^/Volumes/", "runs from a mounted disk image or external volume"),
)


def path_risk(exe: Optional[str]) -> Optional[str]:
    """A short reason if *exe* runs from somewhere malware typically hides."""
    if not exe:
        return None
    if "/AppTranslocation/" in exe:  # Gatekeeper's quarantine copy of a downloaded app
        return None
    for pattern, reason in _SUSPICIOUS:
        if re.search(pattern, exe):
            # Translocated / mounted apps are how many legit installers start.
            if reason.startswith("runs from a mounted") and ".app/" in exe:
                return None
            return reason
    parts = exe.split("/")
    # Hidden directories (".something") outside the known dev-tool homes.
    if any(p.startswith(".") and len(p) > 1 for p in parts[:-1]) and not is_dev_location(exe):
        return "runs from a hidden folder"
    if parts[-1].startswith("."):
        return "the program file itself is hidden"
    # ~/Library/Application Support/<x>/<binary> without an .app bundle:
    # a common persistence spot for droppers.
    if re.search(r"^/Users/[^/]+/Library/Application Support/", exe) and ".app/" not in exe \
            and not is_dev_location(exe):
        return "runs from Application Support without an app bundle"
    return None


def is_dev_location(exe: Optional[str]) -> bool:
    if not exe:
        return False
    if exe.startswith(_DEV_PREFIXES):
        return True
    return exe.startswith("/Users/") and any(part in exe for part in _DEV_HOME_PARTS)


def is_system_path(exe: Optional[str]) -> bool:
    """On the read-only, SIP-protected system volume."""
    return bool(exe) and exe.startswith(("/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/",
                                         "/usr/bin/", "/bin/"))


def sha256_file(path: str, limit: int = 512 * 1024 * 1024) -> Optional[str]:
    """SHA-256 of *path* (skipped for files over *limit* bytes)."""
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Cached, asynchronous checker
# ---------------------------------------------------------------------------

class SignatureChecker:
    """
    Check code signatures off the hot path.

    :meth:`lookup` never blocks: it returns the cached result, or ``None``
    after queueing the path for the worker thread.  :meth:`check` blocks
    (used by the API and CLI for on-demand checks).

    Args:
        runner:   Injectable ``path -> Signature`` (tests).
        on_result: Called with ``(path, signature)`` after each fresh check.
    """

    def __init__(
        self,
        runner: Optional[Callable[[str], Signature]] = None,
        on_result: Optional[Callable[[str, Signature], None]] = None,
        max_entries: int = 4096,
    ) -> None:
        self.available = runner is not None or (sys.platform == "darwin" and os.path.exists(_CODESIGN))
        self._runner = runner or _run_codesign
        self._cache: Dict[str, Tuple[Tuple[int, int], Signature]] = {}
        self._pending: set = set()
        self._queue: "queue.Queue[str]" = queue.Queue()
        self._lock = threading.Lock()
        self._max = max_entries
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self.on_result = on_result

    def start(self) -> "SignatureChecker":
        if self.available and not self._thread:
            self._thread = threading.Thread(target=self._run, name="codesign", daemon=True)
            self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        self._queue.put("")

    @staticmethod
    def _stamp(path: str) -> Optional[Tuple[int, int]]:
        try:
            st = os.stat(path)
        except OSError:
            return None
        return (st.st_size, int(st.st_mtime))

    def _cached(self, path: str) -> Optional[Signature]:
        hit = self._cache.get(path)
        if hit is None:
            return None
        stamp, sig = hit
        # Re-check if the file changed on disk (an update, or tampering).
        return sig if stamp == self._stamp(path) or stamp == (-1, -1) else None

    def lookup(self, path: Optional[str]) -> Optional[Signature]:
        if not path or not self.available:
            return None
        with self._lock:
            sig = self._cached(path)
            if sig is None and path not in self._pending:
                self._pending.add(path)
                self._queue.put(path)
        return sig

    def check(self, path: str) -> Signature:
        if not self.available:
            return {"status": UNKNOWN, "error": "code signature checks need macOS"}
        with self._lock:
            sig = self._cached(path)
        if sig is not None:
            return sig
        return self._store(path, self._runner(path))

    def _store(self, path: str, sig: Signature) -> Signature:
        stamp = self._stamp(path) or (-1, -1)
        sig = {**sig, "label": LABELS.get(sig.get("status"), sig.get("status"))}
        with self._lock:
            if len(self._cache) >= self._max:
                self._cache.clear()
            self._cache[path] = (stamp, sig)
            self._pending.discard(path)
        if self.on_result:
            try:
                self.on_result(path, sig)
            except Exception:  # noqa: BLE001
                logger.debug("signature callback failed", exc_info=True)
        return sig

    def _run(self) -> None:
        while not self._stop.is_set():
            path = self._queue.get()
            if not path or self._stop.is_set():
                continue
            try:
                self._store(path, self._runner(path))
            except Exception as exc:  # noqa: BLE001
                logger.debug("codesign failed for %s: %s", path, exc)
                with self._lock:
                    self._pending.discard(path)

    def known(self) -> List[Tuple[str, Signature]]:
        with self._lock:
            return [(p, s) for p, (_, s) in self._cache.items()]


def assess(exe: Optional[str], sig: Optional[Signature]) -> Dict[str, Any]:
    """
    Combine signature + location into flags for the UI and detectors.

    Returns ``{"flags": [...], "risk": 0-3, "reasons": [...]}`` where risk
    0 = nothing notable, 1 = unusual, 2 = suspicious, 3 = very suspicious.
    """
    flags: List[str] = []
    reasons: List[str] = []
    risk = 0
    status = (sig or {}).get("status", UNKNOWN)
    where = path_risk(exe)
    dev = is_dev_location(exe)
    if where:
        flags.append("odd_path")
        reasons.append(where)
        # A program a known developer vouches for is unusual there, not alarming.
        risk = max(risk, 1 if status in TRUSTED else 2)
    if status == INVALID:
        flags.append("invalid_signature")
        reasons.append("its code signature is broken (the file was modified after signing)")
        risk = max(risk, 3)
    elif status in (UNSIGNED, ADHOC):
        flags.append("unsigned" if status == UNSIGNED else "adhoc")
        if not dev:
            reasons.append("it is unsigned" if status == UNSIGNED else "it is ad-hoc signed (no developer identity)")
            risk = max(risk, 2 if where else 1)
    if where and status in UNTRUSTED:
        risk = 3
    return {"flags": flags, "risk": risk, "reasons": reasons, "dev_location": dev}
