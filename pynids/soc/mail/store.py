"""
Evidence store for analysed emails.

The original bytes are written once, named by their SHA-256, read-only, and
never modified: the analysis is always recomputed from them, so what the
dashboard shows can be reproduced and verified (``shasum -a 256``).
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyze import analyze
from .mime import LineIndex, Part, bytes_to_text, parse, visible

MAX_EMAIL = 50 * 1024 * 1024


class EmailStore:
    def __init__(self, root: Path, db_path: Optional[Path] = None) -> None:
        self.root = Path(root)
        self.db_path = Path(db_path) if db_path else self.root / "index.db"
        self._lock = threading.Lock()
        self._cache: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        conn = self._conn()
        conn.execute("CREATE TABLE IF NOT EXISTS soc_emails (sha256 TEXT PRIMARY KEY, name TEXT, source TEXT,"
                     " added REAL, size INTEGER, subject TEXT, sender TEXT, risk TEXT, counts TEXT)")
        conn.commit()
        conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.row_factory = sqlite3.Row
        return conn

    def _path(self, sha: str) -> Path:
        if not (len(sha) == 64 and all(c in "0123456789abcdef" for c in sha)):
            raise KeyError("bad id")
        return self.root / sha[:2] / f"{sha}.eml"

    # --- write ----------------------------------------------------------

    def add(self, data: bytes, name: Optional[str] = None, source: str = "upload") -> Dict[str, Any]:
        if not data:
            raise ValueError("empty message")
        if len(data) > MAX_EMAIL:
            raise ValueError(f"message larger than {MAX_EMAIL // (1024 * 1024)} MB")
        sha = hashlib.sha256(data).hexdigest()
        path = self._path(sha)
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o400)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        result = self.analysis(sha, data)
        s = result["summary"]
        with self._lock:
            conn = self._conn()
            conn.execute("INSERT OR IGNORE INTO soc_emails VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                         (sha, name, source, time.time(), len(data), s.get("subject"), s.get("from"),
                          result["risk"], json.dumps(result["counts"])))
            conn.commit()
            conn.close()
        return result

    def delete(self, sha: str) -> bool:
        path = self._path(sha)
        existed = path.exists()
        if existed:
            os.chmod(path, 0o600)
            path.unlink()
        with self._lock:
            self._cache.pop(sha, None)
            conn = self._conn()
            conn.execute("DELETE FROM soc_emails WHERE sha256 = ?", (sha,))
            conn.commit()
            conn.close()
        return existed

    # --- read -----------------------------------------------------------

    def raw(self, sha: str) -> bytes:
        path = self._path(sha)
        if not path.exists():
            raise KeyError("not found")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != sha:
            raise ValueError("stored evidence no longer matches its hash — the file was altered on disk")
        return data

    def list(self, limit: int = 200) -> List[Dict[str, Any]]:
        conn = self._conn()
        rows = conn.execute("SELECT * FROM soc_emails ORDER BY added DESC LIMIT ?", (limit,)).fetchall()
        conn.close()
        out = []
        for r in rows:
            d = dict(r)
            d["counts"] = json.loads(d["counts"] or "{}")
            out.append(d)
        return out

    def meta(self, sha: str) -> Optional[Dict[str, Any]]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM soc_emails WHERE sha256 = ?", (sha,)).fetchone()
        conn.close()
        return dict(row) if row else None

    def analysis(self, sha: str, data: Optional[bytes] = None) -> Dict[str, Any]:
        with self._lock:
            hit = self._cache.get(sha)
            if hit:
                self._cache.move_to_end(sha)
                return hit
        data = data if data is not None else self.raw(sha)
        meta = self.meta(sha) or {}
        result = analyze(data, meta.get("name"))
        result["added"] = meta.get("added")
        result["source"] = meta.get("source")
        with self._lock:
            self._cache[sha] = result
            while len(self._cache) > 8:
                self._cache.popitem(last=False)
        return result

    def lines(self, sha: str, start: int = 1, end: Optional[int] = None, fold: int = 60) -> Dict[str, Any]:
        """Raw source lines [start, end], made visible (control/bidi/zero-width shown).

        Long encoded bodies (base64 attachments) are folded to their first few
        lines unless a specific range is requested; the fold records the range
        so the viewer can fetch it.
        """
        data = self.raw(sha)
        idx = LineIndex(data)
        total = len(idx)
        end = min(total, end or total)
        start = max(1, start)
        folds: List[List[int]] = []
        if fold and start == 1 and end == total:
            root = self.analysis(sha, data)["structure"]
            folds = _foldable(root, fold)
        out: List[Any] = []
        n = start
        fold_iter = iter(sorted(folds))
        nxt = next(fold_iter, None)
        while n <= end:
            if nxt and n == nxt[0]:
                out.append({"fold": [nxt[0], nxt[1]], "count": nxt[1] - nxt[0] + 1})
                n = nxt[1] + 1
                nxt = next(fold_iter, None)
                continue
            line = idx.line(n)
            text = bytes_to_text(line.rstrip(b"\n"))
            crlf = text.endswith("\r")
            out.append(visible(text[:-1] if crlf else text))
            n += 1
        return {"start": start, "end": end, "total": total, "lines": out}

    def part(self, sha: str, part_id: str) -> Part:
        root = parse(self.raw(sha))
        for p in root.walk():
            if p.id == part_id:
                return p
        raise KeyError("no such part")


def _foldable(node: Dict[str, Any], threshold: int) -> List[List[int]]:
    """Body line ranges of encoded leaf parts longer than *threshold* lines (keep 3 visible)."""
    out: List[List[int]] = []
    stack = [node]
    while stack:
        p = stack.pop()
        stack.extend(p.get("children") or [])
        if p.get("embedded"):
            stack.append(p["embedded"])
        if p.get("children") or p.get("embedded"):
            continue
        a, b = p["body_lines"]
        if b - a + 1 > threshold and (p.get("cte") in ("base64", "x-uuencode") or p.get("attachment")):
            out.append([a + 3, b - 1])
    return out
