"""
Investigation sources: one small adapter per external service.

Every source declares which indicator types it understands, whether it
needs an API key, and whether querying it is *active* (it touches the
indicator's own infrastructure, so an attacker could notice) or *passive*
(it asks a third party what it already knows).

A source answers with a :class:`Result`: a verdict, an ordered summary,
tags, pivots (new indicators to investigate next) and the **raw response
exactly as received**, so the analyst can always check the summary against
the original data.
"""
from __future__ import annotations

import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ... import __version__
from ..ioc import Ioc

VERDICT_RANK = {"unknown": 0, "info": 1, "clean": 2, "suspicious": 3, "malicious": 4}
MAX_RAW = 2 * 1024 * 1024
HASHES = ("md5", "sha1", "sha256", "sha512")
IPS = ("ipv4", "ipv6")

# (method, url, headers, body, timeout) -> (HTTP status, response text)
Http = Callable[[str, str, Dict[str, str], Optional[bytes], float], Tuple[int, str]]


class SourceError(Exception):
    """A source failed in a way worth showing the analyst."""


def urllib_http(method: str, url: str, headers: Dict[str, str], body: Optional[bytes],
                timeout: float) -> Tuple[int, str]:
    req = urllib.request.Request(url, data=body, method=method, headers={
        "User-Agent": f"PyNIDS/{__version__} (SOC workbench)", "Accept": "application/json", **headers})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — fixed https endpoints
            return resp.status, resp.read(MAX_RAW + 1).decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(MAX_RAW).decode("utf-8", errors="replace")


@dataclass
class Result:
    source: str
    status: str = "ok"  # ok | not_found | error | needs_key | unsupported | rate_limited
    verdict: str = "unknown"
    summary: List[Tuple[str, Any]] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    pivots: List[Dict[str, str]] = field(default_factory=list)
    raw: Any = None
    message: str = ""
    fetched: float = field(default_factory=time.time)
    cached: bool = False
    truncated: bool = False

    def row(self, label: str, value: Any) -> None:
        if value not in (None, "", [], {}):
            self.summary.append((label, value))

    def pivot(self, kind: str, value: Any, label: str = "") -> None:
        if value and len(self.pivots) < 200:
            item = {"type": kind, "value": str(value), "label": label}
            if item not in self.pivots:
                self.pivots.append(item)

    def worse(self, verdict: str) -> None:
        if VERDICT_RANK[verdict] > VERDICT_RANK[self.verdict]:
            self.verdict = verdict

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["summary"] = [[k, v] for k, v in self.summary]
        return d


@dataclass
class Ctx:
    http: Http
    key: Optional[str] = None
    timeout: float = 12.0


class Source:
    """Base class.  Subclasses set the class attributes and implement :meth:`query`."""

    name = ""
    label = ""
    description = ""
    homepage = ""
    types: Sequence[str] = ()
    key: Optional[str] = None       # KeyStore name, or None for keyless sources
    key_optional = False            # works without a key, better with one
    key_help = ""                   # where to get a key
    active = False                  # touches the indicator's own infrastructure
    ttl = 6 * 3600                  # cache lifetime in seconds
    per_minute: Optional[int] = None  # rate limit of the free tier

    def supports(self, ioc: Ioc) -> bool:
        return ioc.type in self.types

    def query(self, ioc: Ioc, ctx: Ctx) -> Result:  # pragma: no cover — abstract
        raise NotImplementedError

    def describe(self, configured: bool) -> Dict[str, Any]:
        return {
            "name": self.name, "label": self.label, "description": self.description,
            "homepage": self.homepage, "types": list(self.types), "key": self.key,
            "key_optional": self.key_optional, "key_help": self.key_help,
            "configured": configured or not self.key, "active": self.active,
            "per_minute": self.per_minute,
        }

    # --- helpers --------------------------------------------------------

    def result(self, **kw: Any) -> Result:
        return Result(source=self.name, **kw)

    def get_json(self, ctx: Ctx, url: str, headers: Optional[Dict[str, str]] = None,
                 method: str = "GET", body: Optional[bytes] = None,
                 not_found: Sequence[int] = (404,)) -> Tuple[Optional[Any], Result]:
        """Fetch and decode JSON.  Returns ``(data, result)``; ``data`` is None on 404."""
        res = self.result()
        status, text = ctx.http(method, url, headers or {}, body, ctx.timeout)
        if len(text) > MAX_RAW:
            text, res.truncated = text[:MAX_RAW], True
        try:
            data = json.loads(text) if text.strip() else None
        except ValueError:
            data = None
        res.raw = data if data is not None else text
        if status in not_found:
            res.status = "not_found"
            return None, res
        if status == 429:
            raise SourceError("rate limit reached at the provider — try again in a minute")
        if status in (401, 403):
            raise SourceError(f"the provider refused the request (HTTP {status}) — check the API key")
        if status >= 500:
            raise SourceError(f"the service is temporarily unavailable (HTTP {status}) — try again later")
        if status >= 400:
            raise SourceError(f"HTTP {status}: {_short(text)}")
        if data is None and not res.truncated:
            raise SourceError("the provider returned something that isn't JSON")
        return data, res


def _short(text: str, n: int = 160) -> str:
    text = re.sub(r"<(script|style)\b.*?</\1>|<[^>]+>", " ", text or "", flags=re.S | re.I)
    text = " ".join(text.split())
    return text[:n] + ("…" if len(text) > n else "")


def fmt_ts(value: Any) -> Optional[str]:
    """Unix seconds → ``YYYY-MM-DD HH:MM UTC``."""
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(float(value)))
    except (TypeError, ValueError):
        return None


def all_sources(local: Optional[Source] = None) -> List[Source]:
    from .free import CrtSh, DnsOverHttps, GreyNoise, InternetDb, Rdap, Urlscan
    from .keyed import AbuseIpDb, MalwareBazaar, Otx, ThreatFox, UrlHaus, VirusTotal

    out: List[Source] = [local] if local else []
    out += [Rdap(), DnsOverHttps(), InternetDb(), GreyNoise(), Urlscan(), CrtSh(),
            VirusTotal(), AbuseIpDb(), Otx(), UrlHaus(), ThreatFox(), MalwareBazaar()]
    return out
