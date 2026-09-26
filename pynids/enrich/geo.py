"""
Offline GeoIP + ASN lookups using the free DB-IP "lite" databases.

DB-IP publishes monthly City Lite and ASN Lite databases in MaxMind's
``.mmdb`` format under CC BY 4.0, with no account or licence key needed.
``pynids geoip download`` fetches them; lookups are then fully local.

Attribution (required by the licence): IP geolocation by DB-IP
(https://db-ip.com).
"""
from __future__ import annotations

import datetime as _dt
import gzip
import ipaddress
import logging
import shutil
import threading
import urllib.request
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import __version__
from ..paths import geoip_dir

logger = logging.getLogger(__name__)

try:
    import maxminddb
except ImportError:  # optional dependency: pip install "pynids[geo]"
    maxminddb = None  # type: ignore[assignment]

CITY_FILE = "dbip-city-lite.mmdb"
ASN_FILE = "dbip-asn-lite.mmdb"
_URL = "https://download.db-ip.com/free/{name}-{month}.mmdb.gz"


class GeoResolver:
    """Look up country / city / coordinates / ASN for public IPs (LRU-cached)."""

    def __init__(self, directory: Optional[Path] = None, cache_size: int = 20_000) -> None:
        directory = Path(directory) if directory else geoip_dir()
        self._city = self._open(directory / CITY_FILE)
        self._asn = self._open(directory / ASN_FILE)
        self._cache: "OrderedDict[str, Optional[Dict[str, Any]]]" = OrderedDict()
        self._cache_size = cache_size
        self._lock = threading.Lock()

    @staticmethod
    def _open(path: Path):
        if maxminddb is None or not path.exists():
            return None
        try:
            return maxminddb.open_database(str(path))
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not open GeoIP database %s: %s", path, exc)
            return None

    @property
    def available(self) -> bool:
        return self._city is not None or self._asn is not None

    def lookup(self, ip: Optional[str]) -> Optional[Dict[str, Any]]:
        if not ip or not self.available:
            return None
        with self._lock:
            if ip in self._cache:
                self._cache.move_to_end(ip)
                return self._cache[ip]
        result = self._lookup_uncached(ip)
        with self._lock:
            self._cache[ip] = result
            if len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)
        return result

    def _lookup_uncached(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if not addr.is_global:
            return None
        out: Dict[str, Any] = {}
        try:
            if self._city is not None:
                rec = self._city.get(ip) or {}
                country = rec.get("country") or {}
                out["country"] = country.get("iso_code")
                out["country_name"] = (country.get("names") or {}).get("en")
                out["city"] = ((rec.get("city") or {}).get("names") or {}).get("en")
                loc = rec.get("location") or {}
                out["lat"] = loc.get("latitude")
                out["lon"] = loc.get("longitude")
            if self._asn is not None:
                rec = self._asn.get(ip) or {}
                out["asn"] = rec.get("autonomous_system_number")
                out["org"] = rec.get("autonomous_system_organization")
        except Exception as exc:  # noqa: BLE001 — a corrupt record must not break the pipeline
            logger.debug("GeoIP lookup failed for %s: %s", ip, exc)
            return None
        return {k: v for k, v in out.items() if v is not None} or None


def download_databases(directory: Optional[Path] = None, timeout: float = 120.0) -> List[str]:
    """
    Download the current month's DB-IP City Lite and ASN Lite databases
    (falling back to last month's if this month's is not published yet).
    Returns the list of files written.
    """
    directory = Path(directory) if directory else geoip_dir()
    directory.mkdir(parents=True, exist_ok=True)
    today = _dt.date.today()
    first = today.replace(day=1)
    months = [first.strftime("%Y-%m"), (first - _dt.timedelta(days=1)).strftime("%Y-%m")]
    written = []
    for name, target in (("dbip-city-lite", CITY_FILE), ("dbip-asn-lite", ASN_FILE)):
        last_error: Optional[Exception] = None
        for month in months:
            url = _URL.format(name=name, month=month)
            try:
                req = urllib.request.Request(url, headers={"User-Agent": f"PyNIDS/{__version__}"})
                tmp = directory / (target + ".tmp")
                with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
                    with gzip.GzipFile(fileobj=resp) as gz, tmp.open("wb") as out:
                        shutil.copyfileobj(gz, out)
                tmp.replace(directory / target)
                written.append(str(directory / target))
                break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
        else:
            raise RuntimeError(f"Could not download {name}: {last_error}")
    return written
