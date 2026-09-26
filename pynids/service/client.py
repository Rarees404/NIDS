"""Tiny client for the daemon's local API (used by the CLI)."""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

from ..paths import DEFAULT_API_HOST, DEFAULT_API_PORT, read_api_token


class DaemonUnavailable(RuntimeError):
    pass


class ApiClient:
    def __init__(self, host: str = DEFAULT_API_HOST, port: int = DEFAULT_API_PORT,
                 token: Optional[str] = None, timeout: float = 10.0) -> None:
        self.base = f"http://{host}:{port}"
        self.token = token if token is not None else read_api_token()
        self.timeout = timeout

    @property
    def dashboard_url(self) -> str:
        return self.base + "/"

    def request(self, method: str, path: str, body: Optional[Dict[str, Any]] = None,
                timeout: Optional[float] = None) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("X-PyNIDS-Token", self.token)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as resp:  # noqa: S310
                return json.loads(resp.read() or b"null")
        except urllib.error.HTTPError as exc:
            try:
                message = json.loads(exc.read()).get("error", str(exc))
            except ValueError:
                message = str(exc)
            raise RuntimeError(message) from None
        except (urllib.error.URLError, ConnectionError, TimeoutError) as exc:
            raise DaemonUnavailable(
                "The PyNIDS daemon is not running. Start it with: sudo pynids daemon install"
            ) from exc

    def get(self, path: str, **kw: Any) -> Any:
        return self.request("GET", path, **kw)

    def post(self, path: str, body: Optional[Dict[str, Any]] = None, **kw: Any) -> Any:
        return self.request("POST", path, body or {}, **kw)

    def delete(self, path: str, **kw: Any) -> Any:
        return self.request("DELETE", path, **kw)

    def alive(self) -> bool:
        try:
            self.get("/api/health", timeout=2)
            return True
        except (DaemonUnavailable, RuntimeError):
            return False
