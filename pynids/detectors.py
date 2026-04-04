from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Iterable, Tuple, Any, List
import time


@dataclass
class RateStats:
    ewma_rate: float = 0.0
    last_window_ts: float = 0.0
    counts_window: Deque[Tuple[float, int]] = None  # (window_start, count)

    def __post_init__(self):
        if self.counts_window is None:
            self.counts_window = deque(maxlen=60)


class AnomalyDetector:
    def __init__(self, ewma_alpha: float, sigma_threshold: float, window_seconds: int = 10):
        self.ewma_alpha = ewma_alpha
        self.sigma_threshold = sigma_threshold
        self.window_seconds = window_seconds
        self.per_source: Dict[str, RateStats] = defaultdict(RateStats)

    def _window_key(self, ts: float) -> float:
        return ts - (ts % self.window_seconds)

    def observe(self, src_ip: str, ts: float) -> Iterable[Dict[str, Any]]:
        stats = self.per_source[src_ip]
        wkey = self._window_key(ts)

        if not stats.counts_window or stats.counts_window[-1][0] != wkey:
            stats.counts_window.append((wkey, 1))
        else:
            last_w, last_c = stats.counts_window.pop()
            stats.counts_window.append((last_w, last_c + 1))

        # compute current window rate
        current_count = stats.counts_window[-1][1]
        current_rate = current_count / float(self.window_seconds)

        # update EWMA
        if stats.ewma_rate == 0.0:
            stats.ewma_rate = current_rate
        else:
            stats.ewma_rate = self.ewma_alpha * current_rate + (1 - self.ewma_alpha) * stats.ewma_rate

        # compute stddev proxy via simple MAD-like approach over recent windows
        rates = [c / float(self.window_seconds) for _, c in stats.counts_window]
        if len(rates) >= 3:
            mean = sum(rates) / len(rates)
            variance = sum((r - mean) ** 2 for r in rates) / (len(rates) - 1)
            stddev = variance ** 0.5
        else:
            stddev = 0.0

        threshold = stats.ewma_rate + self.sigma_threshold * stddev

        if stddev > 0 and current_rate > threshold and current_count > 3:
            yield {
                "type": "anomaly",
                "message": f"Spike from {src_ip}: {current_rate:.2f} pkt/s > {threshold:.2f}",
                "src_ip": src_ip,
                "rate": current_rate,
                "threshold": threshold,
                "window_start": wkey,
            }





