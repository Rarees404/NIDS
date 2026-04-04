"""
Abstract base class for all PyNIDS detectors.

Every detector — signature, anomaly, behavioral, or threat-intel —
implements this interface so the engine can treat them uniformly.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable, Optional

from ..alerts.model import Alert
from ..flow.tracker import Flow


class BaseDetector(ABC):
    """
    Abstract detector interface.

    Subclasses must implement :meth:`name` and :meth:`analyze`.
    The engine calls ``analyze()`` once per packet, supplying:

    - ``meta``   — raw network-layer metadata (src/dst IPs, ports, payload).
    - ``layer7`` — parsed application-layer fields from the dissector.
    - ``flow``   — the current stateful Flow object (may be *None* for
                   connectionless or first-packet scenarios).

    Detectors are stateful by design; they may accumulate per-source
    counters, sliding windows, or flow tables internally.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Short identifier for this detector (used in logging)."""

    @abstractmethod
    def analyze(
        self,
        meta: dict,
        layer7: dict,
        flow: Optional[Flow],
    ) -> Iterable[Alert]:
        """
        Analyse one packet and yield zero or more :class:`~pynids.alerts.model.Alert` objects.

        This method **must not raise**; unexpected exceptions should be
        caught internally and logged, not propagated to the engine.
        """
