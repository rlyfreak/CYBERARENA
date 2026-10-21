"""Small process-wide budget for public password endpoints.

The reverse proxy does not currently provide a trustworthy per-client IP to
FastAPI, so this limit intentionally does not use forwarded headers.
"""

import math
import time
from collections.abc import Callable
from threading import Lock

BURST = 32
REFILL_PER_SECOND = 4.0


class PublicAuthBudget:
    def __init__(
        self,
        burst: int = BURST,
        refill: float = REFILL_PER_SECOND,
        clock: Callable[[], float] = time.monotonic,
    ):
        if burst < 1 or refill <= 0:
            raise ValueError("Invalid public authentication budget")
        self._burst = burst
        self._refill = refill
        self._tokens = float(burst)
        self._clock = clock
        self._updated = clock()
        self._lock = Lock()

    def retry_after(self) -> int:
        with self._lock:
            now = self._clock()
            self._tokens = min(
                self._burst,
                self._tokens + max(0.0, now - self._updated) * self._refill,
            )
            self._updated = now
            if self._tokens < 1:
                return max(1, math.ceil((1 - self._tokens) / self._refill))
            self._tokens -= 1
            return 0


public_auth_budget = PublicAuthBudget()
