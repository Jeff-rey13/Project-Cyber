"""Fixed-window in-memory limiter. Single process lab, so no redis needed here."""

import threading
import time


class FixedWindowLimiter:
    def __init__(self, limit: int, window_seconds: int, clock=time.monotonic):
        self.limit = limit
        self.window = window_seconds
        self._clock = clock
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = self._clock()
        with self._lock:
            start, count = self._hits.get(key, (now, 0))
            if now - start >= self.window:
                start, count = now, 0
            if count >= self.limit:
                self._hits[key] = (start, count)
                return False
            self._hits[key] = (start, count + 1)
            return True
