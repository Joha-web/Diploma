"""
Thread-safe process-local token bucket for ReconX modules.
"""

import threading
import time


class TokenBucket:
    """Thread-safe token bucket scoped to one module instance."""

    def __init__(self, rate: float = 100):
        self._lock = threading.Lock()
        self.rate = max(float(rate or 0), 0.0)
        self.capacity = max(float(rate or 0), 1.0)
        self.tokens = self.capacity
        self.last_refill = time.monotonic()

    def configure(self, rate: float) -> None:
        with self._lock:
            self.rate = max(float(rate or 0), 0.0)
            self.capacity = max(float(rate or 0), 1.0)
            self.tokens = min(self.tokens, self.capacity)
            self.last_refill = time.monotonic()

    def acquire(self, tokens: float = 1.0) -> None:
        if self.rate <= 0:
            return

        tokens = max(float(tokens), 0.0)
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self.last_refill
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.last_refill = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                wait_time = (tokens - self.tokens) / self.rate

            time.sleep(max(wait_time, 0.001))
