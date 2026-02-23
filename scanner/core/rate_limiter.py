import asyncio
import time


class RateLimiter:
    """
    Token bucket rate limiter.

    rate_per_second: tokens added per second
    burst: maximum tokens stored (allows short bursts)
    """

    def __init__(self, rate_per_second: float, burst: float | None = None):
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be > 0")

        self.rate = float(rate_per_second)
        self.capacity = float(burst if burst is not None else rate_per_second)
        self.tokens = self.capacity
        self.updated_at = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self, tokens: float = 1.0):
        """
        Wait until enough tokens are available, then consume them.
        """
        if tokens <= 0:
            return

        while True:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self.updated_at

                # Refill tokens
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                self.updated_at = now

                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return

                # Compute wait time for required tokens
                needed = tokens - self.tokens
                wait_time = needed / self.rate

            # Sleep outside the lock so other coroutines can progress
            await asyncio.sleep(wait_time)