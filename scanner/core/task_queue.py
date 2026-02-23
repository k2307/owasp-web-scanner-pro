import asyncio
import logging
from typing import Awaitable, Callable, Optional, Any

logger = logging.getLogger(__name__)


class TaskQueue:
    """
    Simple async task queue with:
    - configurable concurrency
    - safe worker shutdown
    - optional per-task timeout
    - error capture
    """

    def __init__(self, concurrency: int = 10, task_timeout: Optional[int] = None):
        self.queue: asyncio.Queue[Callable[[], Awaitable[Any]]] = asyncio.Queue()
        self.concurrency = max(1, int(concurrency))
        self.task_timeout = task_timeout

        self._workers = []
        self.errors = []  # stores exceptions for debugging
        self.completed = 0

    async def add(self, coro_factory: Callable[[], Awaitable[Any]]):
        """
        Add a coroutine factory: lambda: some_async_function(...)
        """
        await self.queue.put(coro_factory)

    async def _worker(self):
        while True:
            coro_factory = await self.queue.get()
            try:
                coro = coro_factory()

                if self.task_timeout:
                    await asyncio.wait_for(coro, timeout=self.task_timeout)
                else:
                    await coro

                self.completed += 1

            except asyncio.CancelledError:
                # Worker is being shut down
                raise

            except Exception as e:
                self.errors.append(e)
                logger.error(f"[TaskQueue] Task failed: {e}")

            finally:
                self.queue.task_done()

    async def run(self):
        """
        Start workers and process until queue is empty.
        """
        self._workers = [asyncio.create_task(self._worker()) for _ in range(self.concurrency)]

        await self.queue.join()

        # Shutdown workers cleanly
        for w in self._workers:
            w.cancel()

        await asyncio.gather(*self._workers, return_exceptions=True)

        return {
            "completed": self.completed,
            "errors": len(self.errors),
        }