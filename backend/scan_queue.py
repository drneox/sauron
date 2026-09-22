# Copyright 2026 Carlos Ganoza
# SPDX-License-Identifier: Apache-2.0
"""
In-process asyncio scan queue.
N workers pull (scan_id, domain, domain_id) items and run the sync scanner
orchestrator via asyncio.to_thread; persistence happens in the async runner
callback supplied by main.py.
"""
import asyncio
import logging
import os
from typing import Any, Awaitable, Callable

logger = logging.getLogger("asm.queue")

QueueItem = tuple[str, str, int | None]  # scan_id, domain, domain_id
Runner = Callable[[str, str, int | None], Awaitable[Any]]


class ScanQueue:
    def __init__(self) -> None:
        self.queue: asyncio.Queue[QueueItem] = asyncio.Queue()
        self.workers: list[asyncio.Task] = []

    async def start(self, runner: Runner) -> None:
        worker_count = int(os.getenv("SCAN_WORKERS", "1"))
        for idx in range(worker_count):
            self.workers.append(asyncio.create_task(self._worker(idx, runner)))
        logger.info(f"Scan queue started with {worker_count} worker(s)")

    async def enqueue(self, scan_id: str, domain: str, domain_id: int | None = None) -> None:
        await self.queue.put((scan_id, domain, domain_id))
        logger.info(f"[{scan_id}] Enqueued scan for {domain}")

    async def _worker(self, idx: int, runner: Runner) -> None:
        while True:
            scan_id, domain, domain_id = await self.queue.get()
            try:
                logger.info(f"[{scan_id}] Worker {idx} picked up scan for {domain}")
                await runner(scan_id, domain, domain_id)
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception(f"[{scan_id}] Worker {idx} crashed on scan")
            finally:
                self.queue.task_done()

    async def stop(self) -> None:
        for w in self.workers:
            w.cancel()
        await asyncio.gather(*self.workers, return_exceptions=True)
        self.workers.clear()
