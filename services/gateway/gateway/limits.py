"""Bounded request resources. All state belongs to one event loop."""

import asyncio
from contextlib import asynccontextmanager


class Rejected(Exception):
    def __init__(self, status, code, retry=None):
        self.status, self.code, self.retry = status, code, retry

    def __reduce__(self):
        return type(self), (self.status, self.code, self.retry)


class Memory:
    def __init__(self, capacity):
        self.capacity, self.used = capacity, 0
        self.changed = asyncio.Condition()

    async def reserve(self, amount, timeout):
        if amount > self.capacity:
            raise Rejected(413, "request_too_large")
        try:
            async with asyncio.timeout(timeout):
                async with self.changed:
                    await self.changed.wait_for(lambda: self.used + amount <= self.capacity)
                    self.used += amount
        except TimeoutError as error:
            raise Rejected(429, "body_memory_capacity", 1) from error
        return amount

    async def resize(self, held, amount):
        if amount > self.capacity:
            raise Rejected(413, "request_too_large")
        async with self.changed:
            if self.used - held + amount > self.capacity:
                raise Rejected(429, "body_memory_capacity", 1)
            self.used += amount - held
            self.changed.notify_all()
        return amount

    async def release(self, held):
        async with self.changed:
            self.used -= held
            self.changed.notify_all()


class Admission:
    def __init__(self, config):
        self.config = config
        self.memory = Memory(config.body_memory)
        self.execution = asyncio.Semaphore(config.execution)
        self.admitted = 0
        self.keys = {}

    @asynccontextmanager
    async def inference(self, key):
        config = self.config
        if self.keys.get(key, 0) >= config.per_key or self.admitted >= config.execution + config.queue:
            raise Rejected(429, "inference_capacity", 1)
        self.keys[key] = self.keys.get(key, 0) + 1
        self.admitted += 1
        acquired = False
        try:
            try:
                async with asyncio.timeout(config.queue_timeout):
                    await self.execution.acquire()
                    acquired = True
            except TimeoutError as error:
                raise Rejected(429, "inference_capacity", 1) from error
            yield
        finally:
            if acquired:
                self.execution.release()
            self.admitted -= 1
            self.keys[key] -= 1
            if not self.keys[key]:
                del self.keys[key]


class Body:
    """A volatile, lazily paged request buffer shared with parse workers.

    memfd has no filesystem path or persistent storage. It avoids copying
    whole prompts through a process queue or zero-filling them on the loop.
    """

    def __init__(self, capacity):
        import mmap
        import os
        self.fd = os.memfd_create("gateway-request", os.MFD_CLOEXEC)
        self.capacity, self.length = capacity + 4096, 0
        self.sent = False
        os.ftruncate(self.fd, self.capacity)
        self.mapping = mmap.mmap(self.fd, self.capacity)

    def append(self, chunk):
        end = self.length + len(chunk)
        self.mapping[self.length:end] = chunk
        self.length = end

    def view(self):
        return memoryview(self.mapping)[:self.length]

    def close(self):
        import os
        self.mapping.close()
        os.close(self.fd)
