import asyncio


class Timer:
    def __init__(self, timeout, callback):
        self._timeout = timeout
        self._expire = get_time() + timeout
        self._callback = callback
        self._task = asyncio.ensure_future(self._job())

    async def _job(self):
        await asyncio.sleep(self._timeout)
        self._callback()

    def cancel(self):
        self._task.cancel()


def get_time():
    _loop = asyncio.get_event_loop()
    return int(_loop.time() * 1000)
