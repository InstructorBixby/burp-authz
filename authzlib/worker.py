"""A tiny wrapper so python callables can be handed to a java
ExecutorService.

makeHttpRequest blocks. Called straight from processHttpMessage it
blocks burps own proxy thread, so every page load waited for my
replays. Four workers is plenty and keeps the target from seeing a
burst.
"""

from java.lang import Runnable
from java.util.concurrent import Executors, TimeUnit


class Task(Runnable):

    def __init__(self, fn, args=(), on_error=None):
        self.fn = fn
        self.args = args
        self.on_error = on_error

    def run(self):
        try:
            self.fn(*self.args)
        except Exception as e:
            # an exception thrown inside a pool thread vanishes
            # silently, which cost me an evening of wondering why
            # nothing appeared in the table
            if self.on_error:
                self.on_error(e)


def pool(size=4):
    return Executors.newFixedThreadPool(size)


def shutdown(executor, seconds=5):
    if executor is None:
        return
    executor.shutdown()
    executor.awaitTermination(seconds, TimeUnit.SECONDS)
    executor.shutdownNow()
