"""Ask several slow sources at once but keep their order of preference: the
answer of the earliest source that has one wins, and nothing waits on a
later source once it's settled. Shared by the name probes, whose sources
each sit out a timeout when the device doesn't answer.
"""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor


def first_answer(
    calls: list[Callable[[], str]],
    usable: Callable[[str], bool] = bool,
) -> str:
    """The first result of `calls`, in list order, that `usable` accepts,
    or "". All of them run at once, so this takes as long as the slowest
    one that has to be waited for, not their sum."""
    if not calls:
        return ""
    pool = ThreadPoolExecutor(max_workers=len(calls))
    try:
        futures = [pool.submit(call) for call in calls]
        for future in futures:
            try:
                answer = (future.result() or "").strip()
            except Exception:
                continue
            if usable(answer):
                return answer
        return ""
    finally:
        # The ones still running finish on their own short timeouts.
        pool.shutdown(wait=False, cancel_futures=True)
