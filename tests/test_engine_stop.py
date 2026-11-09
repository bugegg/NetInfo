"""PingEngine.stop() ends a session at once, not after the ping timeout."""

import asyncio
import time

from NetInfoView.ping.engine import EngineOptions, PingEngine, PingTarget


class _HangingPinger:
    """Stands in for the ICMP pinger: every ping waits out a long timeout."""

    dont_fragment_supported = False

    def open(self):
        pass

    def close(self):
        self.closed = True

    def configure(self, ttl=None, dont_fragment=None):
        pass

    async def ping(self, ip, timeout_ms, payload_size=32):
        await asyncio.sleep(5)
        raise AssertionError("a stopped session should not wait for this")


def test_stop_does_not_wait_for_pings_still_out():
    batches = []
    engine = PingEngine(on_results=batches.append)
    engine._pinger = _HangingPinger()
    engine.set_options(EngineOptions(interval_seconds=1.0))
    engine.set_targets([PingTarget(key=k, host=f"192.0.2.{k}") for k in range(1, 50)])

    async def session():
        run = asyncio.create_task(engine.run())
        await asyncio.sleep(0.2)
        started = time.perf_counter()
        engine.stop()
        await run
        return time.perf_counter() - started

    assert asyncio.run(session()) < 1.0
    assert engine._pinger.closed
    # Cancelled pings report nothing rather than a failure.
    assert not [result for batch in batches for result in batch]
