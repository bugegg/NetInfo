"""TCP "ping": time how long a connection to host:port takes to establish.

PingInfoView offers this for hosts written as ``192.168.0.100:80``, for targets
that filter ICMP. There is no TTL to report, so that column stays empty.
"""

from __future__ import annotations

import asyncio
import errno
import time

from .result import PingResult, PingStatus


async def tcp_ping(ip: str, port: int, timeout_ms: int) -> PingResult:
    """Open and immediately close a TCP connection, measuring the handshake."""
    started = time.perf_counter()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout_ms / 1000.0
        )
        rtt_ms = (time.perf_counter() - started) * 1000.0
        return PingResult(PingStatus.SUCCEEDED, rtt_ms, ip)
    except asyncio.TimeoutError:
        return PingResult(PingStatus.TIMEOUT)
    except ConnectionRefusedError:
        return PingResult(PingStatus.CONNECTION_REFUSED, None, ip)
    except OSError as exc:
        return PingResult(_status_for_connect_error(exc), None, ip)
    finally:
        if writer is not None:
            writer.close()
            # Swallow the close handshake: we only cared about the connect.
            try:
                await writer.wait_closed()
            except (OSError, asyncio.TimeoutError):
                pass


def _status_for_connect_error(exc: OSError) -> PingStatus:
    if exc.errno in (errno.ENETUNREACH, errno.ENETDOWN):
        return PingStatus.NET_UNREACHABLE
    if exc.errno in (errno.EHOSTUNREACH, errno.EHOSTDOWN):
        return PingStatus.HOST_UNREACHABLE
    if exc.errno == errno.ECONNRESET:
        return PingStatus.CONNECTION_REFUSED
    return PingStatus.GENERAL_FAILURE
