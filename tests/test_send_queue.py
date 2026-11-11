import socket
import time

from NetInfoView.ping import send_queue
from NetInfoView.ping.speedtest import _Counter, summarize


def _pair():
    listener = socket.socket()
    # Fixed buffers: with autotuning the peer's receive buffer can grow
    # and take everything a moment later, so nothing would be left queued.
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * 1024)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.socket()
    client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256 * 1024)
    client.connect(listener.getsockname())
    server, _ = listener.accept()
    listener.close()
    return client, server


def _fill(sock) -> int:
    """Write until the send buffer is full; the bytes written."""
    sock.setblocking(False)
    written = 0
    block = b"0" * 65536
    try:
        while written < 64_000_000:
            written += sock.send(block)
    except BlockingIOError:
        pass
    sock.setblocking(True)
    return written


def _drain(sock, n: int) -> None:
    got = 0
    while got < n:
        got += len(sock.recv(1 << 20))


def test_queued_counts_what_the_peer_has_not_read_then_nothing():
    client, server = _pair()
    try:
        written = _fill(client)
        waiting = send_queue.queued(client, written)
        assert waiting is not None and 0 < waiting <= written
        _drain(server, written)
        deadline = time.monotonic() + 2
        while send_queue.queued(client, written) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert send_queue.queued(client, written) == 0
    finally:
        client.close()
        server.close()


def test_upload_counter_counts_only_what_arrived():
    client, server = _pair()
    try:
        counter = _Counter()
        counter.upload_on(1, client)
        written = _fill(client)
        counter.wrote(1, written)
        # The peer hasn't read a byte, so only what fits in its receive
        # buffer can have been acknowledged.
        assert counter.value < written
        _drain(server, written)
        counter.settle(1)
        assert counter.value == written
        counter.upload_closing(1)
        assert counter.value == written
    finally:
        client.close()
        server.close()


def test_peak_leaves_out_the_ramp():
    # A burst of 50 MB in the first 0.1 s, then a steady 10 MB/s (80 Mbps).
    points = [(0.0, 0), (0.1, 50_000_000)]
    points += [(round(0.1 + i * 0.1, 1), 50_000_000 + i * 1_000_000) for i in range(1, 60)]
    result = summarize(points, ramp_s=2.0)
    assert 79 < result.peak_mbps < 81
    assert 79 < result.mbps < 81
