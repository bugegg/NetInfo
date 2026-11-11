"""How much of what a program wrote to a TCP socket the other end hasn't
acknowledged yet.

``send()`` returns as soon as the data is copied into the kernel's send
buffer, which at the start of an upload takes megabytes in a few
milliseconds; counting bytes there makes the first second of an upload look
far faster than the line. Subtracting what is still queued counts what has
actually arrived.
"""

from __future__ import annotations

import socket
import struct
import sys

#: <sys/socket.h>: bytes in the send buffer not yet acknowledged.
_SO_NWRITE = 0x1024
#: <linux/sockios.h> SIOCOUTQ (= TIOCOUTQ): the same on Linux.
_SIOCOUTQ = 0x5411
#: <mstcpip.h> SIO_TCP_INFO = _WSAIORW(IOC_VENDOR, 39), Windows 10 1703 and later.
_SIO_TCP_INFO = 0xD8000027


def queued(sock: socket.socket | None, written: int) -> int | None:
    """Bytes of the `written` so far on `sock` that haven't been
    acknowledged; None if this system can't say."""
    if sock is None:
        return None
    try:
        if sys.platform == "darwin":
            return sock.getsockopt(socket.SOL_SOCKET, _SO_NWRITE)
        if sys.platform.startswith("linux"):
            import fcntl

            out = fcntl.ioctl(sock.fileno(), _SIOCOUTQ, struct.pack("i", 0))
            return struct.unpack("i", out)[0]
        if sys.platform == "win32":
            acked = _windows_acked(sock)
            return None if acked is None else max(0, written - acked)
    except (OSError, ValueError):
        return None
    return None


_wsa_ioctl = None
_tcp_info_type = None


def _windows_acked(sock: socket.socket) -> int | None:
    """Bytes sent on `sock` and acknowledged (BytesOut less BytesInFlight
    from SIO_TCP_INFO). Includes the HTTP headers, a few hundred bytes."""
    global _wsa_ioctl, _tcp_info_type
    import ctypes
    from ctypes import wintypes

    if _wsa_ioctl is None:
        _tcp_info_type = _define_tcp_info()
        fn = ctypes.WinDLL("ws2_32", use_last_error=True).WSAIoctl
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_size_t, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                       ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                       ctypes.c_void_p, ctypes.c_void_p]
        _wsa_ioctl = fn
    version = wintypes.DWORD(0)
    info = _tcp_info_type()
    returned = wintypes.DWORD(0)
    if _wsa_ioctl(sock.fileno(), _SIO_TCP_INFO, ctypes.byref(version),
                  ctypes.sizeof(version), ctypes.byref(info), ctypes.sizeof(info),
                  ctypes.byref(returned), None, None) != 0:
        return None
    return max(0, info.BytesOut - info.BytesInFlight)


def _define_tcp_info():
    import ctypes
    from ctypes import wintypes

    class TCP_INFO_v0(ctypes.Structure):
        _fields_ = [
            ("State", ctypes.c_int),
            ("Mss", wintypes.ULONG),
            ("ConnectionTimeMs", ctypes.c_uint64),
            ("TimestampsEnabled", ctypes.c_ubyte),
            ("RttUs", wintypes.ULONG),
            ("MinRttUs", wintypes.ULONG),
            ("BytesInFlight", wintypes.ULONG),
            ("Cwnd", wintypes.ULONG),
            ("SndWnd", wintypes.ULONG),
            ("RcvWnd", wintypes.ULONG),
            ("RcvBuf", wintypes.ULONG),
            ("BytesOut", ctypes.c_uint64),
            ("BytesIn", ctypes.c_uint64),
            ("BytesReordered", wintypes.ULONG),
            ("BytesRetrans", wintypes.ULONG),
            ("FastRetrans", wintypes.ULONG),
            ("DupAcksIn", wintypes.ULONG),
            ("TimeoutEpisodes", wintypes.ULONG),
            ("SynRetrans", ctypes.c_ubyte),
        ]

    return TCP_INFO_v0
