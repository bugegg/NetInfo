"""HTTPS for the app's own downloads (the IEEE OUI registry, GitHub
releases), verified by the operating system rather than OpenSSL's bundle.

On Windows, Python's default context only sees the root certificates already
copied into the certificate store; Windows adds roots on demand when it
verifies a chain itself, and a company's TLS-inspecting proxy installs its
root where Windows (not OpenSSL) looks. Either way the download fails with
"self-signed certificate in certificate chain" where a browser succeeds.
truststore hands verification to Windows' CryptoAPI and macOS's Security
framework, so whatever the browser trusts, NetInfoView does too.
"""

from __future__ import annotations

import ssl
import urllib.request


def ssl_context() -> ssl.SSLContext:
    try:
        import truststore
    except ImportError:  # running from source without it installed
        return ssl.create_default_context()
    return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def urlopen(request: urllib.request.Request | str, timeout: float):
    return urllib.request.urlopen(request, timeout=timeout, context=ssl_context())
