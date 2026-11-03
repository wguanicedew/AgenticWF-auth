"""Which certification authorities the AgenticWF clients trust (standard library only).

    ssl_context()       the system's CAs, certifi's (when installed), the ones shipped in cacerts/
                        and AGENTICWF_CA_BUNDLE (a PEM file or a c_rehash'ed directory)

cacerts/ is installed with the package, so a client trusts a site CA such as CERN's (cern.pem:
CERN Root Certification Authority 2 and the CERN Grid Certification Authority, which signs CERN
hosts) wherever it is installed, not only where the system has it (lxplus does, a laptop does
not). `agenticwf` uses it, and so do the kb and agent clients when this package is installed.
"""

from __future__ import annotations

import os
import ssl
from functools import lru_cache
from pathlib import Path
from typing import Optional

CA_DIR = Path(__file__).parent / "cacerts"


def ca_files() -> list[Path]:
    """The CA bundles shipped with the package."""
    return sorted(CA_DIR.glob("*.pem"))


def ssl_context() -> ssl.SSLContext:
    return _context(os.environ.get("AGENTICWF_CA_BUNDLE") or None)


@lru_cache(maxsize=4)
def _context(extra: Optional[str]) -> ssl.SSLContext:
    context = ssl.create_default_context()      # the system's (SSL_CERT_FILE / SSL_CERT_DIR honoured)
    try:
        import certifi
    except ImportError:
        pass
    else:
        context.load_verify_locations(certifi.where())
    for bundle in ca_files():
        context.load_verify_locations(str(bundle))
    if extra:
        path = Path(extra).expanduser()
        if path.is_dir():
            context.load_verify_locations(capath=str(path))
        else:
            context.load_verify_locations(str(path))
    return context
