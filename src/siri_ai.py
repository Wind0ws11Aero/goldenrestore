"""Siri AI override delivery constraints (standalone).

The opaque eligibility archives ride the protective restore on iOS 27, so their
delivery is validated here (``require_protective_delivery``) exactly as in the
tweak registry.
"""
from .exceptions import NuggetException

DOMAIN = "SysContainerDomain-com.apple.eligibilityd"
RELATIVE_PATH = "Library/Caches/NeverRestore/eligibility_overrides.data"


def require_protective_delivery(files, inject_all):
    """Raise when a Siri AI override is present without a full inject delivery.

    Opaque NSKeyedArchiver records cannot ride the sparse pass — they must be
    injected into the protective backup (``inject_all``) or the device rejects
    them.
    """
    if any(f.domain == DOMAIN for f in files) and not inject_all:
        raise NuggetException(
            "Siri AI overrides require a prepared, unencrypted protective backup. "
            "Enable protective backup, disable local backup encryption in Finder/iTunes, "
            "and remove protective/sparse restore environment overrides before retrying.")
