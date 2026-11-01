"""
goldenrestore
============

Standalone async package for the GoldenNugget iOS restore engine.

Exposes the sparse `Backup`/`perform_restore` primitives plus the full
six-phase iOS 27 protective-restore flow (`restore_files`).
"""

# PEP 810: defer operation-only dependencies on Python 3.15+; eager on older Python.
__lazy_modules__ = (
    "pymobiledevice3.lockdown",
    "pymobiledevice3.services.mobilebackup2",
    "pymobiledevice3.services.diagnostics",
)

import os
from tempfile import TemporaryDirectory
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux, LockdownClient
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.services.diagnostics import DiagnosticsService
from pymobiledevice3.exceptions import PyMobileDevice3Exception

from .src import backup





# perform_restore / reboot_device must exist before restore.py does
# `from . import perform_restore, reboot_device`.
from .src import restore  # noqa: E402
from .src.restore import perform_restore, reboot_device

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
from .src.backup import (  # noqa: E402,F401
    Backup, ConcreteFile, Directory, SymbolicLink, AppBundle,
)
from .src.file_to_restore import FileToRestore  # noqa: E402,F401
from .src.protective import (  # noqa: E402,F401
    PreparedBackup, perform_protective_backup, clean_backup_for_restore,
    make_restore_view, discard_restore_view, backup_contains_keychain,
)
from .src.protective_cache import ProtectiveBackupCache, peek_cache_info  # noqa: E402,F401
from .src.context import RestoreOptions, RestoreSession  # noqa: E402,F401
from .src.exceptions import NuggetException  # noqa: E402,F401
from .src.restore import restore_files, _restore_ios27  # noqa: E402,F401

__all__ = [
    "perform_restore",
    "reboot_device",
    "restore_files",
    "Backup",
    "ConcreteFile",
    "Directory",
    "SymbolicLink",
    "AppBundle",
    "FileToRestore",
    "PreparedBackup",
    "perform_protective_backup",
    "clean_backup_for_restore",
    "make_restore_view",
    "discard_restore_view",
    "backup_contains_keychain",
    "ProtectiveBackupCache",
    "peek_cache_info",
    "RestoreOptions",
    "RestoreSession",
    "NuggetException",
]
