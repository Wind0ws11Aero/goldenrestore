"""Single source of truth for where GoldenNugget's backup data lives on disk.

All the heavy trees (protective backup cache master + AFC media store, live
protective backup runs, PosterBoard database pulls and legacy full backups)
sit under a single backup root. Resolution priority (highest first):

  1. ``GOLDENNUGGET_BACKUP_DIR`` environment override (headless/manual tools)
  2. the default ``~/.goldennugget`` location

Every component keeps its usual relative subfolder underneath the root.
"""
import os
from pathlib import Path

_ENV_OVERRIDE = "GOLDENNUGGET_BACKUP_DIR"
_DEFAULT_ROOT = Path.home() / ".goldennugget"


def storage_root() -> Path:
    """The configured backup data root (env override > ``~/.goldennugget``)."""
    raw = os.environ.get(_ENV_OVERRIDE, "").strip()
    return Path(raw).expanduser() if raw else _DEFAULT_ROOT


def is_custom_backup_dir() -> bool:
    """True when a non-default backup location is configured (env override)."""
    return bool(os.environ.get(_ENV_OVERRIDE, "").strip())


def cache_base() -> Path:
    """Root of the protective backup cache (master, media store, snapshots)."""
    return storage_root() / "backup_cache"


def protective_base() -> Path:
    """Per-user folder holding live protective backups that survive reboots."""
    return storage_root() / "protective"


def posterboard_dir() -> Path:
    """Folder holding extracted PosterBoard database pulls (per UDID)."""
    return storage_root() / "PosterBoard"


def statusbar_dir() -> Path:
    """Folder holding StatusBarOverrides.archive dumps (per UDID, research)."""
    return storage_root() / "StatusBar"


def legacy_backups_dir() -> Path:
    """Folder holding legacy full-device backups (PosterBoard fallback)."""
    return storage_root() / "Backups"
