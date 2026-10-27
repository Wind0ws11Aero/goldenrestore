"""Persistent per-device cache of the protective backup master copy.

The master keeps the FULL Manifest.db (rows for drained payloads stay put)
so mobilebackup2 can run true incremental refreshes against it: after the
first apply, each next apply only uploads what actually changed on the
device. The master is never modified by an apply — each apply builds a
disposable *view* of it (a pruned copy of the manifest plus hardlinks to the
payloads) and restores from that, so a crashed apply cannot leave the master
half-pruned and the next refresh always diffs against a complete manifest.

The master always lives in the persistent app-data store (never the system
temp dir): it is the sole copy of user data between Phase 2 (device wipe)
and Phase 3 (restore), so it must survive reboots and crashes.
"""

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

from pymobiledevice3.lockdown import LockdownClient

from .inject import _validate_sqlite_db
from .storage import cache_base as _cache_base

_logger = logging.getLogger("GoldenNugget.cache")


def peek_cache_info(udid: str) -> Optional[dict]:
    """Read the cache info JSON for a UDID without a device session.

    Best-effort: returns the ``created`` timestamp and age (if any)
    regardless of encryption/version matching — the pre-apply summary uses it
    only to display "cache from <date>"; the real matching happens in
    ``ProtectiveBackupCache.locate`` at apply time.
    """
    try:
        temp_base = Path(tempfile.gettempdir()) / "goldennugget_protective_cache"
        persist_base = _cache_base()
    except Exception:
        return None
    now = int(time.time())
    for base in (temp_base, persist_base):
        try:
            with open(base / f"{udid}.json", "r", encoding="utf-8") as f:
                info = json.load(f)
        except Exception:
            continue
        if info.get("udid") != udid:
            continue
        created_ts = int(info.get("created_ts", now))
        return {"created": info.get("created", ""),
                "created_ts": created_ts,
                "age_secs": max(0, now - created_ts),
                "media_afc": bool(info.get("media_afc", False))}
    return None


CACHE_PERSIST_MIN_GB = float(os.environ.get("GOLDENNUGGET_CACHE_PERSIST_MIN_GB", "1"))
CACHE_REFRESH_SECS = int(os.environ.get("GOLDENNUGGET_CACHE_REFRESH_SECS", "1800"))
CACHE_MEDIA_REFRESH_SECS = int(
    os.environ.get("GOLDENNUGGET_CACHE_MEDIA_REFRESH_SECS", "21600"))


class ProtectiveBackupCache:
    """Persistent per-device cache of the protective backup master copy.

    The master keeps the FULL Manifest.db (rows for drained payloads stay put)
    so mobilebackup2 can run true incremental refreshes against it. The master
    is never modified by an apply — each apply builds a disposable view and
    restores from that, so the master stays a pristine full-manifest mirror
    whatever happens during the restore.
    """

    def __init__(self, udid: str, product_version: str, encrypted: bool = False):
        self.udid = udid
        self.product_version = product_version
        self.encrypted = encrypted
        self._temp_base = Path(tempfile.gettempdir()) / "goldennugget_protective_cache"
        self._persist_base = _cache_base()
        self.base = self._persist_base
        self.master_root = self.base / "master"
        self.device_dir = self.master_root / self.udid
        self.info_path = self.base / f"{self.udid}.json"
        # Persistent per-device media store (OUTSIDE ``master_root`` so working
        # copies and the manifest prune never touch it).
        self.media_dir = self.base / "media" / self.udid
        # Per-apply restore views live on the SAME filesystem as the master so
        # the view's payload hardlinks stay links instead of full copies.
        self.view_root = self.base / "view"

    def locate(self) -> Optional[dict]:
        """Find an existing master across both bases; point homes at it.

        Returns dict(base, info, age_secs, media_age_secs) or None.
        """
        now = int(time.time())
        for base in (self._temp_base, self._persist_base):
            info_path = base / f"{self.udid}.json"
            try:
                with open(info_path, "r", encoding="utf-8") as f:
                    info = json.load(f)
            except Exception:
                continue
            if info.get("udid") != self.udid or info.get("product_version") != self.product_version:
                continue
            if bool(info.get("encrypted", False)) != self.encrypted:
                continue
            master = base / "master" / self.udid
            required = ("Manifest.db", "Manifest.plist", "Status.plist")
            if not all((master / n).is_file() for n in required):
                continue
            if not _validate_sqlite_db(master / "Manifest.db"):
                continue
            self.base = base
            self.master_root = base / "master"
            self.device_dir = master
            self.info_path = info_path
            self.media_dir = base / "media" / self.udid
            self.view_root = base / "view"
            created = int(info.get("created_ts", now))
            # A cache written before the media store got its own clock has no
            # ``media_ts`` — treat its media as the master's age so it is
            # refreshed rather than trusted indefinitely.
            media_created = int(info.get("media_ts", created))
            return {"base": base, "info": info,
                    "age_secs": max(0, now - created),
                    "media_age_secs": max(0, now - media_created)}
        return None

    def _set_home(self, base: Path):
        self.base = base
        self.master_root = base / "master"
        self.device_dir = self.master_root / self.udid
        self.info_path = base / f"{self.udid}.json"
        self.media_dir = base / "media" / self.udid
        self.view_root = base / "view"

    def relocate_by_size(self):
        """Legacy no-op (the master always lives in the persistent store)."""

    def has_valid_master(self) -> bool:
        return self.locate() is not None

    def build_view(self) -> str:
        """Build the per-apply restore view of the master (master untouched)."""
        from .protective import make_restore_view
        return make_restore_view(str(self.master_root), self.udid,
                                 str(self.view_root))

    def discard_view(self) -> None:
        """Remove the per-apply restore view (it is disposable)."""
        from .protective import discard_restore_view
        discard_restore_view(str(self.view_root), self.udid)

    async def refresh(self, lockdown_client: LockdownClient, progress_callback=None,
                      include_photos: bool = True, include_posterboard: bool = False,
                      include_keychain: bool = False,
                      include_afc_media: bool = False) -> str:
        """Bring the master up to the device's current state (full or incremental).

        With ``include_posterboard`` the PosterBoard container rides along, so
        after this call ``extract_posterboard_db`` yields the live on-device
        database. With ``include_afc_media`` the bulk photo trees go over AFC
        into the persistent per-device media store, pulled as a diff.
        """
        from .protective import perform_protective_backup

        valid = self.has_valid_master()
        mode = "incremental" if valid else "full"
        _logger.info(f"Protective backup cache: {mode} refresh for {self.udid}")
        is_encrypted = await perform_protective_backup(
            lockdown_client, str(self.master_root), progress_callback,
            include_photos=include_photos, include_posterboard=include_posterboard,
            include_keychain=include_keychain,
            incremental_ok=valid,
            include_afc_media=include_afc_media,
            media_root=str(self.media_dir),
            afc_media_diff=True)

        self.base.mkdir(parents=True, exist_ok=True)
        now = int(time.time())
        media_ts = now if include_afc_media else self._last_media_ts()
        with open(self.info_path, "w", encoding="utf-8") as f:
            json.dump({"udid": self.udid,
                       "product_version": self.product_version,
                       "encrypted": is_encrypted,
                       "media_afc": include_afc_media,
                       "created_ts": now,
                       "media_ts": media_ts,
                       "created": time.strftime("%Y-%m-%d %H:%M:%S")}, f)
        return str(self.master_root)

    def _last_media_ts(self) -> int:
        """Timestamp of the last media pull (0 when it never happened)."""
        try:
            with open(self.info_path, "r", encoding="utf-8") as f:
                info = json.load(f)
            return int(info.get("media_ts", 0))
        except Exception:
            return 0

    def media_age_secs(self) -> int:
        """Age of the AFC photo store in seconds (0 when it never happened)."""
        ts = self._last_media_ts()
        if not ts:
            return 0
        return max(0, int(time.time()) - ts)

    async def refresh_media(self, lockdown_client: LockdownClient,
                            progress_callback=None) -> str:
        """Re-pull the AFC photo store without touching the master.

        The photo store is the safety net for the device's media, so it has its
        own freshness window. When the master is still fresh but the photo
        store has aged out, this pulls the photos (as a diff) instead of forcing
        a full master refresh.
        """
        from .afc_media import backup_media_via_afc

        self.media_dir.mkdir(parents=True, exist_ok=True)
        await backup_media_via_afc(lockdown_client, str(self.media_dir),
                                   progress_callback=progress_callback,
                                   diff=True)
        now = int(time.time())
        info = {}
        try:
            with open(self.info_path, "r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                info = loaded
        except Exception:
            info = {}
        info.setdefault("udid", self.udid)
        info.setdefault("product_version", self.product_version)
        info.setdefault("encrypted", self.encrypted)
        info.setdefault("media_afc", True)
        info["media_ts"] = now
        info.setdefault("created_ts", now)
        self.base.mkdir(parents=True, exist_ok=True)
        with open(self.info_path, "w", encoding="utf-8") as f:
            json.dump(info, f)
        return str(self.media_dir)
