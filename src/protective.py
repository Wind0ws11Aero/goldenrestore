"""Protective backup module for iOS 27+.

On iOS 27, the sparse restore triggers a "safe state recovery" that purges
device data not present in the backup (photos, Apple ID credentials, user
settings). To keep user data alive, the six-phase flow in ``restore.py`` does:

  Phase 1 (this module): selective device backup. App containers are skipped
      device-side (empty Applications dict in the factory info), and every
      non-protective file the device uploads is discarded mid-stream instead
      of being written to disk.
  Phase 3 (this module): the same backup directory — with Manifest.db pruned
      to the protective rows and orphan payload files removed — is restored
      back to the device after the security recovery.

Protective scope: HomeDomain/{Accounts, ConfigurationProfiles, Preferences,
Library/SpringBoard} (Apple ID + user settings + home screen layout),
Library/ControlCenter, Library/Shortcuts, Library/WebClips (Safari "Add to
Home Screen" web clips, incl. each <.webclip>/Storage PWA payload),
Library/WebApp + Library/WebKit/WebsiteData (installed-PWA data),
Library/AddressBook (contacts), MessagesDomain (iMessage/SMS/MMS), and,
optionally, CameraRollDomain + MediaDomain (photos). KeychainDomain is
included only when backup encryption is enabled.
"""

import asyncio
import hashlib
import os
import shutil
import sqlite3
import sys
import tempfile
import time
import uuid as _uuid
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pymobiledevice3.exceptions as _pm3_exc
import pymobiledevice3.service_connection as _sc
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.lockdown import LockdownClient
from pymobiledevice3.exceptions import NotEnoughDiskSpaceError
from pymobiledevice3.services.mobilebackup2 import (
    Mobilebackup2Service, NP_LOCAL_AUTH_PRESENTED, NP_LOCAL_AUTH_DISMISSED,
)

from .exceptions import NuggetException, BackupStorageError, BackupDiskSpaceError
from .utils import (
    clone_or_copy,  # noqa: F401  (re-exported; used by tree copiers)
    ensure_thread_executor,
    log_info, log_warn, log_error, log_debug,
    tr,
    BackupStatus,
)
from .storage import protective_base
from .managed_prefs import managed_pref_app_plists
from .posterboard import require_usable_snapshot  # noqa: F401  (re-exported)
from .afc_media import (  # noqa: F401  (re-exported public API)
    AFC_MEDIA_TREES,
    afc_media_dir_for,
    backup_media_via_afc,
    restore_media_via_afc,
)
from .inject import (  # noqa: F401  (re-exported public API)
    _is_encrypted_backup,
    _validate_sqlite_db,
    inject_files_into_backup,
)
from .protective_cache import (  # noqa: F401  (re-exported public API)
    CACHE_MEDIA_REFRESH_SECS,
    CACHE_PERSIST_MIN_GB,
    CACHE_REFRESH_SECS,
    ProtectiveBackupCache,
)
from .backup_store import (
    _BACKUP_METADATA_FILES, WORKING_COPY_PREFIX, _copy_backup_tree,
    make_protective_working_copy, make_cache_snapshot, _retire_backup_tree,
    discard_protective_working_copy, regenerate_cache_from_snapshot,
    _payload_inventory, _remove_orphan_payloads,
)
from .verification import PruneResult, inspect_backup_payloads  # noqa: F401
from .device_link_adapter import install_verbose, install_contents


@dataclass
class PreparedBackup:
    """A protective backup prepared ahead of the six-phase restore."""
    root: str
    manifest_password: str = ""  # required to prune/inject encrypted manifests
    # True when ``root`` is the CACHE MASTER — a pristine, incrementally
    # refreshed mirror the master must never modify. The apply builds a
    # disposable *view* of it and restores from that. False for a fresh live
    # backup, which the restore prunes in place.
    master: bool = False
    # Where the per-apply restore view is built. Empty for live backups.
    view_root: str = ""
    # Directory holding photos/videos pulled over AFC in parallel with this
    # backup ('' when media stayed in the mobilebackup2 backup). Phase 5 pushes
    # this tree back to the device via AFC.
    media_src: str = ""


# Minimum free disk space required before any device backup is started.
# Backups can easily reach several GB, so filling the disk mid-backup is a real
# hazard. Overridable via GOLDENNUGGET_MIN_FREE_GB.
MIN_FREE_DISK_GB = 5.0


def _min_free_disk_bytes() -> int:
    try:
        return int(float(os.environ.get("GOLDENNUGGET_MIN_FREE_GB", str(MIN_FREE_DISK_GB))) * (1024 ** 3))
    except ValueError:
        return int(MIN_FREE_DISK_GB * (1024 ** 3))


def check_disk_space(path: str = None, min_free_bytes: int = None) -> None:
    """Raise ``BackupStorageError`` if free disk space is below the threshold."""
    if path is None:
        path = tempfile.gettempdir()
    os.makedirs(path, exist_ok=True)  # disk_usage requires an existing path
    if min_free_bytes is None:
        min_free_bytes = _min_free_disk_bytes()
    usage = shutil.disk_usage(path)
    if usage.free < min_free_bytes:
        free_gb = usage.free / (1024 ** 3)
        required_gb = min_free_bytes / (1024 ** 3)
        raise BackupStorageError(
            tr(
                "Not enough free disk space: only {0} GB available, at least {1} GB is required for the backup. "
                "Free up space on your computer (backups are written to {2}) and try again.",
            ).format(f"{free_gb:.1f}", f"{required_gb:.1f}", path), location="computer"
        )


async def _get_device_used_storage(lockdown_client) -> Optional[int]:
    """Return the device's used data storage in bytes, or ``None`` if unreadable."""
    try:
        from pymobiledevice3.services.diagnostics import DiagnosticsService
        async with DiagnosticsService(lockdown_client) as diag:
            report = await diag.info("All")
        if not isinstance(report, dict):
            return None
        capacity = report.get("TotalDataCapacity")
        free = report.get("TotalDataSpace")
        if capacity is None or free is None:
            nested = report.get("DiskUsage")
            if isinstance(nested, dict):
                capacity = nested.get("TotalDataCapacity", capacity)
                free = nested.get("TotalDataSpace", free)
        if capacity is None or free is None:
            return None
        used = int(capacity) - int(free)
        return used if used > 0 else None
    except Exception:
        return None


async def check_disk_space_for_backup(lockdown_client=None, path: str = None,
                                      min_free_bytes: int = None) -> int:
    """Check free disk space before a device backup, sized to the device's data."""
    if min_free_bytes is None:
        min_free_bytes = _min_free_disk_bytes()
        if lockdown_client is not None:
            used = await _get_device_used_storage(lockdown_client)
            if used is not None:
                min_free_bytes = max(min_free_bytes, used)
    check_disk_space(path=path, min_free_bytes=min_free_bytes)
    return min_free_bytes


# Bump SSL handshake timeout — the default 10 seconds is too short for
# mobilebackup2 service startup on busy or post-reboot devices (iOS 27+).
_sc.DEFAULT_SSL_HANDSHAKE_TIMEOUT = 60

# Resolve the executor through its defining module, including Python 3.15.
ensure_thread_executor()


def backup_disk_space_message(path, available_bytes=None) -> str:
    """Describe a host-side backup space refusal using the actual destination."""
    if available_bytes is None:
        try:
            available_bytes = shutil.disk_usage(path).free
        except OSError:
            pass
    available = (tr("Available on that drive: {0} GiB.")
                 .format(f"{available_bytes / (1024 ** 3):.1f}")
                 if available_bytes is not None else "")
    return tr(
        "The device refused the backup because the backup drive does not have enough free disk space.\n\n"
        "Backup location: {0}\n{1}\n\n"
        "Free space on that drive, or choose a drive with more room in Settings → Backup → "
        "Backup/Cache Location, then retry. A filtered backup can still require space for "
        "the device's full backup estimate.").format(path, available)


def _install_device_link_verbose():
    install_verbose(backup_disk_space_message)


def _install_device_link_contents_shim():
    install_contents()


_install_device_link_verbose()
_install_device_link_contents_shim()


# Domains whose files should be kept in the protective backup.
PROTECTIVE_DOMAINS = frozenset({
    "CameraRollDomain",  # Actual photos and videos (DCIM/)
    "MediaDomain",       # Photo metadata (PhotoData/), PhotoStream, other media
    "MessagesDomain",    # iMessage / SMS / MMS (preserved across safe-state recovery)
})

KEYCHAIN_DOMAIN = "KeychainDomain"

# Path prefixes within HomeDomain that contain Apple ID account data and user
# settings.
APPLE_ID_PATH_PREFIXES = (
    "Library/Accounts",              # Account database (Accounts3.sqlite)
    "Library/ConfigurationProfiles",  # Configuration profiles
    "Library/Preferences",           # User settings (dark mode, wallpaper, etc.)
)

# Path prefixes within HomeDomain holding SpringBoard's home screen layout and
# icon state.
SPRINGBOARD_PATH_PREFIXES = (
    "Library/SpringBoard",
)

# Path prefixes within HomeDomain holding the Control Center module layout.
CONTROL_CENTER_PATH_PREFIXES = (
    "Library/ControlCenter",
)

# Path prefixes within HomeDomain holding iOS Shortcuts.
SHORTCUTS_PATH_PREFIXES = (
    "Library/Shortcuts",
)

# Path prefixes within HomeDomain holding Safari "Add to Home Screen" web
# clips and each web app's own WKWebsiteDataStore under <.webclip>/Storage/.
WEB_CLIPS_PATH_PREFIXES = (
    "Library/WebClips",
)

# Older/alternative HomeDomain homes for installed web-app data.
WEB_APP_PATH_PREFIXES = (
    "Library/WebApp",
)
WEBKIT_WEBSITE_DATA_PATH_PREFIXES = (
    "Library/WebKit/WebsiteData",
)

# Path prefixes within HomeDomain holding the contacts database.
ADDRESS_BOOK_PATH_PREFIXES = (
    "Library/AddressBook",
)

# Path prefixes within HomeDomain holding the IdentityServices persistence
# store (iMessage / iCloud account identity). Carried so the device keeps its
# identity across the security-recovery wipe.
IDENTITY_SERVICES_PATH_PREFIXES = (
    "Library/IdentityServices",
)

# System containers carrying Find My / device-identity state. Restored so the
# device keeps its Find My / iCloud identity across the security-recovery wipe
# (avoids the post-restore "verify your Apple ID" prompt).
PROTECTIVE_IDENTITY_DOMAINS = frozenset({
    "SysContainerDomain-com.apple.icloud.findmydeviced",
    "SysSharedContainerDomain-systemgroup.com.apple.icloud.findmydevice.managed",
    "SysContainerDomain-com.apple.adid",
})

# Domains whose uploads may be domain-qualified in the device-side name.
# Longest first, so "SysSharedContainerDomain-…" wins over a shorter prefix.
_DOMAIN_PREFIXES = tuple(sorted(
    {"HomeDomain", "SystemPreferencesDomain", "MessagesDomain",
     "AddressBookDomain", "CameraRollDomain", "MediaDomain",
     "KeychainDomain"} | set(PROTECTIVE_IDENTITY_DOMAINS),
    key=len, reverse=True))

# Apple-ID state, split into three groups.
#
# * account record — which Apple Account the device is signed into
#   (``Library/Accounts`` + the Apple-account preference plists). Restoring
#   this onto a device that has no matching keychain credential is the
#   *proven* trigger of the post-restore "verify your Apple ID" prompt: the
#   device finds an account it cannot authenticate and asks the user. The
#   iOS 27 selective restore cannot re-import a backup keychain, so this
#   group must stay out of the protective restore by default.
# * session state — the identity-services token / provisioning cache and the
#   account-daemon preference plists. Upstream GoldenNugget does not carry
#   these either; restoring them is harmless but pointless (the device keeps
#   its own live copy in the merged flow).
# * Find My / adid identity — the containers that keep the Find My identity
#   alive across the safe-state recovery wipe. Upstream does not carry them
#   either, but they are the reason the wipe does not cost the user their
#   Find My setup, so they are kept by default.
#
# The App Store / media-purchase account state (com.apple.itunesstored,
# com.apple.amsaccountsd) is in none of these groups: it is a separate
# account and does not drive the verification prompt.
APPLE_ID_ACCOUNT_PATH_PREFIXES = (
    "Library/Accounts",               # Account database (Accounts3.sqlite)
)

APPLE_ID_ACCOUNT_PREF_PREFIXES = (
    "Library/Preferences/com.apple.appleaccount",
)

APPLE_ID_SESSION_PATH_PREFIXES = IDENTITY_SERVICES_PATH_PREFIXES

APPLE_ID_SESSION_PREF_PREFIXES = (
    "Library/Preferences/com.apple.ids",
    "Library/Preferences/com.apple.identityservices",
    "Library/Preferences/com.apple.accountsd",
    "Library/Preferences/com.apple.madrid",
)

# The Find My / adid identity containers and the preference plists that go
# with them.
FIND_MY_PREF_PREFIXES = (
    "Library/Preferences/com.apple.icloud.findmydeviced",
    "Library/Preferences/com.apple.fairplaydeviceidentityd",
)

# Files/dirs inside the protective HomeDomain scope that tweaks write
# themselves — restoring the stale copies would undo the applied tweaks.
_SKIP_PATH_PREFIXES = (
    "Library/SpringBoard/statusBarOverrides",          # iOS ≤26 classic binary struct
    "Library/SpringBoard/StatusBarOverrides.archive",  # iOS 27+ NSKeyedArchiver record
)

# App-domain mirrors of the managed-preference targets.
_SKIP_APP_PREF_FILES = managed_pref_app_plists()

# Files iOS manages internally and rejects if included in a sparse backup with
# incorrect metadata (e.g. wrong protection class).
_SKIP_FILES = frozenset({
    "keychain-backup.plist",    # iOS validates protection class, rejects flags=4
    ".GlobalPreferences.plist",  # Written separately as tweaks; skip to avoid overwrite
})

# PosterBoard sqlite database carried by the protective backup so wallpaper
# applies need no second device backup.
POSTERBOARD_DB_DOMAIN = "AppDomain-com.apple.PosterBoard"
POSTERBOARD_DB_NAME = "PBFPosterExtensionDataStoreSQLiteDatabase.sqlite3"
POSTERBOARD_DB_STORE_DIR = "PRBPosterExtensionDataStore"


def _is_apple_id_session(domain: str, relative_path: str) -> bool:
    """Whether a manifest entry carries Apple-ID session/token state."""
    if domain != "HomeDomain" or not relative_path:
        return False
    return (relative_path.startswith(APPLE_ID_SESSION_PATH_PREFIXES)
            or relative_path.startswith(APPLE_ID_SESSION_PREF_PREFIXES))


def _is_apple_id_account(domain: str, relative_path: str) -> bool:
    """Whether a manifest entry carries the Apple-ID account record."""
    if domain != "HomeDomain" or not relative_path:
        return False
    return (relative_path.startswith(APPLE_ID_ACCOUNT_PATH_PREFIXES)
            or relative_path.startswith(APPLE_ID_ACCOUNT_PREF_PREFIXES))


def _is_find_my_state(domain: str, relative_path: str) -> bool:
    """Whether a manifest entry carries the Find My / adid identity state."""
    if domain in PROTECTIVE_IDENTITY_DOMAINS:
        return True
    if domain != "HomeDomain" or not relative_path:
        return False
    return relative_path.startswith(FIND_MY_PREF_PREFIXES)


def _drop_apple_id(domain: str, relative_path: str, include_apple_account: bool,
                   include_apple_identity: bool,
                   include_find_my_state: bool) -> bool:
    """Whether the entry must be kept out of the protective backup."""
    if not include_apple_account and _is_apple_id_account(domain, relative_path):
        return True
    if not include_apple_identity and _is_apple_id_session(domain, relative_path):
        return True
    if not include_find_my_state and _is_find_my_state(domain, relative_path):
        return True
    return False


def _device_relative_path(device_name: str) -> str:
    """An upload's path inside its domain, for both device-side name layouts.

    Pre-iOS 27 the upload name is domain-qualified
    (``HomeDomain/Library/Preferences/x.plist``); on iOS 27 the HomeDomain
    tree carries no domain prefix (``/.b/6/Library/Preferences/x.plist``).
    Both are reduced to the path the manifest row uses, so the upload filter
    and the prune filter can be compared directly.
    """
    name = _device_tree_name(device_name)
    for domain in _DOMAIN_PREFIXES:
        if name.startswith(domain + "/"):
            return name[len(domain) + 1:]
    return name


def _is_apple_id_session_upload(device_name: str) -> bool:
    """Whether an upload carries Apple-ID session/token state."""
    relative_path = _device_relative_path(device_name)
    return (relative_path.startswith(APPLE_ID_SESSION_PATH_PREFIXES)
            or relative_path.startswith(APPLE_ID_SESSION_PREF_PREFIXES))


def _is_apple_id_account_upload(device_name: str) -> bool:
    """Whether an upload carries the Apple-ID account record."""
    relative_path = _device_relative_path(device_name)
    return (relative_path.startswith(APPLE_ID_ACCOUNT_PATH_PREFIXES)
            or relative_path.startswith(APPLE_ID_ACCOUNT_PREF_PREFIXES))


def _is_find_my_state_upload(device_name: str) -> bool:
    """Whether an upload carries the Find My / adid identity state."""
    # The Find My / adid system containers: the upload name carries the
    # container id, not the domain (iOS 27 physical tree).
    if _identity_container_domain(device_name) in PROTECTIVE_IDENTITY_DOMAINS:
        return True
    for domain in PROTECTIVE_IDENTITY_DOMAINS:
        if _domain_match(device_name, domain):
            return True
    relative_path = _device_relative_path(device_name)
    return relative_path.startswith(FIND_MY_PREF_PREFIXES)


def _drop_apple_id_upload(device_name: str, include_apple_account: bool,
                          include_apple_identity: bool,
                          include_find_my_state: bool) -> bool:
    """Upload-side twin of :func:`_drop_apple_id`."""
    if not include_apple_account and _is_apple_id_account_upload(device_name):
        return True
    if not include_apple_identity and _is_apple_id_session_upload(device_name):
        return True
    if not include_find_my_state and _is_find_my_state_upload(device_name):
        return True
    return False


def _is_protective_file(domain: str, relative_path: str, include_photos: bool = True, include_keychain: bool = False,
                        exclude_afc_media_trees: bool = False,
                        include_apple_account: bool = False,
                        include_apple_identity: bool = True,
                        include_find_my_state: bool = True) -> bool:
    """Check if a file belongs in the protective backup."""
    filename = relative_path.rsplit("/", 1)[-1]
    if filename in _SKIP_FILES and not (include_keychain and filename == "keychain-backup.plist"):
        return False
    if _drop_apple_id(domain, relative_path, include_apple_account,
                      include_apple_identity, include_find_my_state):
        return False
    if domain == "HomeDomain":
        if relative_path.startswith(_SKIP_PATH_PREFIXES):
            return False
        if relative_path in _SKIP_APP_PREF_FILES:
            return False
        return (relative_path.startswith(APPLE_ID_PATH_PREFIXES)
                or relative_path.startswith(SPRINGBOARD_PATH_PREFIXES)
                or relative_path.startswith(CONTROL_CENTER_PATH_PREFIXES)
                or relative_path.startswith(SHORTCUTS_PATH_PREFIXES)
                or relative_path.startswith(WEB_CLIPS_PATH_PREFIXES)
                or relative_path.startswith(WEB_APP_PATH_PREFIXES)
                or relative_path.startswith(WEBKIT_WEBSITE_DATA_PATH_PREFIXES)
                or relative_path.startswith(ADDRESS_BOOK_PATH_PREFIXES)
                or relative_path.startswith(IDENTITY_SERVICES_PATH_PREFIXES))
    if domain in PROTECTIVE_IDENTITY_DOMAINS:
        return True
    if include_photos and domain in PROTECTIVE_DOMAINS:
        if exclude_afc_media_trees and _media_tree_scope(relative_path) in AFC_MEDIA_TREES:
            return False
        return True
    if include_keychain and domain == KEYCHAIN_DOMAIN:
        return True
    return False


def _norm_device_name(device_name: str) -> str:
    return device_name.replace("\\", "/").lstrip("/")


# iOS 27 physical tree: uploads arrive under ``/.b/<n>/<segment>/`` and the
# segment is the *physical* directory name, not the manifest domain name —
# verified against a real iOS 27 backup (``preferences`` carries
# SystemPreferencesDomain 13/13, ``protected`` ProtectedDomain 5/5,
# ``wireless`` WirelessDomain, ``root`` RootDomain, ``Managed Preferences``
# ManagedPreferencesDomain, ``db`` DatabaseDomain, ``installd`` InstallDomain,
# ``networkd`` NetworkDomain, ``MobileDevice`` MobileDeviceDomain,
# ``Keychains`` KeychainDomain). Pre-iOS 27 devices upload ``<domain>/...``.
_TREE_DOMAIN_SEGMENTS = {
    "Keychains": "KeychainDomain",
    "MobileDevice": "MobileDeviceDomain",
    "Managed Preferences": "ManagedPreferencesDomain",
    "preferences": "SystemPreferencesDomain",
    "protected": "ProtectedDomain",
    "root": "RootDomain",
    "wireless": "WirelessDomain",
    "db": "DatabaseDomain",
    "installd": "InstallDomain",
    "networkd": "NetworkDomain",
}


def _domain_match(device_name: str, domain: str) -> bool:
    name = _norm_device_name(device_name)
    if name == domain or name.startswith(f"{domain}/"):
        return True
    # iOS 27 physical tree: match the segment that carries this domain
    # (e.g. SystemPreferencesDomain travels as ``/.b/<n>/preferences/...``).
    # Without this the domain-qualified keep-set never matches and those
    # payloads are dropped while their manifest rows stay, failing the
    # payload verification.
    for segment, dom in _TREE_DOMAIN_SEGMENTS.items():
        if dom == domain and _tree_match(device_name, segment):
            return True
    return False


def _path_match(device_name: str, path: str) -> bool:
    """Match a HomeDomain-scoped path prefix against a device-side upload name.

    Accepts the three layouts seen in the wild:
    - bare physical path: ``Library/Preferences/...``
    - legacy domain-qualified: ``HomeDomain/Library/Preferences/...``
    - iOS 27 physical tree: ``/.b/<n>/Library/Preferences/...`` (via ``_tree_match``)
    """
    name = _norm_device_name(device_name)
    if name == path or name.startswith(f"{path}/"):
        return True
    if name == f"HomeDomain/{path}" or name.startswith(f"HomeDomain/{path}/"):
        return True
    return _tree_match(device_name, path)


def _device_tree_name(device_name: str) -> str:
    """Normalised device name with the iOS 27+ backup-session root stripped."""
    name = _norm_device_name(device_name)
    for prefix in (".b", "b"):
        if name.startswith(f"{prefix}/"):
            name = name[len(prefix) + 1:]
            if name.split("/", 1)[0].isdigit():
                return name.split("/", 1)[1]
            break
    return name


def _tree_match(device_name: str, *trees: str) -> bool:
    """Match a device name against physical tree roots (iOS 27+ layout)."""
    name = _device_tree_name(device_name)
    for tree in trees:
        if name == tree or name.startswith(f"{tree}/"):
            return True
    return False


def _identity_container_domain(device_name: str) -> Optional[str]:
    """Map an iOS 27 physical container path to its system-container domain.

    iOS 27 uploads system containers under the physical tree, where the path
    segment is the container id, not the manifest domain name:
      ``containers/Shared/SystemGroup/<id>/...`` -> ``SysSharedContainerDomain-<id>``
      ``containers/System/<id>/...``             -> ``SysContainerDomain-<id>``
    Pre-iOS 27 devices already upload the domain-qualified name, which
    ``_domain_match`` handles. Returns the derived domain, or ``None`` when the
    name is not one of these physical container trees.
    """
    name = _device_tree_name(device_name)
    for prefix, domain_prefix in (
        ("containers/Shared/SystemGroup/", "SysSharedContainerDomain-"),
        ("containers/System/", "SysContainerDomain-"),
    ):
        if name.startswith(prefix):
            cid = name[len(prefix):].split("/", 1)[0]
            if cid:
                return f"{domain_prefix}{cid}"
    return None


def _media_tree_scope(device_name: str) -> str:
    """Top-level ``Media`` child an upload lives under, or ``""`` if none."""
    name = _device_tree_name(device_name)
    for prefix in ("CameraRollDomain/Media/", "MediaDomain/Media/", "Media/"):
        if name.startswith(prefix):
            rest = name[len(prefix):]
            seg = rest.split("/", 1)[0]
            return seg
    return ""


def _posterboard_db_match(device_name: str) -> bool:
    """Match the PosterBoard sqlite database by its physical file name."""
    name = _norm_device_name(device_name)
    return POSTERBOARD_DB_NAME in name


def is_protective_device_file(device_name: str, include_photos: bool = True,
                              include_posterboard: bool = False,
                              include_keychain: bool = False,
                              exclude_afc_media_trees: bool = False,
                              include_apple_account: bool = False,
                              include_apple_identity: bool = True,
                              include_find_my_state: bool = True) -> bool:
    """Mid-stream backup filter: match an upload's device-side name against the keep-set."""
    if _drop_apple_id_upload(device_name, include_apple_account,
                             include_apple_identity, include_find_my_state):
        # Must match the prune filter exactly: an upload kept here but
        # dropped there leaves a manifest row without a payload, which the
        # restore agent rejects with MBErrorDomain/205.
        return False
    for domain in (("CameraRollDomain", "MediaDomain") if include_photos else ()) + \
            ("SystemPreferencesDomain", "MessagesDomain", "AddressBookDomain") + \
            tuple(PROTECTIVE_IDENTITY_DOMAINS):
        if _domain_match(device_name, domain):
            if exclude_afc_media_trees and _media_tree_scope(device_name) in AFC_MEDIA_TREES:
                continue
            return True
    # iOS 27 physical container trees (containers/Shared/SystemGroup/<id>,
    # containers/System/<id>): the domain loop above cannot see them because the
    # upload name carries the container id, not the domain. Map them back so the
    # Find My / identity payloads are kept (matching the prune filter).
    if _identity_container_domain(device_name) in PROTECTIVE_IDENTITY_DOMAINS:
        return True
    if include_photos and not (exclude_afc_media_trees
                               and _media_tree_scope(device_name) in AFC_MEDIA_TREES) \
            and _tree_match(device_name, "Media"):
        return True
    if _tree_match(device_name, "Library/Messages", "Library/SMS", "Library/MessagesMetaData"):
        return True
    if include_keychain and (_domain_match(device_name, KEYCHAIN_DOMAIN)
                             or _tree_match(device_name, "Keychains")):
        return True
    for prefix in (APPLE_ID_PATH_PREFIXES + SPRINGBOARD_PATH_PREFIXES
               + CONTROL_CENTER_PATH_PREFIXES + SHORTCUTS_PATH_PREFIXES
               + WEB_CLIPS_PATH_PREFIXES + WEB_APP_PATH_PREFIXES
               + WEBKIT_WEBSITE_DATA_PATH_PREFIXES
               + ADDRESS_BOOK_PATH_PREFIXES
               + IDENTITY_SERVICES_PATH_PREFIXES):
        if _path_match(device_name, prefix):
            return True
    if include_posterboard and _posterboard_db_match(device_name):
        return True
    return False


async def set_will_encrypt(mb: ProtectiveBackupService, enable: bool, backup_directory: str,
                           password: str = "") -> None:
    """Set the device's backup-encryption state via mobilebackup2 ChangePassword.

    ``mb`` is any Mobilebackup2Service (connects lazily). mobilebackup2 has no
    ``SetBackupOptions`` — that is the old mobilebackup1 command, and the device
    tears down the session when it receives one. The mobilebackup2 way (as in
    Finder and tools/idevicebackup2.c) is ``ChangePassword``: enabling sets a
    ``NewPassword``; disabling supplies the current password as ``OldPassword``
    — there is no passwordless toggle. Encryption is what makes the device
    upload KeychainDomain (Apple ID credentials, …) at all.

    The device replies only after acting on the request, which since iOS 13
    may include an on-device passcode confirmation (LocalAuthentication); keep
    the session open until the reply arrives instead of timing out host-side.

    Before the final reply the device may ask the host to remove metadata of a
    previous, now-incompatible backup (an unencrypted ``Snapshot/Manifest.plist``
    when switching on, the reverse when switching off). ``dl_loop`` answers
    those requests and returns only on the final ``DLMessageProcessMessage``.
    """
    if not password:
        raise NuggetException(
            "Changing backup encryption requires the backup password — the "
            "new one when enabling, the current one when disabling. There is "
            "no passwordless toggle on the mobilebackup2 protocol.")
    message: dict = {"MessageName": "ChangePassword",
                     "TargetIdentifier": mb.lockdown.udid}
    message["NewPassword" if enable else "OldPassword"] = password
    try:
        async with mb.device_link(Path(backup_directory)) as dl:
            await dl.send_process_message(message)
            # Handles the device's RemoveItems/GetFreeDiskSpace requests and
            # returns on the final ProcessMessage (ErrorCode 0), raising
            # PyMobileDevice3Exception on a non-zero ErrorCode.
            await dl.dl_loop()
    except _pm3_exc.ConnectionTerminatedError as e:
        raise NuggetException(
            "The device closed the mobilebackup2 session while backup "
            "encryption was being switched "
            f"{'on' if enable else 'off'} — unlock the device, answer (or "
            "cancel) any on-device passcode prompt, and retry") from e
    except _pm3_exc.PyMobileDevice3Exception as e:
        raise NuggetException(
            f"Device refused to {'enable' if enable else 'disable'} "
            f"backup encryption: {e}") from e
    if enable:
        log_info(f"Backup encryption enabled (password "
                 f"{'set by the tool' if password else 'chosen on the device'})")
    else:
        log_info("Backup encryption disabled — device back in its original state")


class ProtectiveBackupService(Mobilebackup2Service):
    """Mobilebackup2Service tuned for fast protective backups.

    - ``init_mobile_backup_factory_info`` returns an empty ``Applications``
      dict, so the device skips all app containers (AppDomain-*) entirely.
      With ``include_posterboard`` it lists only the PosterBoard container so
      its sqlite database rides the same backup.
    - Mid-stream payload filtering is done via pymobiledevice3's native
      ``filter_callback`` on ``backup()``.
    - ``connect`` retries transient failures with exponential backoff.
    """

    def __init__(self, lockdown, include_posterboard: bool = False, authentication_callback=None):
        super().__init__(lockdown)
        self.include_posterboard = include_posterboard
        self.authentication_callback = authentication_callback

    def _log_backup_notification(self, event):
        super()._log_backup_notification(event)
        name = event.get("Name")
        if self.authentication_callback is not None:
            if name == NP_LOCAL_AUTH_PRESENTED:
                self.authentication_callback(True)
            elif name == NP_LOCAL_AUTH_DISMISSED:
                self.authentication_callback(False)

    async def connect(self, max_retries: int = 5):
        from .utils import async_retry

        retryable = (_pm3_exc.ConnectionTerminatedError, ConnectionError,
                     OSError, asyncio.TimeoutError)
        base_connect = super().connect
        return await async_retry(
            base_connect,
            max_retries,
            retry_if=lambda e: isinstance(e, retryable),
            exp_cap=15,
            on_retry=lambda attempt, total, e, delay: print(
                f"[ProtectiveBackup] mobilebackup2 connect failed "
                f"(attempt {attempt}/{total}), retrying in {delay}s: {e}"
            ),
        )

    @asynccontextmanager
    async def device_link(self, backup_directory, filter_callback=None, password=""):
        retryable = (_pm3_exc.ConnectionTerminatedError, ConnectionError, asyncio.TimeoutError)
        stack = AsyncExitStack()
        try:
            link = None
            for attempt in range(3):
                try:
                    link = await stack.enter_async_context(super().device_link(
                        backup_directory, filter_callback=filter_callback, password=password))
                    break
                except retryable as error:
                    log_warn(f"Backup service closed during DeviceLink handshake (attempt {attempt + 1}/3): {type(error).__name__}. This does not establish a USB disconnect.")
                    try:
                        await self.close()
                    except Exception:
                        pass
                    if attempt == 2:
                        raise
                    await asyncio.sleep(3 * (attempt + 1))
            yield link
        finally:
            await stack.aclose()

    async def enable_backup_encryption(self, backup_directory: str,
                                       password: str = "") -> None:
        """Turn on backup encryption (see ``set_will_encrypt``)."""
        await set_will_encrypt(self, True, backup_directory, password)

    async def init_mobile_backup_factory_info(self, afc):
        root_node = self.lockdown.all_values
        info = {
            "iTunes Version": "10.0.1",
            "iTunes Files": {},
            "Unique Identifier": self.lockdown.udid.upper(),
            "Target Type": "Device",
            "Target Identifier": root_node["UniqueDeviceID"],
            "Serial Number": root_node["SerialNumber"],
            "Product Version": root_node["ProductVersion"],
            "Product Type": root_node["ProductType"],
            "Installed Applications": [],
            "GUID": _uuid.uuid4().bytes,
            "Display Name": root_node.get("DeviceName", ""),
            "Device Name": root_node.get("DeviceName", ""),
            "Build Version": root_node["BuildVersion"],
            "Applications": {},  # skip all app containers — big speedup
        }
        if self.include_posterboard:
            await self._add_posterboard_container(info)
        return info

    async def _add_posterboard_container(self, info: dict):
        """List only the PosterBoard container so its sqlite DB rides this backup."""
        try:
            from pymobiledevice3.services.installation_proxy import InstallationProxyService
            from pymobiledevice3.services.springboard import SpringBoardServicesService
            bundle_id = POSTERBOARD_DB_DOMAIN.removeprefix("AppDomain-")
            async with InstallationProxyService(lockdown=self.lockdown) as ip:
                apps = await ip.get_apps(application_type="Any", calculate_sizes=False)
            app_info = apps.get(bundle_id)
            if app_info is None:
                log_warn("PosterBoard app not found via installation proxy; skipping container inclusion")
                return
            entry = {
                "Container": app_info["Container"],
                "CFBundleIdentifier": bundle_id,
                "CFBundleVersion": app_info.get("CFBundleVersion", "1.0"),
                "ApplicationSINF": app_info.get("ApplicationSINF", b""),
                "iTunesMetadata": app_info.get("iTunesMetadata", {}),
            }
            try:
                async with SpringBoardServicesService(self.lockdown) as sbs:
                    entry["PlaceholderIcon"] = await sbs.get_icon_pngdata(bundle_id)
            except Exception:
                entry["PlaceholderIcon"] = b""
            info["Installed Applications"] = [bundle_id]
            info["Applications"] = {bundle_id: entry}
            log_debug(f"PosterBoard container added to factory info: "
                      f"bundle={bundle_id} Container={app_info.get('Container')} "
                      f"keys={sorted(entry.keys())}")
        except Exception as e:
            log_warn(f"PosterBoard container inclusion failed: {e}")


async def perform_protective_backup(
    lockdown_client: LockdownClient,
    backup_root: str,
    progress_callback=None,
    include_photos: bool = True,
    include_posterboard: bool = False,
    include_keychain: Optional[bool] = None,
    incremental_ok: bool = False,
    include_afc_media: bool = False,
    media_root: str = None,
    afc_media_diff: bool = False,
    backup_password: str = "",
    include_apple_account: bool = False,
    include_apple_identity: bool = True,
    include_find_my_state: bool = True,
) -> bool:
    report_progress = progress_callback
    authentication_presented = False

    def progress_callback(progress):
        if report_progress is not None and not authentication_presented:
            report_progress(progress)

    def authentication_changed(presented):
        nonlocal authentication_presented
        authentication_presented = presented
        if report_progress is not None:
            report_progress(BackupStatus(
                tr("iOS authentication prompt detected. Check your iPhone and enter its passcode if requested to continue the protective backup.")
                if presented else
                tr("iOS authentication prompt closed. Waiting for protective backup progress…"),
                "authentication" if presented else "backup"))

    await check_disk_space_for_backup(lockdown_client, path=backup_root)
    if not incremental_ok:
        Path(backup_root).mkdir(parents=True, exist_ok=True)

    afc_media_task = None
    if include_afc_media:
        media_dir = media_root or afc_media_dir_for(backup_root)
        if media_root is None:
            (Path(backup_root).parent / '.afc_media_required').touch()
        afc_media_task = asyncio.create_task(backup_media_via_afc(
            lockdown_client,
            media_dir,
            progress_callback=progress_callback,
            diff=afc_media_diff,
        ))
        log_info("Photos/videos over AFC in parallel: pulling "
                 f"{sorted(AFC_MEDIA_TREES)} via AFC; mobilebackup2 keeps "
                 "PhotoData and the rest of the protective scope")

    _pb_names_to_db: list = []
    _totals = {"seen": 0, "kept": 0, "containers": 0}
    _last_category = [None]

    def _category_for(name: str) -> str:
        low = name.lower()
        if "keychaindomain" in low:
            return BackupStatus(tr("Keychain"), "keychain")
        if "messagesdomain" in low:
            return BackupStatus(tr("Messages"), "messages")
        if "camerarolldomain" in low or "mediadomain" in low:
            return BackupStatus(tr("Photos and videos"), "photos")
        if "accounts" in low or "appleaccount" in low:
            return BackupStatus(tr("Apple account"), "account")
        if "springboard" in low or "home screen" in low:
            return BackupStatus(tr("Home screen"), "home")
        if "shortcuts" in low:
            return BackupStatus(tr("Shortcuts"), "shortcuts")
        if "poster" in low:
            return BackupStatus(tr("Wallpaper data"), "wallpaper")
        if "preferences" in low or "configurationprofiles" in low:
            return BackupStatus(tr("Settings"), "settings")
        return BackupStatus(tr("Device data"), "backup")

    def _filter_callback(backup_file):
        name = backup_file.device_name or ""
        category = _category_for(name)
        if category != _last_category[0]:
            _last_category[0] = category
            if progress_callback:
                progress_callback(BackupStatus(category + "…", category.category))
        keep = is_protective_device_file(
            name,
            include_photos=include_photos,
            include_posterboard=include_posterboard,
            include_keychain=include_keychain,
            exclude_afc_media_trees=include_afc_media,
            include_apple_account=include_apple_account,
            include_apple_identity=include_apple_identity,
            include_find_my_state=include_find_my_state)
        _totals["seen"] += 1
        _totals["kept"] += int(keep)
        low = name.lower()
        if "containers/" in low or "/.b/" in low:
            _totals["containers"] += 1
        if include_posterboard and ("poster" in low or POSTERBOARD_DB_NAME.lower() in low):
            _pb_names_to_db.append((name, keep))
            log_debug(f"PB filter {'KEEP' if keep else 'drop'}: {name}")
        return keep

    is_encrypted = False
    try:
        async with ProtectiveBackupService(
                lockdown_client, include_posterboard=include_posterboard,
                authentication_callback=authentication_changed) as mb:
            try:
                is_encrypted = await mb.get_will_encrypt()
            except Exception:
                pass
            if include_keychain is None:
                include_keychain = is_encrypted
            if include_keychain and not is_encrypted:
                # The keychain (Apple ID credentials, …) is only ever uploaded
                # by an ENCRYPTED backup, so enable encryption on the fly —
                # without it the post-restore "verify your Apple ID" prompt
                # has to be answered by hand (no saved credential).
                log_info("Backup encryption is off — enabling it so the keychain "
                         "is backed up and restored with the account")
                progress_callback("Enabling backup encryption for the keychain...")
                await mb.enable_backup_encryption(backup_root, backup_password)
                is_encrypted = True
            if is_encrypted:
                log_info("Backup encryption already enabled on device.")
                progress_callback("Using existing backup encryption...")
            else:
                progress_callback("Creating protective backup (unencrypted)...")
            try:
                await mb.backup(full=not incremental_ok, backup_directory=backup_root,
                                progress_callback=progress_callback,
                                filter_callback=_filter_callback)
            except NotEnoughDiskSpaceError as e:
                message = str(e).strip() or backup_disk_space_message(backup_root)
                log_warn(message)
                if progress_callback:
                    progress_callback(message)
                raise BackupDiskSpaceError(message) from e
    except BaseException:
        if afc_media_task is not None:
            afc_media_task.cancel()
            try:
                await afc_media_task
            except (asyncio.CancelledError, Exception):
                pass
        raise
    else:
        if afc_media_task is not None:
            try:
                await afc_media_task
            except NuggetException:
                raise
            except asyncio.CancelledError:
                raise
            except Exception as e:
                raise NuggetException(
                    tr("Could not back up photos/videos over AFC: {0}").format(e)) from e

    kept = sum(1 for _, keep in _pb_names_to_db if keep)
    log_info(f"Backup upload tally: seen={_totals['seen']} kept={_totals['kept']} "
             f"container_paths={_totals['containers']} | PosterBoard names seen="
             f"{len(_pb_names_to_db)} (kept {kept}, dropped {len(_pb_names_to_db) - kept})")

    return is_encrypted


async def is_backup_encrypted(lockdown_client: LockdownClient) -> bool:
    """Check whether the device currently encrypts its backups."""
    try:
        async with Mobilebackup2Service(lockdown_client) as mb:
            return await mb.get_will_encrypt()
    except Exception as e:
        log_warn(f"Could not read backup encryption state: {e}")
        return False


# The keychain's on-disk identity. The device uploads it as
# ``KeychainDomain/keychain-backup.plist``; the payload lives under the
# standard ``<aa>/<fileID>`` layout with ``fileID = SHA1("<domain>-<relativePath>")``.
KEYCHAIN_BACKUP_FILENAME = "keychain-backup.plist"


def backup_contains_keychain(backup_dir, udid: str) -> Optional[bool]:
    """Whether a backup's payload tree carries the keychain blob.

    Returns ``None`` when the backup's device directory cannot be identified.
    The check is a plain payload-existence probe (no manifest read), so it
    works for encrypted and unencrypted backups alike and needs no password.
    A backup taken without ``include_keychain`` — e.g. a cache master
    refreshed with the default — has no ``KeychainDomain`` upload and
    therefore no such payload, even when encrypted.
    """
    device_dir = Path(backup_dir) / udid
    if not device_dir.is_dir():
        if (Path(backup_dir) / "Manifest.db").exists():
            device_dir = Path(backup_dir)
        else:
            return None
    # fileID convention: SHA1("<domain>-<relativePath>") — see inject.py.
    file_id = hashlib.sha1(
        f"{KEYCHAIN_DOMAIN}-{KEYCHAIN_BACKUP_FILENAME}".encode("utf-8")
    ).hexdigest()
    return (device_dir / file_id[:2] / file_id).is_file()


# Retention for finished live backups: how many to keep per device.
PROTECTIVE_KEEP_RUNS = 1


def protective_persistent_base() -> Path:
    """Per-user folder holding live protective backups that survive reboots."""
    return protective_base()


def new_protective_backup_dir(udid: str) -> str:
    """Create a fresh, persistent directory for one live protective backup.

    Layout: ``<persistent base>/<udid>/<timestamp>-<pid>-<rand>/device_backup``.
    """
    safe_udid = udid or "unknown"
    run_dir = (protective_persistent_base() / safe_udid
               / f"{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid()}-{_uuid.uuid4().hex[:8]}")
    backup_root = run_dir / "device_backup"
    backup_root.mkdir(parents=True, exist_ok=True)
    return str(backup_root)


def list_protective_backups(udid: str) -> list:
    """Completed, usable live backup run directories for ``udid``, newest first."""
    safe_udid = udid or "unknown"
    root = protective_persistent_base() / safe_udid
    if not root.is_dir():
        return []
    runs = []
    for entry in root.iterdir():
        device_dir = entry / "device_backup" / safe_udid
        manifest_db = device_dir / "Manifest.db"
        if not entry.is_dir() or not manifest_db.is_file():
            continue
        if (not _validate_sqlite_db(manifest_db)
                and not _is_encrypted_backup(device_dir)):
            log_warn(f"Skipping protective backup {entry.name}: Manifest.db is "
                     f"corrupt or incomplete (interrupted upload?)")
            continue
        runs.append(entry)
    runs.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return runs


def find_latest_protective_backup(udid: str) -> Optional[str]:
    """``backup_root`` of the newest live protective backup for ``udid``."""
    runs = list_protective_backups(udid)
    return str(runs[0] / "device_backup") if runs else None


def prune_protective_backups(udid: str, keep: int = PROTECTIVE_KEEP_RUNS) -> int:
    """Drop older live backups for ``udid``, keeping the newest ``keep``."""
    runs = list_protective_backups(udid)
    removed = 0
    for old in runs[keep:]:
        shutil.rmtree(old, ignore_errors=True)
        if not old.exists():
            removed += 1
            log_info(f"Pruned old protective backup: {old}")
    return removed


def _copy_backup_tree(src_root: Path, dst_root: Path) -> None:
    """Faithfully copy one backup device dir into ``dst_root``.

    Metadata (incl. sqlite sidecars) is real-copied — pruning rewrites
    Manifest.db, and a hardlink would corrupt the cache master through the
    shared inode/-wal. Everything else is hardlinked, with a copy fallback.
    """
    dst_root.mkdir(parents=True, exist_ok=True)
    always_copy = set(_BACKUP_METADATA_FILES) | {"Manifest.db-wal", "Manifest.db-shm"}
    for dirpath, _dirnames, filenames in os.walk(src_root):
        rel = Path(dirpath).relative_to(src_root)
        (dst_root / rel).mkdir(parents=True, exist_ok=True)
        for name in filenames:
            src_file = Path(dirpath) / name
            dst_file = dst_root / rel / name
            if name in always_copy:
                shutil.copy2(src_file, dst_file)
            else:
                try:
                    os.link(src_file, dst_file)
                except OSError:
                    shutil.copy2(src_file, dst_file)


def make_restore_view(master_root: str, udid: str, view_root: str) -> str:
    """Build a disposable restore *view* of the cache master.

    The master must never be modified by an apply, so the prune and the tweak
    injection run against a view: hardlinks to the master's payloads plus real
    copies of its metadata. Returns the view's parent directory.
    """
    src_root = Path(master_root) / udid
    if not src_root.is_dir():
        if (Path(master_root) / "Manifest.db").is_file():
            src_root = Path(master_root)
        else:
            raise NuggetException("Cache master is missing its payload.")

    view_parent = Path(view_root)
    view_device = view_parent / udid
    shutil.rmtree(view_device, ignore_errors=True)
    view_device.mkdir(parents=True, exist_ok=True)
    _copy_backup_tree(src_root, view_device)
    return str(view_parent)


def discard_restore_view(view_root: str, udid: str) -> None:
    """Remove a per-apply restore view (disposable hardlink farm)."""
    if not view_root:
        return
    shutil.rmtree(Path(view_root) / udid, ignore_errors=True)


def make_protective_working_copy(backup_root: str, udid: str) -> str:
    """Build a throwaway hardlink copy of a protective backup for prune + injection."""
    working_root = Path(tempfile.mkdtemp(prefix=WORKING_COPY_PREFIX)) / "device_backup"
    src_root = Path(backup_root) / udid
    if not src_root.is_dir():
        if (Path(backup_root) / "Manifest.db").is_file():
            src_root = Path(backup_root)
        else:
            raise NuggetException("Protective backup is missing its payload.")

    _copy_backup_tree(src_root, working_root / udid)
    return str(working_root)


def make_cache_snapshot(backup_root: str, udid: str, inject_files: list = None) -> str:
    """Deprecated: the cache master is no longer modified in place."""
    raise NotImplementedError(
        "the cache master is immutable — use make_restore_view() instead")


def regenerate_cache_from_snapshot(snapshot_dir: str, backup_root: str, udid: str) -> str:
    """Deprecated: the cache master is never modified, so nothing regenerates it."""
    raise NotImplementedError(
        "the cache master is immutable — it needs no regeneration")


def verify_backup_payloads(backup_dir, udid: str,
                           manifest_password: str = "") -> list[str]:
    """Return missing paths, raising when verification could not be performed."""
    return inspect_backup_payloads(
        backup_dir, udid, manifest_password, inventory=_payload_inventory,
        is_sqlite=_validate_sqlite_db, is_encrypted=_is_encrypted_backup,
        decrypt=Mobilebackup2Service._decrypt_backup_manifest_db,
    ).require_verified()


def posterboard_structure_version(rel_path: str) -> int:
    """Derive the PosterBoard store structure version from a manifest path."""
    marker = f"{POSTERBOARD_DB_STORE_DIR}/"
    idx = rel_path.find(marker)
    if idx >= 0:
        num = ""
        for ch in rel_path[idx + len(marker):]:
            if ch.isdigit():
                num += ch
            else:
                break
        if num:
            return int(num)
    return 61


def _require_usable_pb_snapshot(db_path) -> None:
    """Gate a pulled PosterBoard database on the strong snapshot check."""
    require_usable_snapshot(str(db_path))


def extract_posterboard_db(backup_root: str, udid: str, dest_path: str) -> Optional[tuple[str, int]]:
    """Pull the PosterBoard sqlite database out of a (refreshed) protective backup.

    Returns ``(destination_path, structure_version)`` — or None when the backup
    does not carry the database.
    """
    device_dir = Path(backup_root) / udid
    if not device_dir.is_dir():
        if (Path(backup_root) / "Manifest.db").is_file():
            device_dir = Path(backup_root)
        else:
            log_debug(f"extract_posterboard_db: no device dir and no Manifest.db under {backup_root}")
            return None
    manifest_db = device_dir / "Manifest.db"
    if not _validate_sqlite_db(manifest_db):
        log_warn(f"extract_posterboard_db: Manifest.db at {manifest_db} is missing/encrypted/"
                 f"not a valid SQLite db (backup may be incomplete)")
        return None
    log_debug(f"extract_posterboard_db: scanning {manifest_db}")
    conn = sqlite3.connect(str(manifest_db))
    try:
        pb_rows = conn.execute(
            "SELECT fileID, relativePath FROM Files "
            "WHERE relativePath LIKE ? OR relativePath LIKE ? "
            "ORDER BY relativePath",
            (f"%{POSTERBOARD_DB_NAME}%", f"%{POSTERBOARD_DB_STORE_DIR}%"),
        ).fetchall()
        if not pb_rows:
            total_rows = conn.execute("SELECT COUNT(*) FROM Files").fetchone()[0]
            container_count = conn.execute(
                "SELECT COUNT(*) FROM Files WHERE relativePath LIKE '%Containers/%'").fetchone()[0]
            poster_rows = conn.execute(
                "SELECT relativePath FROM Files WHERE relativePath LIKE '%Poster%' "
                "ORDER BY relativePath LIMIT 20").fetchall()
            log_warn(
                f"Master manifest has NO PosterBoard rows ({total_rows} rows total, "
                f"{container_count} under Containers/; Poster-ish sample: "
                f"{[r[0] for r in poster_rows]})")
            return None
    finally:
        conn.close()

    # resolve by FILE NAME; prefer the highest-versioned match
    candidates = sorted((r for r in pb_rows if r[1].endswith(POSTERBOARD_DB_NAME)),
                        key=lambda r: r[1], reverse=True)
    if not candidates:
        log_warn(f"No {POSTERBOARD_DB_NAME} among the PosterBoard rows; "
                 f"sample rows: {[r[1] for r in pb_rows[:5]]}")
        return None
    file_id, rel_path = candidates[0]
    structure_version = posterboard_structure_version(rel_path)

    def _payload_for(suffix: str) -> Optional[Path]:
        target = rel_path + suffix
        for fid, rp in pb_rows:
            if rp == target:
                p = device_dir / fid[:2] / fid
                return p if p.is_file() else None
        return None

    main_payload = _payload_for("")
    if main_payload is None:
        log_warn(f"extract_posterboard_db: manifest row for {rel_path} exists but its "
                 f"payload file {device_dir / file_id[:2] / file_id} is missing "
                 f"(mid-stream filter dropped it?)")
        return None

    dest = Path(dest_path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    log_debug(f"extract_posterboard_db: using {rel_path} (fileID={file_id}) -> {dest}")

    wal_payload = _payload_for("-wal")
    if wal_payload is None:
        shutil.copyfile(main_payload, dest)
        _require_usable_pb_snapshot(dest)
        return str(dest), structure_version

    # WAL consolidation via the SQLite online-backup API.
    work_dir = Path(tempfile.mkdtemp(prefix="nugget_pbwal_"))
    try:
        work_main = work_dir / "posterboard.sqlite3"
        shutil.copyfile(main_payload, work_main)
        shutil.copyfile(wal_payload, str(work_main) + "-wal")
        dest.unlink(missing_ok=True)
        try:
            src = sqlite3.connect(str(work_main))
            merged = sqlite3.connect(str(dest))
            try:
                src.backup(merged)
                merged.execute("PRAGMA journal_mode=DELETE")
                merged.commit()
            finally:
                src.close()
                merged.close()
        except Exception:
            log_warn("WAL consolidation failed — falling back to the plain database file")
        if not _validate_sqlite_db(dest):
            log_warn("Consolidated PosterBoard DB failed validation — "
                     "falling back to the plain database file")
            dest.unlink(missing_ok=True)
            shutil.copyfile(main_payload, dest)
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    _require_usable_pb_snapshot(dest)

    return str(dest), structure_version


def _keep_protective_entry(domain: str, relative_path: str, include_photos: bool = True,
                           include_keychain: bool = False,
                           exclude_afc_media_trees: bool = False,
                           include_apple_account: bool = False,
                           include_apple_identity: bool = True,
                           include_find_my_state: bool = True) -> bool:
    """Keep-set predicate shared by the plain and encrypted prune paths."""
    if _drop_apple_id(domain, relative_path, include_apple_account,
                      include_apple_identity, include_find_my_state):
        # The Apple-ID groups are dropped as a whole — including the domain
        # root rows (relative_path == "") of the Find My / adid containers,
        # which never reach _is_protective_file.
        return False
    if domain and relative_path and (_is_protective_file(domain, relative_path, include_photos, include_keychain,
                                                         exclude_afc_media_trees, include_apple_account,
                                                         include_apple_identity, include_find_my_state)
                                     or domain == "SystemPreferencesDomain"):
        return True
    if relative_path == "" and domain in ("SystemPreferencesDomain", "MessagesDomain"):
        return True
    if include_keychain and relative_path == "" and domain == KEYCHAIN_DOMAIN:
        return True
    return False


def clean_backup_for_restore(backup_dir, udid: str,
                             include_photos: bool = True,
                             include_keychain: bool = False,
                             manifest_password: str = "",
                             exclude_afc_media_trees: bool = False,
                             collect_inode: bool = False,
                             include_apple_account: bool = False,
                             include_apple_identity: bool = True,
                             include_find_my_state: bool = True) -> PruneResult:
    """Prune a backup directory down to its protective payload.

    1. Deletes every non-protective row from Manifest.db in a single DELETE.
    2. Deletes payload files not referenced by the keep-set.
    3. Removes directories left empty by the pruning.

    Encrypted backups are supported when ``manifest_password`` is given.
    Returns a ``PruneResult``.
    """
    device_dir = Path(backup_dir) / udid
    if not device_dir.is_dir():
        if (Path(backup_dir) / "Manifest.db").exists():
            device_dir = Path(backup_dir)
        else:
            return PruneResult()

    manifest_db = device_dir / "Manifest.db"
    if not manifest_db.exists():
        return PruneResult()

    if _is_encrypted_backup(device_dir):
        if not manifest_password:
            log_info("Backup is encrypted and no password was given — skipping local manifest pruning")
            return PruneResult()
        dropped_apple_id = [0]

        def _keep(bf) -> bool:
            if bf.domain is None or bf.relative_path is None:
                return False
            if _drop_apple_id(bf.domain, bf.relative_path, include_apple_account,
                              include_apple_identity, include_find_my_state):
                dropped_apple_id[0] += 1
                return False
            return _keep_protective_entry(bf.domain, bf.relative_path, include_photos, include_keychain,
                                          exclude_afc_media_trees, include_apple_account,
                                          include_apple_identity, include_find_my_state)
        allowed_ids = Mobilebackup2Service.prune_backup_manifest(
            device_dir, _keep, password=manifest_password)
        removed_files = _remove_orphan_payloads(_payload_inventory(device_dir), allowed_ids)
        log_info(f"Encrypted manifest pruned with password (-{removed_files} orphan payloads)")
        log_info(f"Encrypted manifest pruned with password (-{removed_files} orphan payloads)")
        if dropped_apple_id[0]:
            log_info(f"Prune: dropped {dropped_apple_id[0]} Apple-ID row(s) "
                     f"(include_apple_account={include_apple_account}, "
                     f"include_apple_identity={include_apple_identity}, "
                     f"include_find_my_state={include_find_my_state})")
        return PruneResult(removed_files=removed_files)

    if not _validate_sqlite_db(manifest_db):
        log_error(f"Manifest.db at {manifest_db} is not a valid SQLite database. Skipping cleanup.")
        return PruneResult()

    keep_ids = set()
    removed_rows = 0
    missing_payloads = []
    inventory = _payload_inventory(device_dir)
    present = inventory[3]
    max_inode = None
    conn = sqlite3.connect(str(manifest_db))
    try:
        cur = conn.cursor()
        cur.execute("SELECT fileID, domain, relativePath, flags FROM Files")
        dropped_apple_id = 0
        for file_id, domain, rel_path, flags in cur:
            if _drop_apple_id(domain, rel_path, include_apple_account,
                              include_apple_identity, include_find_my_state):
                dropped_apple_id += 1
                continue
            if _keep_protective_entry(domain, rel_path, include_photos, include_keychain,
                                      exclude_afc_media_trees, include_apple_account,
                                      include_apple_identity, include_find_my_state):
                if flags == 1 and file_id not in present:
                    missing_payloads.append(rel_path)
                else:
                    keep_ids.add(file_id)

        if dropped_apple_id:
            log_info(f"Prune: dropped {dropped_apple_id} Apple-ID row(s) "
                     f"(include_apple_account={include_apple_account}, "
                     f"include_apple_identity={include_apple_identity}, "
                     f"include_find_my_state={include_find_my_state})")

        if missing_payloads:
            log_warn(f"Prune: dropping {len(missing_payloads)} file rows with missing payloads "
                     f"(e.g. {missing_payloads[:5]})")

        cur.execute("CREATE TEMP TABLE nugget_keep (fileID TEXT PRIMARY KEY)")
        cur.executemany("INSERT INTO nugget_keep (fileID) VALUES (?)",
                        ((fid,) for fid in keep_ids))
        cur.execute("DELETE FROM Files WHERE fileID NOT IN (SELECT fileID FROM nugget_keep)")
        removed_rows = max(cur.rowcount, 0)
        if collect_inode:
            from .inject import _max_inode_in_manifest
            max_inode = _max_inode_in_manifest(conn)
        conn.commit()
    finally:
        conn.close()

    removed_files = _remove_orphan_payloads(inventory, keep_ids)
    return PruneResult(removed_rows, removed_files, max_inode)
