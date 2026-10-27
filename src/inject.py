"""Manifest.db tweak injection for the iOS 27 protective restore.

The iOS 27 "safe state recovery" wipe clears HomeDomain files that were
staged by the sparse restore but are absent from the protective backup.
Files the tweak writes can be re-added here with their *new* content so
Phase 3's mobilebackup2 restore lays them down natively (AFC cannot reach
HomeDomain, so that is the only reliable path on iOS 27).

This module is a leaf: it depends only on stdlib + pymobiledevice3 and knows
nothing about the backup/restore flow in ``protective.py``.
"""

from contextlib import closing
import hashlib
import logging
import os
import plistlib
import sqlite3
import time
from pathlib import Path
from typing import Optional

from .utils import install_payload
from .mbfile import MBFileArchive, InvalidMBFile
from .exceptions import NuggetException

from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

_logger = logging.getLogger("GoldenNugget.inject")


def _is_encrypted_backup(device_dir: Path) -> bool:
    """Check if a backup directory has an encrypted Manifest.db."""
    try:
        return Mobilebackup2Service._is_encrypted_backup(device_dir)
    except Exception as exc:
        raise NuggetException(
            f"Could not determine backup encryption at {device_dir}. "
            "The backup was not modified.", detailed_text=str(exc)) from exc


def _validate_sqlite_db(db_path) -> bool:
    """Check if a file is a valid SQLite database (accepts str or Path)."""
    if isinstance(db_path, str):
        db_path = Path(db_path)
    if not db_path.exists() or db_path.stat().st_size < 100:
        return False
    try:
        with closing(sqlite3.connect(str(db_path))) as conn:
            conn.execute("SELECT 1 FROM sqlite_master LIMIT 1")
        return True
    except sqlite3.DatabaseError:
        return False


def _build_mbfile_blob(relative_path: str, contents: bytes, mode: int = 33188,
                       owner: int = 501, group: int = 501, *,
                       size=None, digest=None, inode=None, protection_class=None) -> bytes:
    """Build a ``MBFile`` archive blob for an injected backup file.

    Matches the NSKeyedArchiver structure BackupAgent2 writes to the
    ``file`` column of Manifest.db: an ``MBFile`` object carrying the file's
    metadata plus a ``Digest`` (SHA1 of the payload) and the data-protection
    extended attribute. Mode/ownership mirror a regular mobile-owned
    HomeDomain file; the extended attribute marks the file as exempt from
    data protection by SpringBoard (same as IconState.plist and friends).
    """
    now = int(time.time())
    extended_attributes = plistlib.dumps(
        {"com.apple.dataprotection.policy.exception-applied-by": b"com.apple.springboard"},
        fmt=plistlib.FMT_BINARY,
    )
    objects = [
        "$null",
        {
            "Birth": now,
            "LastModified": now,
            "LastStatusChange": now,
            "Flags": 0,
            "GroupID": group,
            "UserID": owner,
            "Mode": mode,
            "ProtectionClass": 4,
            "Size": len(contents) if size is None else size,
            "RelativePath": plistlib.UID(2),
            "Digest": plistlib.UID(3),
            "ExtendedAttributes": plistlib.UID(4),
            "$class": plistlib.UID(5),
        },
        relative_path,
        hashlib.sha1(contents).digest() if digest is None else digest,
        extended_attributes,
        {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
    ]
    if inode is not None:
        objects[1]["InodeNumber"] = inode
    if protection_class is not None:
        objects[1]["ProtectionClass"] = protection_class
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
    )


def _patch_donor_blob(donor_blob: bytes, relative_path: str, contents: bytes,
                      mode: Optional[int] = None, owner: Optional[int] = None,
                      group: Optional[int] = None, *, size=None, digest=None, inode=None, protection_class=None) -> bytes:
    """Re-target a real MBFile blob from the same backup for a new payload.

    Cloning a row the device itself produced guarantees byte-exact metadata
    (extended attributes, protection class) instead of risking a hand-built
    archive the restore agent might reject. Only the path, digest, size and
    (optionally) mode/ownership change.
    """
    template = donor_blob if isinstance(donor_blob, MBFileArchive) else MBFileArchive.decode(donor_blob)
    blob = template.clone()
    info = blob.fields
    blob.set_reference("RelativePath", relative_path)
    blob.set_reference("Digest", hashlib.sha1(contents).digest() if digest is None else digest)
    info["Size"] = len(contents) if size is None else size
    for key, value in (("Mode", mode), ("UserID", owner), ("GroupID", group),
                       ("InodeNumber", inode), ("ProtectionClass", protection_class)):
        if value is not None:
            info[key] = value
    return blob.encode()


def _pick_donor_blob(conn, domain: str, relative_path: str) -> "Optional[bytes]":
    """Pick a donor MBFile blob the restore agent will accept.

    The iOS 27 restore agent silently skips rows whose blob it considers
    invalid, and it deduplicates by inode. A safe donor is a regular (0644)
    file with a SpringBoard data-protection exception and a real inode:
    ``IconState.plist`` is the canonical such file in the protective scope.
    Falls back to any regular row carrying a digest, then to the old
    arbitrary-row behavior.
    """
    preferred = ("Library/SpringBoard/IconState.plist",)
    for candidate in preferred:
        row = conn.execute(
            "SELECT file FROM Files WHERE domain = ? AND relativePath = ? "
            "AND flags = 1 AND file IS NOT NULL",
            (domain, candidate),
        ).fetchone()
        if row is not None:
            return row[0]

    for _candidate_flags, candidate_blob in conn.execute(
        "SELECT flags, file FROM Files WHERE domain = ? AND file IS NOT NULL "
        "AND relativePath != ? AND flags = 1",
        (domain, relative_path),
    ):
        try:
            info = MBFileArchive.decode(candidate_blob).fields
            if (info.get("Mode", 0) & 0o777) == 0o644 and isinstance(
                info.get("InodeNumber"), int
            ):
                return candidate_blob
        except Exception:
            continue

    for _candidate_flags, candidate_blob in conn.execute(
        "SELECT flags, file FROM Files WHERE domain = ? AND file IS NOT NULL "
        "AND relativePath != ? AND flags = 1",
        (domain, relative_path),
    ):
        try:
            info = MBFileArchive.decode(candidate_blob).fields
            if "Digest" in info and "ExtendedAttributes" in info:
                return candidate_blob
        except Exception:
            continue
    return None


def _owned(value, default: int = 501) -> int:
    """Resolve a uid/gid for a manifest blob — ``None`` means "unspecified".

    ``owner or 501`` (the original form) silently re-owned every injected file
    whose owner was 0. That is *not* an unspecified value, it is root: the
    daemons plist (``/var/db/com.apple.xpc.launchd/disabled.plist``) and the
    rest of ``DatabaseDomain`` are root-owned in a real backup, and the device
    ignores a root path restored as mobile-owned (silently — the launchd
    disabled list simply does not take). Only a genuinely missing value may
    fall back to the mobile default.
    """
    return default if value is None else value


def _build_mbdir_blob(relative_path: str, mode: int = 16877) -> bytes:
    """Build an ``MBFile``-style archive blob for a directory row.

    Mirrors what BackupAgent2 writes for flag=2 rows (dump of the device's
    own SystemPreferencesDomain dir rows): no digest, size 0, S_IFDIR mode,
    root-owned. The device's real rows carry a real inode, so a unique one
    must be stamped by the caller.
    """
    now = int(time.time())
    objects = [
        "$null",
        {
            "Birth": now,
            "LastModified": now,
            "LastStatusChange": now,
            "Flags": 0,
            "GroupID": 0,
            "UserID": 0,
            "Mode": mode,
            "ProtectionClass": 4,
            "Size": 0,
            "RelativePath": plistlib.UID(2),
            "InodeNumber": 0,
            "$class": plistlib.UID(3),
        },
        relative_path,
        {"$classname": "MBFile", "$classes": ["MBFile", "NSObject"]},
    ]
    return plistlib.dumps(
        {
            "$version": 100000,
            "$archiver": "NSKeyedArchiver",
            "$top": {"root": plistlib.UID(1)},
            "$objects": objects,
        },
        fmt=plistlib.FMT_BINARY,
    )


def _ensure_directory_rows(conn, domain: str, relative_dir: str,
                           next_inode: int = None, known_dirs: set = None,
                           donor_blob: bytes = None,
                           owner: int = None, group: int = None) -> int:
    """Insert flags=2 directory rows for every missing path component.

    The iOS 27 restore agent skips a file whose parent directories have no
    manifest rows, so before injecting a tweak file its directory chain must
    exist in Manifest.db. Rows are cloned from a real directory blob of the
    backup (byte-exact metadata) with a unique inode; falls back to a
    hand-built blob when the backup has no directory rows at all.

    Batch-aware: when ``next_inode`` / ``known_dirs`` / ``donor_blob`` are
    supplied the directory state is reused across calls — ``known_dirs`` is a
    set of ``(domain, relativePath)`` tuples already present (so repeated
    chains skip the SELECT) and ``next_inode`` is an in-memory counter picked
    up where the previous call left it, avoiding a fresh manifest scan per
    file. Returns the current inode counter (one call passes it forward).

    ``owner``/``group`` (when not ``None``) are stamped onto every row written
    here. A donor dir blob is cloned from whatever directory row the backup
    happens to have — on a pruned protective backup that is a HomeDomain one,
    so a new root-owned domain would otherwise inherit mobile ownership on its
    own directory rows (DatabaseDomain's ``com.apple.xpc.launchd`` is
    uid 0 / mode 0755 on a real device).
    """
    if donor_blob is None:
        donor = conn.execute(
            "SELECT file FROM Files WHERE flags = 2 AND file IS NOT NULL LIMIT 1"
        ).fetchone()
        donor_blob = donor[0] if donor else None
    if next_inode is None:
        next_inode = _max_inode_in_manifest(conn)
    rel = ""
    for component in [""] + (relative_dir.split("/") if relative_dir else []):
        if component:
            rel = f"{rel}/{component}" if rel else component
        if known_dirs is not None:
            if (domain, rel) in known_dirs:
                continue
            exists = conn.execute(
                "SELECT 1 FROM Files WHERE domain = ? AND relativePath = ? AND flags = 2",
                (domain, rel),
            ).fetchone()
            if exists:
                known_dirs.add((domain, rel))
                continue
        else:
            exists = conn.execute(
                "SELECT 1 FROM Files WHERE domain = ? AND relativePath = ? AND flags = 2",
                (domain, rel),
            ).fetchone()
            if exists:
                continue
        next_inode += 1
        if donor_blob is not None:
            template = donor_blob if isinstance(donor_blob, MBFileArchive) else MBFileArchive.decode(donor_blob)
            metadata = template.clone()
            metadata.set_reference("RelativePath", rel)
        else:
            metadata = MBFileArchive.decode(_build_mbdir_blob(rel))
        info = metadata.fields
        info["InodeNumber"] = next_inode
        if domain == "SysContainerDomain-com.apple.eligibilityd":
            info["ProtectionClass"] = 0
            info["Mode"] = 0o40755
        if owner is not None:
            info["UserID"] = owner
        if group is not None:
            info["GroupID"] = group
        blob = metadata.encode()
        dir_id = hashlib.sha1(f"{domain}-{rel}".encode("utf-8")).hexdigest()
        conn.execute(
            "INSERT OR REPLACE INTO Files (fileID, domain, relativePath, flags, file) "
            "VALUES (?, ?, ?, ?, ?)",
            (dir_id, domain, rel, 2, sqlite3.Binary(blob)),
        )
        if known_dirs is not None:
            known_dirs.add((domain, rel))
    return next_inode


def _max_inode_in_manifest(conn) -> int:
    """Largest inode claimed by any regular or directory row (0 when none has one)."""
    max_inode = 0
    for (candidate_blob,) in conn.execute(
        "SELECT file FROM Files WHERE flags IN (1, 2) AND file IS NOT NULL"
    ):
        try:
            ino = MBFileArchive.decode(candidate_blob).fields.get("InodeNumber")
            if ino is not None:
                if type(ino) is not int or ino < 0:
                    raise InvalidMBFile("InodeNumber must be a nonnegative integer")
                max_inode = max(max_inode, ino)
        except InvalidMBFile as exc:
            raise NuggetException(
                "The backup contains unreadable file metadata. Injection stopped.",
                detailed_text=str(exc)) from exc
    return max_inode


def inject_files_into_backup(backup_dir, udid: str, files: list,
                             manifest_password: str = "", *, max_inode_hint=None):
    """Add many files to a pruned backup in a single Manifest.db transaction.

    The iOS 27 "safe state recovery" wipe clears HomeDomain files that were
    staged by the sparse restore but are absent from the protective backup.
    Files the tweak writes can therefore be re-added here with their *new*
    content so Phase 3's mobilebackup2 restore lays them down natively (AFC
    cannot reach HomeDomain, so that is the only reliable path on iOS 27).

    Batch mode: the Manifest.db connection is opened once, the maximum inode
    is scanned once, and everything else rides on in-memory state carried
    across the whole batch — an inode counter, per-domain donor blobs, and
    the set of known directory rows. Payloads whose bytes already match the
    file on disk are left untouched (no unlink, no rewrite). All rows are
    committed together at the end. This removes the per-file
    open-Connection / scan-max-inode / prepare-dirs / commit cycle that made
    Phase 1 quadratic for large tweak payloads.

    ``files`` is a list of ``(domain, relative_path, contents, mode, owner,
    group)`` tuples; contents may be bytes or a Path and is streamed in bounded
    buffers. ``max_inode_hint`` is accepted only from the immediately preceding
    prune of this same manifest, before any other writer can change it. The iOS 27 restore agent requires a well-formed
    regular-file blob with a real, *unique* inode (it deduplicates by inode —
    a clone sharing the donor's inode gets restored with the donor's content,
    and a fresh blob without an inode is skipped outright). The mode is
    normalized to a regular 0644-style file so the agent accepts the row;
    the uid/gid are written **verbatim** (owner 0 = root is meaningful — the
    daemons plist lives in root-owned DatabaseDomain), and the parent
    directory rows inherit the same ownership.

    The file ID follows the standard ``SHA1("<domain>-<relativePath>")``
    convention and the payload is placed in the ``<aa>/<fileID>`` layout the
    restore agent expects. Returns ``(injected, unchanged, failed)``.

    Encrypted backups are NOT supported here: their payloads are written to
    disk encrypted (each with a per-file key wrapped by the manifest keybag),
    and a locally-injected plaintext payload has no matching wrapped key — the
    Phase 3 restore agent fails to decrypt it (MBErrorDomain/205). Injection
    is skipped for encrypted backups rather than corrupting the restore.
    """
    device_dir = Path(backup_dir) / udid
    if not device_dir.is_dir():
        # Tolerate backup_dir already pointing at the device directory.
        if (Path(backup_dir) / "Manifest.db").exists():
            device_dir = Path(backup_dir)
        else:
            return 0, 0, len(files)

    manifest_db = device_dir / "Manifest.db"
    if not manifest_db.exists():
        return 0, 0, len(files)

    if _is_encrypted_backup(device_dir):
        # See the docstring: plaintext injection into an encrypted backup makes
        # the Phase 3 restore fail with MBErrorDomain/205.
        _logger.warning(f"Skipping injection into encrypted backup for {len(files)} files")
        return 0, 0, len(files)

    if not _validate_sqlite_db(manifest_db):
        _logger.error(f"Manifest.db at {manifest_db} is not a valid SQLite database. Cannot inject files.")
        return 0, 0, len(files)

    conn = sqlite3.connect(str(manifest_db))
    injected = unchanged = 0
    try:
        # Batch-level state, computed once instead of per file:
        #   next_inode   - in-memory inode counter (one manifest scan total)
        #   donor_cache  - per-domain donor blob (the device's own row format)
        #   known_dirs   - directory rows already present / inserted
        #   dir_donor    - one real directory blob reused for dir rows
        next_inode = _max_inode_in_manifest(conn) if max_inode_hint is None else max_inode_hint
        donor_cache: dict = {}
        known_dirs: set = set()
        dir_donor = conn.execute(
            "SELECT file FROM Files WHERE flags = 2 AND file IS NOT NULL LIMIT 1"
        ).fetchone()
        dir_donor = MBFileArchive.decode(dir_donor[0]) if dir_donor else None
        for domain, relative_path, contents, mode, owner, group in files:
            file_id = hashlib.sha1(f"{domain}-{relative_path}".encode("utf-8")).hexdigest()

            # The restore agent skips a file whose parent directory rows are
            # missing, so ensure the whole directory chain first.
            dir_path, _ = os.path.split(relative_path)
            next_inode = _ensure_directory_rows(
                conn, domain, dir_path, next_inode, known_dirs, dir_donor,
                owner=owner, group=group)

            # The restore agent validates the blob and deduplicates by inode:
            # pick a donor the agent accepts, then stamp a unique inode so the
            # restored file cannot be confused with the donor's own file.
            if domain not in donor_cache:
                donor_bytes = _pick_donor_blob(conn, domain, relative_path)
                donor_cache[domain] = MBFileArchive.decode(donor_bytes) if donor_bytes else None
            donor = donor_cache[domain]
            unique_inode = next_inode + 1
            next_inode += 1
            safe_mode = (mode or 33188) & 0o100777
            if safe_mode & 0o777 == 0:
                safe_mode |= 0o644
            # Ownership is carried verbatim: 0 (root) is a real uid, not a
            # missing value — see _owned().
            payload = device_dir / file_id[:2] / file_id
            size, digest, changed = install_payload(contents, payload)
            if donor is None:
                blob = _build_mbfile_blob(
                    relative_path, contents,
                    mode=safe_mode, owner=_owned(owner), group=_owned(group),
                    size=size, digest=digest, inode=unique_inode,
                    protection_class=4 if domain == "SysContainerDomain-com.apple.eligibilityd" else None)
            else:
                blob = _patch_donor_blob(
                    donor, relative_path, contents,
                    mode=safe_mode, owner=_owned(owner), group=_owned(group),
                    size=size, digest=digest, inode=unique_inode,
                    protection_class=4 if domain == "SysContainerDomain-com.apple.eligibilityd" else None)
            conn.execute(
                "INSERT OR REPLACE INTO Files (fileID, domain, relativePath, flags, file) "
                "VALUES (?, ?, ?, ?, ?)",
                (file_id, domain, relative_path, 1, sqlite3.Binary(blob)),
            )
            injected += int(changed)
            unchanged += int(not changed)
        conn.commit()
    finally:
        conn.close()

    return injected, unchanged, len(files) - injected - unchanged
