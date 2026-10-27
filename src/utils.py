"""Standalone helpers folded into one light, stdlib-only module.

Combines the GoldenNugget ``src/utils`` modules (payload copying, async
retry, thread-executor disk calls, filesystem cloning, log wrappers,
cancellation tokens, archive bounds) plus the string-translation identity and
the backup status text type, so the package has no PySide6 dependency.
"""
import asyncio
import logging
import os
import shutil
import stat
import sys
import tempfile
from contextlib import contextmanager
from contextvars import ContextVar
from hashlib import sha1
import io
from pathlib import Path, PurePosixPath
from threading import Event
from typing import Awaitable, Callable, Optional, TypeAlias

__all__ = [
    "log_info", "log_warn", "log_error", "log_debug",
    "tr",
    "OperationStatus", "BackupStatus",
    "open_payload", "copy_payload", "install_payload", "CHUNK_SIZE",
    "PayloadSource",
    "async_retry",
    "ensure_thread_executor", "disk_call",
    "clone_or_copy",
    "JobCancelled", "CancellationToken", "check_cancelled", "run_cancellable",
    "safe_member", "checked_members", "package_path", "package_matches",
    "MAX_FILES", "MAX_FILE_BYTES", "MAX_TOTAL_BYTES",
]

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

_logger = logging.getLogger("GoldenNugget")


def log_info(msg: str) -> None:
    _logger.info(msg)


def log_warn(msg: str) -> None:
    _logger.warning(msg)


def log_error(msg: str) -> None:
    _logger.error(msg)


def log_debug(msg: str) -> None:
    _logger.debug(msg)


# --------------------------------------------------------------------------
# String translation
# --------------------------------------------------------------------------

def tr(text: str) -> str:
    """Identity translation hook (no Qt in the standalone package)."""
    return text


# --------------------------------------------------------------------------
# Status text
# --------------------------------------------------------------------------

class OperationStatus(str):
    def __new__(cls, text, category):
        instance = super().__new__(cls, text)
        instance.category = category
        return instance


class BackupStatus(OperationStatus):
    pass


# --------------------------------------------------------------------------
# Payload copying and hashing
# --------------------------------------------------------------------------

PayloadSource: TypeAlias = bytes | bytearray | memoryview | str | os.PathLike[str]

CHUNK_SIZE = 1024 * 1024


@contextmanager
def open_payload(source: PayloadSource):
    if isinstance(source, (bytes, bytearray, memoryview)):
        with io.BytesIO(source) as stream:
            yield stream
        return
    with open(source, "rb") as stream:
        before = os.fstat(stream.fileno())
        yield stream
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise OSError(f"Payload changed while being read: {source}")


def copy_payload(source: PayloadSource, output=None) -> tuple[int, bytes]:
    """Return (size, SHA1), optionally copying to an already open output."""
    size, digest = 0, sha1()
    with open_payload(source) as stream:
        while chunk := stream.read(CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
            if output is not None:
                output.write(chunk)
    return size, digest.digest()


def install_payload(source: PayloadSource, destination) -> tuple[int, bytes, bool]:
    """Atomically install bytes or a path, preserving equal files and hardlinks.

    At most two bounded passes over a path are needed when replacing an existing
    file. A source that changes between comparison and copying is rejected.
    Returns (size, SHA1, changed).
    """
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    previous = None
    if destination.is_file() and not destination.is_symlink():
        digest, size, equal = sha1(), 0, True
        with open_payload(source) as stream, destination.open("rb") as existing:
            while chunk := stream.read(CHUNK_SIZE):
                digest.update(chunk)
                size += len(chunk)
                if equal and existing.read(len(chunk)) != chunk:
                    equal = False
            equal = equal and not existing.read(1)
        previous = size, digest.digest()
        if equal:
            return *previous, False
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=destination.parent, prefix=".payload-",
                                         delete=False) as output:
            temporary = output.name
            info = copy_payload(source, output)
        if previous is not None and info != previous:
            raise OSError(f"Payload changed between comparison and copy: {source}")
        os.replace(temporary, destination)
        return *info, True
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


# --------------------------------------------------------------------------
# Async retry
# --------------------------------------------------------------------------

async def async_retry(
    coro_factory: Callable[[], Awaitable],
    attempts: int,
    *,
    retry_if: Callable[[Exception], bool] = lambda exc: True,
    fixed_delay: Optional[float] = None,
    exp_cap: float = 15,
    on_retry: Optional[Callable[[int, int, Exception, float], None]] = None,
    on_failure: Optional[Callable[[Exception], None]] = None,
) -> Awaitable:
    """Run ``coro_factory()`` up to ``attempts`` times.

    On an exception matching ``retry_if`` (default: any) before the last
    attempt, wait ``fixed_delay`` or ``min(2 ** attempt, exp_cap)`` seconds,
    call ``on_retry(attempt, attempts, exc, delay)`` and try again. If the
    exception is not retryable, or all attempts are exhausted, call
    ``on_failure(exc)`` (if given) and re-raise it.

    ``attempt`` is 1-based and matches the delay formula ``2 ** attempt`` so
    callers that previously used ``min(2 ** attempt, 15)`` see identical
    behaviour.
    """
    last_error: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            return await coro_factory()
        except Exception as e:  # noqa: BLE001 — retry predicates decide
            last_error = e
            if attempt >= attempts or not retry_if(e):
                if on_failure is not None:
                    on_failure(e)
                raise
            delay = fixed_delay if fixed_delay is not None else min(2 ** attempt, exp_cap)
            if on_retry is not None:
                on_retry(attempt, attempts, e, delay)
            await asyncio.sleep(delay)
    raise last_error  # pragma: no cover — unreachable, kept for typing


# --------------------------------------------------------------------------
# Thread-executor disk calls
# --------------------------------------------------------------------------

def ensure_thread_executor():
    """Resolve the canonical executor before asyncio accesses the public export.

    Python 3.15 can leave concurrent.futures.ThreadPoolExecutor as a lazy
    import object. Importing from its defining module avoids exporting that
    proxy back into concurrent.futures. This also works before protective.py
    has ever been imported, as required by standalone recovery callers.
    """
    import concurrent.futures as futures
    if not isinstance(vars(futures).get("ThreadPoolExecutor"), type):
        from concurrent.futures.thread import ThreadPoolExecutor
        futures.ThreadPoolExecutor = ThreadPoolExecutor


async def disk_call(function, *args, **kwargs):
    ensure_thread_executor()
    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        # A thread cannot be forcibly cancelled. Its file mutation must finish
        # before rollback, snapshot regeneration or temporary-file cleanup.
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError:
                continue
            except BaseException:
                break
        if not task.cancelled():
            # The worker may have failed between cancellation and the loop's
            # first condition. Retrieve that exception even when no await ran.
            task.exception()
        raise


# --------------------------------------------------------------------------
# Filesystem cloning
# --------------------------------------------------------------------------

def clone_or_copy(source, destination):
    """Unlike hardlinks, modifying the destination never changes the source."""
    cloned = False
    if sys.platform == "darwin":
        import ctypes
        library = ctypes.CDLL(None, use_errno=True)
        clone = getattr(library, "clonefile", None)
        if clone is not None:
            clone.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int)
            clone.restype = ctypes.c_int
            cloned = clone(os.fsencode(source), os.fsencode(destination), 0) == 0
    elif sys.platform.startswith("linux"):
        import fcntl
        created = False
        try:
            with open(source, "rb") as incoming, open(destination, "xb") as outgoing:
                created = True
                fcntl.ioctl(outgoing.fileno(), 0x40049409, incoming.fileno())  # FICLONE
                cloned = True
        except OSError:
            if created:
                os.unlink(destination)
    if cloned:
        shutil.copystat(source, destination)
    else:
        shutil.copy2(source, destination)


# --------------------------------------------------------------------------
# Cancellation
# --------------------------------------------------------------------------

_token = ContextVar("local_job_cancellation", default=None)


class JobCancelled(Exception):
    pass


class CancellationToken:
    def __init__(self):
        self._cancelled = Event()

    def cancel(self):
        self._cancelled.set()

    def check(self):
        if self._cancelled.is_set():
            raise JobCancelled("Local background operation cancelled")


def check_cancelled():
    token = _token.get()
    if token is not None:
        token.check()


def run_cancellable(callback, token):
    state = _token.set(token)
    try:
        token.check()
        return callback()
    finally:
        _token.reset(state)


# --------------------------------------------------------------------------
# Archive bounds
# --------------------------------------------------------------------------

MAX_FILES = 20000
MAX_FILE_BYTES = 512 * 1024 ** 2
MAX_TOTAL_BYTES = 2 * 1024 ** 3


def safe_member(name):
    parts = name.rstrip('/').split('/')
    return (bool(name) and not name.startswith('/') and '\\' not in name
            and '\x00' not in name and ':' not in name
            and all(part not in ('', '.', '..') for part in parts)
            and not PurePosixPath(name).is_absolute())


def checked_members(archive):
    """Reject ambiguous paths, links, encryption and unreasonable expansion."""
    members = archive.infolist()
    if len(members) > MAX_FILES:
        raise ValueError('Archive contains too many entries.')
    seen, total = set(), 0
    for info in members:
        name = info.filename
        canonical = name.rstrip('/').casefold()
        if not safe_member(name) or '\x00' in info.orig_filename or canonical in seen:
            raise ValueError(f'Unsafe or duplicate archive path: {name}')
        seen.add(canonical)
        mode = info.external_attr >> 16
        if stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR)):
            raise ValueError(f'Unsupported archive entry: {name}')
        if info.flag_bits & 1:
            raise ValueError('Encrypted ZIP entries are not supported.')
        total += info.file_size
        if info.file_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
            raise ValueError('Archive exceeds the supported unpacked size.')
        if info.file_size > 16 * 1024 ** 2 and info.file_size > max(info.compress_size, 1) * 1000:
            raise ValueError(f'Excessive archive expansion: {name}')
    return members


def package_path(root, relative):
    """Resolve an untrusted package path, including wildcard patterns."""
    if not isinstance(relative, str) or not safe_member(relative):
        raise ValueError(f"Unsafe template path: {relative!r}")
    base = Path(root).resolve()
    target = base.joinpath(*relative.split('/')).resolve()
    if not target.is_relative_to(base) or target == base:
        raise ValueError(f"Template path escapes its package: {relative!r}")
    return str(target)


def package_matches(root, relative):
    """Validate the pattern and every match before the caller mutates files."""
    import glob
    pattern = package_path(root, relative)
    base = Path(root).resolve()
    matches = glob.glob(pattern, recursive=True)
    for match in matches:
        target = Path(match).resolve()
        if not target.is_relative_to(base) or target == base:
            raise ValueError(f"Template path escapes its package: {relative!r}")
    return matches
