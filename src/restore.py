# PEP 810: defer operation-only dependencies on Python 3.15+; eager on older.
__lazy_modules__ = (
    "skip_setup27",
    "pymobiledevice3.services.installation_proxy",
    "pymobiledevice3.services.lockdown_service",
    "pymobiledevice3.services.mobilebackup2",
)

import asyncio
import os
import plistlib
import shutil
import ssl
import tempfile
import time
from pathlib import Path

from .utils import OperationStatus, tr, log_info, log_warn, log_error
from . import backup, perform_restore, reboot_device
from .file_to_restore import FileToRestore, _FileMode
from .lastapply import is_ios27_scaffolding, load_lastapply, sparse_signature
from .skip_setup27 import skip_all_setup27
from .afc_media import (
    afc_media_dir_for, describe_media_store,
    media_store_verified, restore_media_via_afc,
)
from .recovery import RecoverySource, RecoveryBackend, prepare_recovery  # noqa: F401
from .context import RestoreOptions, RestoreSession
from .inject import _is_encrypted_backup
from .protective import (
    PreparedBackup,
    clean_backup_for_restore,
    discard_restore_view,
    inject_files_into_backup,
    make_restore_view,
    new_protective_backup_dir,
    perform_protective_backup,
    prune_protective_backups,
    verify_backup_payloads,
    WORKING_COPY_PREFIX,
)
from .siri_ai import require_protective_delivery
from pymobiledevice3.lockdown import LockdownClient, create_using_usbmux
from pymobiledevice3.services.installation_proxy import InstallationProxyService
from pymobiledevice3.services.lockdown_service import LockdownService
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
from pymobiledevice3.exceptions import ConnectionTerminatedError, PasswordRequiredError, InvalidServiceError, CloudConfigurationAlreadyPresentError

from .exceptions import NuggetException
from .device_errors import is_transient_restore_error, is_find_my_error
from .device_errors import is_connection_error, is_device_lock_required_error, is_device_locked_error

from packaging.version import Version as _V


def concat_regular_file(file: FileToRestore, files_list: list[FileToRestore], last_domain: str, last_path: str):
    path, name = os.path.split(file.restore_path)
    paths = path.split("/")
    new_last_domain = last_domain
    if last_domain != file.domain:
        files_list.append(backup.Directory(
            "",
            file.domain,
            owner=file.owner,
            group=file.group
        ))
        last_path = ""
        new_last_domain = file.domain
    full_path = ""
    mode = file.mode
    if mode == None:
        mode = backup.DEFAULT
    for path_item in paths:
        if full_path != "":
            full_path += "/"
        full_path += path_item
        if full_path == "":
            continue
        if last_path != full_path and not last_path.startswith(full_path + "/"):
            files_list.append(backup.Directory(
                full_path,
                file.domain,
                owner=file.owner,
                group=file.group,
                mode=mode
            ))
            last_path = full_path
    files_list.append(backup.ConcreteFile(
        f"{full_path}/{name}" if full_path else name,
        file.domain,
        owner=file.owner,
        group=file.group,
        contents=file.contents,
        src_path=file.contents_path,
        mode=mode
    ))
    return new_last_domain, full_path


# merge all files that have duplicates and returns the list without duplicates
def merge_duplicates(original_files: list[FileToRestore]) -> list[FileToRestore]:
    no_dupe_files: list[FileToRestore] = []
    existing_locations: dict[str, int] = {}
    for file in original_files:
        file_loc = "-" if file.domain is None else file.domain + '-'
        restore_path = file.restore_path
        if file.restore_path.startswith('/'):
            restore_path = restore_path.removeprefix('/')
        file_loc += restore_path
        if file_loc in existing_locations:
            if not restore_path.endswith('.plist'):
                print(f'cannot merge duplicate file, ignoring {file_loc}')
                continue
            print(f'merging duplicate files for {file_loc}')
            initial_data = plistlib.loads(no_dupe_files[existing_locations[file_loc]].contents)
            added_data = plistlib.loads(file.contents)
            initial_data.update(added_data)
            no_dupe_files[existing_locations[file_loc]].contents = plistlib.dumps(initial_data)
        else:
            no_dupe_files.append(file)
            existing_locations[file_loc] = len(no_dupe_files) - 1
    return no_dupe_files


# How long to wait for the device to come back after the iOS 27 security
# recovery before giving up.
_RECONNECT_TIMEOUT = 20 * 60


async def _wait_for_device(udid: str, progress_callback,
                           timeout: float = _RECONNECT_TIMEOUT,
                           prompt_choice=None) -> LockdownClient:
    """Wait for the device to return after the iOS 27 security recovery.

    Polls usbmux with capped exponential backoff. Fully async. The caller can
    pass ``prompt_choice(title, text) -> "abort" | "resume"`` so a timeout shows
    an Abort/Resume prompt and "resume" restarts a fresh waiting cycle instead
    of killing the restore.
    """
    from pymobiledevice3.exceptions import (
        DeviceNotFoundError, PasswordRequiredError, NotPairedError,
        ConnectionFailedError, ConnectionTerminatedError, LockdownError,
        MissingValueError, PairingError, FatalPairingError,
        MuxException,
    )
    while True:
        start = time.monotonic()
        deadline = start + timeout
        delay = 1.0
        last_error = None
        autopair_tried = False
        saw_password_required = False
        while True:
            elapsed = int(time.monotonic() - start)
            if isinstance(last_error, PasswordRequiredError):
                progress_callback(OperationStatus(
                    "Your iPhone is locked. Unlock it and enter its passcode to continue.",
                    "authentication"))
            else:
                progress_callback(
                    f"Waiting for device after reboot "
                    f"({elapsed // 60}:{elapsed % 60:02d} elapsed)...")
            try:
                ld = await create_using_usbmux(serial=udid, autopair=False)
                if not getattr(ld, "paired", False):
                    try:
                        await ld.close()
                    except Exception:
                        pass
                    raise NotPairedError()
                return ld
            except NotPairedError as e:
                last_error = e
                if not autopair_tried and time.monotonic() - start >= 30:
                    autopair_tried = True
                    try:
                        ld = await create_using_usbmux(serial=udid, autopair=True)
                        if getattr(ld, "paired", False):
                            return ld
                        try:
                            await ld.close()
                        except Exception:
                            pass
                        last_error = NotPairedError(
                            "re-pair completed but lockdownd still reports "
                            "the host as unpaired")
                    except (MissingValueError, LockdownError,
                            PairingError, FatalPairingError,
                            DeviceNotFoundError, ConnectionFailedError,
                            ConnectionTerminatedError, MuxException,
                            ConnectionError, OSError, asyncio.TimeoutError) as e2:
                        last_error = e2
            except (DeviceNotFoundError, PasswordRequiredError,
                    ConnectionFailedError, ConnectionTerminatedError,
                    MuxException,
                    ConnectionError, OSError, asyncio.TimeoutError,
                    LockdownError) as e:
                last_error = e
                if isinstance(e, PasswordRequiredError):
                    saw_password_required = True
                    progress_callback(OperationStatus(
                        "Your iPhone is locked. Unlock it and enter its passcode to continue.",
                        "authentication"))
            if time.monotonic() + delay > deadline:
                break
            await asyncio.sleep(delay)
            delay = min(delay * 1.5, 30.0)
        err = DeviceNotFoundError(
            f"Device {udid} not reachable after reboot "
            f"({int(timeout // 60)} min timeout). Unlock the device and make "
            f"sure it is connected via USB. Last error: {last_error}"
        )
        if prompt_choice is None:
            raise err
        title = tr("Device took too long to unlock")
        if saw_password_required:
            text = tr(
                "The device has not been unlocked for too long after the "
                "security recovery \u2014 it keeps asking for your passcode.\n\n"
                "Unlock it, enter the passcode and tap \"Trust\" if prompted, "
                "then choose:\n\n"
                "  \u2022 Resume \u2014 keep waiting (restarts the \"Waiting for "
                "device to reconnect after security recovery\" cycle).\n"
                "  \u2022 Abort \u2014 stop now. Tweaks may not be applied and "
                "data protection stays incomplete.")
        else:
            text = tr(
                "The device has not been unlocked for too long after the "
                "security recovery.\n\n"
                "Unlock it, enter the passcode, tap \"Trust\" if the computer "
                "trust prompt appears, and make sure it stays connected via "
                "USB, then choose:\n\n"
                "  \u2022 Resume \u2014 keep waiting (restarts the \"Waiting for "
                "device to reconnect after security recovery\" cycle).\n"
                "  \u2022 Abort \u2014 stop now. Tweaks may not be applied and "
                "data protection stays incomplete.")
        log_info("Reconnect wait timed out; asking the user whether to resume or abort")
        try:
            decision = prompt_choice(title, text)
        except Exception as e:
            log_warn(f"Reconnect prompt failed ({e}) — aborting")
            raise err
        if decision != "resume":
            raise err
        log_info("User chose to resume — restarting the reconnect wait cycle")


class _Mobilebackup2NoEscrow(Mobilebackup2Service):
    """mobilebackup2 started WITHOUT the escrow bag.

    After the iOS 27 safe-state wipe, _wait_for_device() re-pairs the device.
    The fresh pair record carries no EscrowBag, so the stock
    Mobilebackup2Service — which hardcodes include_escrow_bag=True — dies with
    KeyError: 'EscrowBag'.
    """

    def __init__(self, lockdown: LockdownClient) -> None:
        LockdownService.__init__(self, lockdown, self.SERVICE_NAME,
                                 include_escrow_bag=False)


def _start_mobilebackup2(lc: LockdownClient) -> Mobilebackup2Service:
    """Pick the mobilebackup2 variant matching the pair record's escrow state."""
    pair_record = getattr(lc, "pair_record", None)
    if pair_record is not None and "EscrowBag" not in pair_record:
        log_warn("Pair record has no EscrowBag (fresh re-pair after the "
                 "wipe) — starting mobilebackup2 without it")
        return _Mobilebackup2NoEscrow(lc)
    return Mobilebackup2Service(lc)


async def _restore_protective_backup(lc: LockdownClient, backup_root: str,
                                     udid: str, reboot: bool,
                                     progress_callback, backup_password: str = "",
                                     skip_apps: bool = True) -> None:
    """Phase 3: restore the pruned protective backup.

    Retries while SpringBoard / mobilebackup2 are still coming up after the
    security recovery (they can take minutes on iOS 27).
    """
    from .utils import async_retry

    max_retries = 18

    from .find_my_wait import current_find_my_wait, ApplyCancelledError
    wait_control = current_find_my_wait.get()
    restore_started = False

    async def _perform_restore(client):
        nonlocal restore_started
        restore_started = False

        def report_progress(value):
            nonlocal restore_started
            if isinstance(value, (int, float)) and value > 0:
                restore_started = True
                if wait_control is not None:
                    wait_control.finish()
            progress_callback(value)
        async with _start_mobilebackup2(client) as mb:
            await mb.restore(
                backup_root,
                system=True, copy=True, remove=False,
                reboot=reboot, source=udid,
                skip_apps=skip_apps,
                progress_callback=report_progress,
                password=backup_password,
            )
        if wait_control is not None:
            wait_control.finish()

    async def _restore_once():
        blocked_by_find_my = False
        while True:
            try:
                if blocked_by_find_my:
                    from .session import lockdown_session
                    async with lockdown_session(udid, autopair=False, connection_type="USB") as fresh:
                        await _perform_restore(fresh)
                else:
                    await _perform_restore(lc)
                return
            except ApplyCancelledError:
                raise
            except Exception as error:
                if wait_control is None:
                    raise
                if is_find_my_error(error):
                    blocked_by_find_my = True
                    progress_callback(tr(
                        "Waiting for Find My to be turned off. Keep the device connected and unlocked. "
                        "Restoration will retry automatically."))
                elif (blocked_by_find_my and not restore_started
                      and (is_transient_restore_error(error) or is_connection_error(error)
                           or is_device_lock_required_error(error) or is_device_locked_error(error))):
                    progress_callback(tr(
                        "Waiting for the device while Find My is checked. Keep it connected and unlocked."))
                else:
                    wait_control.finish()
                    raise
                await wait_control.wait_for_retry()

    def _on_retry(attempt: int, total: int, e: Exception, delay: float) -> None:
        progress_callback(
            f"Device not ready, retrying ({attempt}/{max_retries})..."
        )

    def _on_failure(e: Exception) -> None:
        if isinstance(e, ApplyCancelledError):
            raise e
        if is_find_my_error(e):
            raise NuggetException(
                tr("Find My must be disabled in order to use this tool."),
                detailed_text=tr(
                    "The device's restore service reported a Find My protection error. "
                    "Turn off Find My iPhone in Settings → [your name] → Find My, "
                    "then retry the restore. Your protective backup remains on this computer.")) from e
        if not is_transient_restore_error(e):
            try:
                missing = verify_backup_payloads(backup_root, udid, backup_password)
                if missing:
                    log_error(f"MBErrorDomain/205 context: {len(missing)} manifest rows "
                              f"lack payloads (e.g. {missing[:5]})")
            except Exception:
                pass
        if isinstance(e, InvalidServiceError):
            raise NuggetException(
                "The iPhone would not start the restore service "
                "(mobilebackup2) even after several minutes of retries.",
                detailed_text=(
                    "The backup/restore service was unavailable. This does not establish "
                    "whether Developer Mode is enabled. The device may still be booting or locked. "
                    "Unlock the iPhone, keep the screen on, wait for "
                    "it to reach the home screen, then apply again. "
                    "Your data was not lost - the protective backup is "
                    "kept on this computer and will be restored on the "
                    "next run."
                ),
            )
        if isinstance(e, (PasswordRequiredError, NuggetException)):
            raise e
        raise NuggetException(
            tr("The protective backup could not be restored to the iPhone."),
            detailed_text=tr(
                "The device dropped the connection during the data restore.\n\n"
                "Your data is not lost — the protective backup taken before "
                "the wipe is kept on this computer.\n\n"
                "This connection error can have several causes. Keep the iPhone "
                "unlocked with the screen on and connected by USB. If the device "
                "reported a Find My protection error, turn Find My off before retrying.\n\n"
                "Do not erase the phone or set it up as new — the protective "
                "backup on this computer is the only copy of your data.")
        ) from e

    await async_retry(
        _restore_once,
        max_retries,
        retry_if=is_transient_restore_error,
        fixed_delay=3,
        on_retry=_on_retry,
        on_failure=_on_failure,
    )


async def _deliver_sparse_phase(back, lockdown_client, udid, progress_callback, options):
    """Deliver sparse files, returning a zero-progress failure for final reporting."""
    merge_phases = options.merge_phases
    stage_callback = options.stage_callback
    sparse_failure = None
    if len(back.files) == 0:
        log_info("Phase 2: nothing to sparse-restore — skipping the partial "
                 "restore; tweaks are delivered by the protective "
                 "restore (Phase 3)")
        progress_callback(100)
    else:
        if stage_callback:
            stage_callback("tweaks", "")
        progress_callback(0)
        log_info(f"Phase 2: Applying tweaks via sparse restore ({len(back.files)} files)")
        sparse_progress = {"last": None, "calls": 0}

        def _tracking_callback(value):
            sparse_progress["calls"] += 1
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                sparse_progress["last"] = value
            progress_callback(value)

        max_sparse_attempts = 2
        for sparse_attempt in range(max_sparse_attempts):
            sparse_progress["last"] = None
            sparse_progress["calls"] = 0
            try:
                await perform_restore(
                    backup=back, reboot=not merge_phases,
                    lockdown_client=lockdown_client if sparse_attempt == 0 else None,
                    progress_callback=_tracking_callback, udid=udid)
                log_info(f"Phase 2: sparse restore completed cleanly "
                         f"({sparse_progress['calls']} progress events)")
                break
            except (ConnectionTerminatedError, ssl.SSLEOFError,
                    ConnectionAbortedError, ConnectionResetError) as e:
                no_progress = sparse_progress["last"] is None or sparse_progress["last"] <= 0
                if no_progress and sparse_attempt + 1 < max_sparse_attempts:
                    log_warn("Phase 2: connection dropped at 0% right after the cache "
                             "session — cooling down 25s and retrying once on a "
                             "fresh connection")
                    await asyncio.sleep(25)
                    continue
                if no_progress:
                    sparse_failure = e
                    log_error("Phase 2: connection dropped with ZERO restore progress "
                              "on every attempt — the sparse restore was likely "
                              "REJECTED. Security state recovery will not trigger; "
                              "tweaks are NOT applied.")
                else:
                    log_info(f"Phase 2: Device rebooted during sparse restore "
                             f"(expected; last progress {sparse_progress['last']:.1f}%)")
                break
        progress_callback(100)

    return sparse_failure


async def _restore_ios27(back: backup.Backup, reboot: bool,
                         lockdown_client: LockdownClient, progress_callback,
                         backup_password: str = "",
                         prepared_backup_root: PreparedBackup = None,
                         inject_files: list = None,
                         skip_setup: bool = True,
                         skip_protective_backup: bool = False,
                         include_keychain: bool = False,
                         prompt_choice=None,
                         afc_media: bool = False,
                         merge_phases: bool = True,
                         supervised: bool = False,
                         organization_name: str = "", stage_callback=None):
    """iOS 27+ restore: backup → tweak → wipe → restore → skip setup → reboot.

    Six phases: Phase 1 selective protective backup (0-40%), Phase 2 sparse
    restore (40-60%), Phase 3 protective restore (60-90%), Phase 4 pre-skip
    reboot (90-95%), Phase 5 reconnect + media push + skip setup (95-98%),
    Phase 6 final reboot (98-100%).
    """
    print("in 27")
    options = RestoreOptions(
        backup_password=backup_password, reboot=reboot, skip_setup=skip_setup,
        skip_protective_backup=skip_protective_backup,
        include_keychain=include_keychain, merge_phases=merge_phases,
        supervised=supervised, organization_name=organization_name,
        prompt_choice=prompt_choice, stage_callback=stage_callback)
    udid = lockdown_client.udid
    started = time.monotonic()
    phase_started = started

    def mark_phase(name: str) -> None:
        nonlocal phase_started
        now = time.monotonic()
        log_info(f"Phase timing — {name}: {now - phase_started:.1f}s "
                 f"({now - started:.1f}s into the apply)")
        phase_started = now

    using_cache = prepared_backup_root is not None
    media_dir = ""
    if prepared_backup_root is not None and getattr(prepared_backup_root, "media_src", ""):
        media_dir = prepared_backup_root.media_src
    manifest_password = ((prepared_backup_root.manifest_password if using_cache else "")
                         or backup_password)
    protective_dir = None
    view_dir = None
    use_master_view = using_cache and prepared_backup_root.master
    if use_master_view:
        view_dir = await asyncio.to_thread(
            make_restore_view, prepared_backup_root.root, udid,
            prepared_backup_root.view_root)
        backup_root = view_dir
    elif using_cache:
        backup_root = prepared_backup_root.root
        protective_dir = os.path.dirname(backup_root)
    else:
        backup_root = new_protective_backup_dir(udid)
        protective_dir = os.path.dirname(backup_root)
        if afc_media and not skip_protective_backup:
            media_dir = afc_media_dir_for(backup_root)
            log_info(f"AFC media for this run will be pulled into: {media_dir}")
    backup_complete = False
    sparse_failure = None
    try:
        log_info(f"Starting iOS 27 restore for device {udid}")
        log_info(f"Protective backup directory: {protective_dir or backup_root}")

        import glob as _glob
        from .protective import protective_persistent_base
        _persistent_base = str(protective_persistent_base())
        for stale in sorted(_glob.glob(os.path.join(
                tempfile.gettempdir(), WORKING_COPY_PREFIX + "*"))):
            try:
                if stale == protective_dir:
                    continue
                if os.path.abspath(stale).startswith(_persistent_base):
                    log_error(f"Refusing to sweep {stale}: inside the persistent "
                              f"protective backup store")
                    continue
                age_h = (time.time() - os.path.getctime(stale)) / 3600
                if age_h > 1:
                    shutil.rmtree(stale, ignore_errors=True)
                    log_info(f"Cleaned stale working copy: {stale} ({age_h:.0f}h old)")
            except OSError:
                pass

        # === Phase 1: selective protective backup (0-40%) ===
        if stage_callback:
            stage_callback("backup", "")
        progress_callback(0)
        if using_cache:
            log_info("Phase 1: Using prepared protective backup "
                     "(cached master snapshotted + modified in place, "
                     "or the fresh Phase-0 live backup pruned in place)")
        elif skip_protective_backup:
            log_warn("Phase 1: protective backup SKIPPED at the user's request "
                     "(no data protection for this apply)")
        else:
            log_info("Phase 1: Starting protective backup (photos, Apple ID, settings, home screen)")
            await perform_protective_backup(
                lockdown_client, backup_root,
                progress_callback=progress_callback,
                include_photos=True,
                include_keychain=include_keychain,
                include_afc_media=bool(media_dir),
            )
            prune_protective_backups(udid)
        backup_complete = not skip_protective_backup

        removed_rows, removed_files = 0, 0
        if backup_complete:
            removed_rows, removed_files = await asyncio.to_thread(
                clean_backup_for_restore, backup_root, udid,
                include_keychain=include_keychain,
                manifest_password=manifest_password,
                exclude_afc_media_trees=media_store_verified(media_dir)
            )
        log_info(f"Phase 1: Pruned backup: -{removed_rows} manifest rows, -{removed_files} payload files "
                 f"({time.monotonic() - started:.1f}s into the run)")
        mark_phase("1 prune + prepare")

        if backup_complete:
            batch = []
            for f in (inject_files or []):
                rel = f.restore_path.lstrip("/")
                data = f.contents
                if data is None and f.contents_path:
                    with open(f.contents_path, "rb") as fh:
                        data = fh.read()
                if isinstance(data, str):
                    data = data.encode("utf-8")
                batch.append((f.domain, rel, data,
                              _FileMode.S_IFREG | 0o644, f.owner, f.group))
            if batch:
                injected, unchanged, failed = await asyncio.to_thread(
                    inject_files_into_backup, backup_root, udid, batch,
                    manifest_password)
                log_info(f"Tweak files delivered via protective restore: "
                         f"{injected} ok, {unchanged} unchanged, {failed} failed")
                if failed:
                    raise NuggetException(
                        f"Could not prepare {failed} tweak file(s) for restore. "
                        "The device has not been modified.")

            missing_payloads = await asyncio.to_thread(
                verify_backup_payloads, backup_root, udid, manifest_password)
            if missing_payloads:
                raise NuggetException(
                    f"{len(missing_payloads)} manifest rows lack payloads "
                    f"(e.g. {missing_payloads[:5]}). Restore stopped before modifying the device.")
            mark_phase("1 inject tweaks")

        progress_callback(100)

        sparse_failure = await _deliver_sparse_phase(
            back, lockdown_client, udid, progress_callback, options)
        if stage_callback:
            stage_callback("restore", "media_pending" if media_dir else "")
        progress_callback(0)
        # === Phase 3: reconnect + restore protective backup (60-90%) ===
        merge_fallback_done = False
        mark_phase("2 sparse restore")
        if merge_phases:
            log_info("Phase 3: merged mode — device never rebooted, restoring "
                     "protective backup on the live session (no security "
                     "recovery, no data wipe)")
            lc = lockdown_client
            await asyncio.sleep(1)
        else:
            log_info("Phase 3: Waiting for device to reconnect after security recovery")
            lc = await _wait_for_device(udid, progress_callback,
                                        prompt_choice=prompt_choice)
        session = RestoreSession(client=lockdown_client)
        try:
            await asyncio.sleep(1)
            if skip_protective_backup or not backup_complete:
                log_warn("Phase 3: skipping protective restore (user opted out "
                         "of data protection)")
            else:
                while True:
                    try:
                        await _restore_protective_backup(
                            lc, backup_root, udid, False,
                            progress_callback,
                            backup_password=backup_password,
                            skip_apps=not any(
                                getattr(f, "domain", "").startswith("AppDomain")
                                for f in (inject_files or [])))
                        break
                    except PasswordRequiredError:
                        if prompt_choice is None:
                            raise
                        log_info("Phase 3: protective restore blocked — device "
                                 "locked (bootloop signature); asking user to "
                                 "resume or abort")
                        title = tr("Device locked — cannot restore backup")
                        text = tr(
                            "The phone is asking for a passcode to start the "
                            "restore service. This usually means the applied "
                            "tweaks are preventing it from booting properly.\n\n"
                            "  \u2022 Resume \u2014 unlock the device, then keep "
                            "trying to restore the backup.\n"
                            "  \u2022 Abort \u2014 stop now. The protective backup "
                            "is kept on this computer for a later restore.")
                        try:
                            decision = prompt_choice(title, text)
                        except Exception:
                            raise
                        if decision != "resume":
                            raise
                        log_info("Phase 3: user chose resume — reconnecting and retrying")
                        try:
                            await lc.close()
                        except Exception:
                            pass
                        lc = await _wait_for_device(udid, progress_callback,
                                                    prompt_choice=prompt_choice)
                    except NuggetException as e:
                        cause = e.__cause__ or e.__context__ or e
                        if not is_connection_error(cause):
                            raise
                        if not merge_phases or merge_fallback_done:
                            raise
                        log_warn(f"Phase 3: merged-mode session dropped "
                                 f"({type(cause).__name__}: {cause}) — falling "
                                 "back to the classic reconnect path")
                        try:
                            await lc.close()
                        except Exception:
                            pass
                        lc = await _wait_for_device(udid, progress_callback,
                                                    prompt_choice=prompt_choice)
                        merge_fallback_done = True
                    except (ConnectionTerminatedError, ConnectionError,
                            OSError, asyncio.TimeoutError) as e:
                        if not merge_phases or merge_fallback_done:
                            raise
                        log_warn(f"Phase 3: merged-mode session dropped "
                                 f"({type(e).__name__}: {e}) — falling back to "
                                 "the classic reconnect path")
                        try:
                            await lc.close()
                        except Exception:
                            pass
                        lc = await _wait_for_device(udid, progress_callback,
                                                    prompt_choice=prompt_choice)
                        merge_fallback_done = True
                log_info("Phase 3: Protective backup restored successfully")
                mark_phase("3 protective restore")
                session.client = lc

                # === Phase 4: reboot before the media restore + setup skip (90-95%) ===
                if stage_callback:
                    stage_callback("restore", "restart" if reboot and skip_setup else "waiting")
                pre_skip_reboot = reboot and skip_setup
                if pre_skip_reboot:
                    progress_callback("Rebooting device...")
                    log_info("Phase 4: Rebooting device before skipping setup")
                    await reboot_device(reboot=True, lockdown_client=lc)
                    log_info("Phase 4: Reboot command sent")

                # === Phase 5: reconnect (if rebooted) + push media + skip setup (95-98%) ===
                if pre_skip_reboot:
                    try:
                        await lc.close()
                    except Exception:
                        pass
                    lc = await _wait_for_device(udid, progress_callback,
                                                prompt_choice=prompt_choice)
                    session.client = lc

                if media_dir:
                    if not os.path.isdir(media_dir) or not os.listdir(media_dir):
                        raise NuggetException(
                            f"AFC media store is missing or empty ({media_dir}) — "
                            f"the photos were not backed up before the wipe. "
                            f"Aborting instead of pretending the restore finished.")
                    if stage_callback:
                        stage_callback("media", "photos")
                    progress_callback(0)
                    log_info(f"Phase 5: Pushing photos/videos back over AFC "
                             f"({describe_media_store(media_dir)})")
                    pushed = await restore_media_via_afc(
                        lc, media_dir,
                        progress_callback=progress_callback,
                        prompt_choice=prompt_choice,
                        unlock_prompt=(
                            tr("Device stayed locked"),
                            tr(
                                "The device has not been unlocked long enough to "
                                "push your photos and videos back after the "
                                "reboot.\n\n"
                                "Unlock it, enter your passcode, and keep it "
                                "connected via USB, then choose:\n\n"
                                "  \u2022 Resume \u2014 keep waiting for the device "
                                "to be unlocked and push your photos.\n"
                                "  \u2022 Abort \u2014 stop now. Your photos are "
                                "still safe in the backup cache on this computer, "
                                "but they will not be on the device yet.")
                        ))
                    if pushed.get("failed"):
                        raise NuggetException(
                            f"AFC media restore failed for {len(pushed['failed'])} "
                            f"file(s) (e.g. {pushed['failed'][:3]}) — the photos on "
                            f"the device are incomplete")
                    log_info(f"Phase 5: Media restored over AFC "
                             f"({pushed.get('files', 0)} pushed, "
                             f"{pushed.get('skipped', 0)} already on the device)")
                    mark_phase("5 media push")

                if skip_setup:
                    if stage_callback:
                        stage_callback("setup", "settings")
                    progress_callback("Skipping setup panes...")
                    log_info("Phase 5: Skipping setup panes via MobileConfigService")
                    try:
                        await skip_all_setup27(lc, udid, supervised=supervised,
                                               organization_name=organization_name,
                                               progress_callback=progress_callback)
                    except CloudConfigurationAlreadyPresentError:
                        log_info("Phase 5: device already has a cloud configuration "
                                 "— setup already handled, nothing to skip")
                    else:
                        log_info("Phase 5: Setup panes skipped successfully")
                    progress_callback(98)

                # === Phase 6: final reboot so the skipped setup takes effect (98-100%) ===
                if reboot:
                    if stage_callback:
                        stage_callback("setup", "restart")
                    progress_callback("Rebooting device...")
                    log_info("Phase 6: Rebooting device")
                    await reboot_device(reboot=True, lockdown_client=lc)
                    log_info("Phase 6: Reboot command sent")
                progress_callback(100)
                session.client = lc
        finally:
            try:
                await session.client.close()
            except Exception:
                pass
        if sparse_failure is not None:
            raise NuggetException(
                "The protective data restore completed, but the device rejected "
                "the tweak transfer without progress. Tweaks were not applied.") from sparse_failure
    except BaseException as e:
        if backup_complete:
            kept = backup_root if not using_cache else prepared_backup_root.root
            log_error(f"Restore failed; protective backup kept at: {kept}")
            try:
                e.add_note(f"Protective backup kept at: {kept}")
            except AttributeError:
                pass
            raise
        log_error(f"Restore failed before backup completed: {e}")
        if protective_dir:
            shutil.rmtree(protective_dir, ignore_errors=True)
        raise
    finally:
        if view_dir:
            try:
                await asyncio.to_thread(
                    discard_restore_view, view_dir, udid)
            except Exception as view_err:
                log_warn(f"Could not remove the cache restore view: {view_err}")

    if skip_protective_backup:
        if protective_dir:
            shutil.rmtree(protective_dir, ignore_errors=True)
    else:
        kept_at = protective_dir or (prepared_backup_root.root
                                     if prepared_backup_root else backup_root)
        log_info(f"Protective backup kept at: {kept_at}")
    log_info(f"iOS 27 restore completed successfully in {time.monotonic() - started:.1f}s")
    progress_callback(100)


def _is_ios27_scaffolding(file) -> bool:
    """True for the incidental iOS 27 scaffolding files."""
    path = getattr(file, "path", None)
    if path is None:
        path = getattr(file, "restore_path", "")
    return is_ios27_scaffolding(file.domain, path.lstrip("/"))


# files is a list of FileToRestore objects
async def restore_files(files: list[FileToRestore], reboot: bool = False, lockdown_client: LockdownClient = None, progress_callback=lambda x: None, backup_password: str = "", prepared_backup_root: PreparedBackup = None, skip_setup: bool = True, skip_protective_backup: bool = False, include_keychain: bool = False, prompt_choice=None, afc_media: bool = False, merge_phases: bool = True, supervised: bool = False, organization_name: str = "", stage_callback=None):
    files_list = []
    apps_list = []
    active_bundle_ids = []
    apps = None
    sorted_files = sorted(merge_duplicates(files), key=lambda x: (x.domain or "", x.restore_path or ""), reverse=False)
    last_domain = ""
    last_path = ""
    exploit_only = True
    pb_via_protective = (prepared_backup_root is not None
                         and not skip_protective_backup
                         and os.environ.get("GOLDENNUGGET_NO_PROTECTIVE_BACKUP") != "1"
                         and os.environ.get("GOLDENNUGGET_PB_SPARSE") != "1")
    inject_all = False
    if pb_via_protective:
        udid = getattr(lockdown_client, "udid", "")
        dev_dir = Path(prepared_backup_root.root) / udid
        if not dev_dir.is_dir() and (Path(prepared_backup_root.root) / "Manifest.db").exists():
            dev_dir = Path(prepared_backup_root.root)
        inject_all = not _is_encrypted_backup(dev_dir)
        if not inject_all:
            log_warn("Prepared backup is encrypted — injecting tweaks is "
                     "impossible (MBErrorDomain/205); falling back to sparse "
                     "restore delivery")
    require_protective_delivery(sorted_files, inject_all)
    inject_files = []
    for file in sorted_files:
        if file.domain == "" or file.domain == "z":
            continue
        else:
            if pb_via_protective and inject_all:
                inject_files.append(file)
                continue
            last_domain, last_path = concat_regular_file(file, files_list, last_domain, last_path)
            exploit_only = False
            if last_domain.startswith("AppDomain"):
                bundle_id = last_domain.removeprefix("AppDomain-")
                if bundle_id in active_bundle_ids:
                    continue
                if apps is None:
                    from .utils import async_retry

                    async def _get_apps():
                        async with InstallationProxyService(lockdown=lockdown_client) as ips:
                            return await ips.get_apps(application_type="Any", calculate_sizes=False)

                    try:
                        apps = await async_retry(
                            _get_apps, 3,
                            exp_cap=8,
                            on_retry=lambda attempt, total, e, delay: log_warn(
                                f"InstallationProxy query failed (attempt {attempt}/3): {e}"
                            ),
                        )
                    except Exception as e:
                        raise NuggetException(
                            "Could not query installed apps from the device "
                            f"(needed to register {bundle_id} for the restore). "
                            f"Last error: {e}") from e
                try:
                    app_info = apps[bundle_id]
                except KeyError:
                    log_warn(f"AppDomain bundle '{bundle_id}' not found in installation proxy; "
                             "the device may reject this restore")
                    active_bundle_ids.append(bundle_id)
                else:
                    active_bundle_ids.append(bundle_id)
                    apps_list.append(backup.AppBundle(
                        identifier=bundle_id,
                        path=app_info.get("Path") or app_info["Container"],
                        version=str(app_info.get("CFBundleVersion", "1.0")),
                        container_content_class="Data/Application"
                    ))
                    log_info(f"Registered AppDomain bundle for restore: {bundle_id} "
                             f"({apps_list[-1].path})")

    skip_sparse = False
    if inject_files:
        if not any(
                isinstance(f, backup.ConcreteFile) and not _is_ios27_scaffolding(f)
                for f in files_list):
            skip_sparse = True
        else:
            udid = getattr(lockdown_client, "udid", None)
            if udid:
                prev = load_lastapply(udid)
                if prev and prev == sparse_signature(files):
                    skip_sparse = True
    if skip_sparse:
        log_info("Phase 2 sparse/partial pass skipped: no new tweak payload "
                 "rides the sparse restore on this apply — the protective "
                 "restore (Phase 3) delivers the tweak/wallpaper files "
                 "directly")
        files_list = []

    values = getattr(lockdown_client, "all_values", {}) or {}
    device_manifest = {k: values[k] for k in (
        "ProductVersion", "ProductType", "DeviceClass", "BuildVersion",
        "UniqueDeviceID", "SerialNumber", "DeviceName") if k in values}

    device_ver = _V(lockdown_client.product_version)
    manifest_ios27 = device_ver >= _V("27.0")
    back = backup.Backup(files=files_list, apps=apps_list,
                         device_manifest=device_manifest,
                         manifest_ios27=manifest_ios27)

    if merge_phases and os.environ.get("GOLDENNUGGET_NO_MERGE_PHASES") == "1":
        merge_phases = False
        log_warn("GOLDENNUGGET_NO_MERGE_PHASES=1 — restoring the classic "
                 "reboot-then-wipe flow (sparse restore reboots the device "
                 "and iOS fully wipes before the protective restore)")

    if os.environ.get("GOLDENNUGGET_NO_PROTECTIVE_BACKUP") == "1":
        skip_protective_backup = True
        log_warn("GOLDENNUGGET_NO_PROTECTIVE_BACKUP=1 — forcing iOS 26-style "
                 "single-pass sparse restore (no protective backups, no "
                 "security-recovery wipe)")

    if device_ver >= _V("27.0"):
        if skip_protective_backup:
            if stage_callback:
                stage_callback("backup", "skipped")
                stage_callback("restore", "skipped")
                stage_callback("media", "skipped")
                stage_callback("tweaks", "")
            try:
                await perform_restore(backup=back, reboot=reboot,
                                      lockdown_client=lockdown_client,
                                      progress_callback=progress_callback)
            except (ConnectionTerminatedError, ssl.SSLEOFError,
                    ConnectionAbortedError, ConnectionResetError):
                log_info("Device disconnected during restore — expected on reboot")
            if reboot and skip_setup:
                if stage_callback:
                    stage_callback("setup", "waiting")
                lc = await _wait_for_device(lockdown_client.udid,
                                            progress_callback,
                                            prompt_choice=prompt_choice)
                log_info("Raw sparse: skipping setup panes via MobileConfigService")
                if stage_callback:
                    stage_callback("setup", "settings")
                await skip_all_setup27(lc, lockdown_client.udid,
                                       supervised=supervised,
                                       organization_name=organization_name,
                                       progress_callback=progress_callback)
                progress_callback(95)
        else:
            await _restore_ios27(back, reboot, lockdown_client, progress_callback,
                                 backup_password=backup_password,
                                 prepared_backup_root=prepared_backup_root,
                                 inject_files=inject_files,
                                 skip_setup=skip_setup,
                                 skip_protective_backup=skip_protective_backup,
                                 include_keychain=include_keychain,
                                 prompt_choice=prompt_choice,
                                 afc_media=afc_media,
                                 merge_phases=merge_phases,
                                 supervised=supervised,
                                 organization_name=organization_name,
                                 stage_callback=stage_callback)
    else:
        if exploit_only and skip_setup:
            files_list.append(backup.ConcreteFile(
                "", "SysContainerDomain-../../../../../../../.." + "/crash_on_purpose",
                contents=b""))
            back = backup.Backup(files=files_list, apps=apps_list,
                                 device_manifest=device_manifest,
                                 manifest_ios27=False)
        try:
            await perform_restore(backup=back, reboot=reboot,
                                  lockdown_client=lockdown_client,
                                  progress_callback=progress_callback)
        except (ConnectionTerminatedError, ssl.SSLEOFError,
                ConnectionAbortedError, ConnectionResetError):
            log_info("Device disconnected during restore — expected on reboot")
