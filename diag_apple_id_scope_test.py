"""Fast A/B test for the post-restore "verify your Apple ID" prompt.

Reuses an EXISTING protective backup as the Phase 1 input, so no fresh device
backup is taken (that part takes an hour on this device — the photos dominate).
The flow is the default one: no ``include_keychain``, so no security-recovery
wipe, and the protective restore is applied over the live device.

Only the Apple-ID scope differs between the runs:

    default   both switches on    (current behaviour)
    identity  include_apple_identity=False   (upstream GoldenNugget's scope)
    none      include_apple_account=False          (no Apple-ID state at all)

    python diag_apple_id_scope_test.py [default|all|account-off|none] [BACKUP_ROOT]

BACKUP_ROOT defaults to the newest protective backup under
~/.goldennugget/protective. It is COPIED first — the flow prunes its input in
place.
"""
import asyncio
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymobiledevice3.lockdown import create_using_usbmux

from goldenrestore import PreparedBackup, restore_files

MODES = {
    "default": {},
    "all": {"include_apple_account": True},
    "account-off": {"include_apple_identity": False},
    "none": {"include_apple_identity": False, "include_find_my_state": False},
}
PASSWORD = "gnug"


def newest_backup() -> Path:
    base = Path.home() / ".goldennugget" / "protective"
    runs = sorted((p for p in base.glob("*/*/device_backup") if p.is_dir()),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    for run in runs:
        if (run / "Manifest.db").exists() or any(run.glob("*/Manifest.db")):
            return run
    raise SystemExit("No protective backup found under ~/.goldennugget/protective")


def progress(status):
    print(f"[{time.strftime('%H:%M:%S')}] {status}", flush=True)


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "account-off"
    if mode not in MODES:
        raise SystemExit(f"mode must be one of {sorted(MODES)}")
    source = Path(sys.argv[2]) if len(sys.argv) > 2 else newest_backup()
    options = MODES[mode]

    work = Path(tempfile.mkdtemp(prefix="gn_scope_"))
    copy = work / "device_backup"
    print(f"copying {source} -> {copy}", flush=True)
    shutil.copytree(source, copy)

    print(f"=== scope test: mode={mode} {options} ===", flush=True)
    lockdown = await create_using_usbmux(connection_type="USB")
    print(f"connected udid={lockdown.udid}", flush=True)

    prepared = PreparedBackup(root=str(copy), manifest_password=PASSWORD,
                              master=False)
    t0 = time.time()
    try:
        await restore_files(
            files=[],
            prepared_backup_root=prepared,
            backup_password=PASSWORD,
            skip_setup=True,
            reboot=True,
            progress_callback=progress,
            **options,
        )
        print(f"=== RESTORE COMPLETE in {time.time()-t0:.0f}s ===", flush=True)
        print("Look at the iPad now: is the \"verify your Apple ID\" prompt "
              "there?", flush=True)
    except Exception as e:
        print(f"=== RESTORE FAILED in {time.time()-t0:.0f}s: "
              f"{type(e).__name__}: {e} ===", flush=True)
        raise
    finally:
        try:
            await lockdown.close()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
