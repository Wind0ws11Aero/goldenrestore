"""Decisive test for the post-restore "verify your Apple ID" prompt.

Runs the *default* flow — no ``include_keychain``, so no security-recovery
wipe — and only varies how much Apple-ID state rides the protective backup:

    default   both switches on   (current behaviour)
    identity  include_apple_identity=False  (upstream GoldenNugget's scope:
              the account record is restored, the identity-services session /
              token cache is not)
    none      include_apple_account=False         (no Apple-ID state at all: the
              device ends up signed out)

The device keeps its own live session state in this flow, so the difference
between "identity" and "none" is exactly whether the restored account record
can be validated against the session that is still on the device.

    python diag_apple_id_restore.py [default|identity|none]

Keep the iPad unlocked and on the home screen for the whole run.
"""
import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pymobiledevice3.lockdown import create_using_usbmux

from goldenrestore import restore_files

MODES = {
    "default": {},
    "identity": {"include_apple_identity": False},
    "none": {"include_apple_account": False, "include_apple_identity": False},
}


def progress(status):
    print(f"[{time.strftime('%H:%M:%S')}] {status}", flush=True)


async def main() -> None:
    mode = sys.argv[1] if len(sys.argv) > 1 else "identity"
    if mode not in MODES:
        print(f"mode must be one of {sorted(MODES)}")
        return
    options = MODES[mode]
    print(f"=== Apple-ID scope test: mode={mode} {options} ===", flush=True)
    lockdown = await create_using_usbmux(connection_type="USB")
    print(f"connected udid={lockdown.udid}", flush=True)

    t0 = time.time()
    try:
        await restore_files(
            files=[],
            skip_setup=True,
            reboot=True,
            progress_callback=progress,
            **options,
        )
        print(f"=== RESTORE COMPLETE in {time.time()-t0:.0f}s ===", flush=True)
        print("Now look at the device: is the \"verify your Apple ID\" "
              "prompt there?", flush=True)
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
