"""Full six-phase protective restore test.

Runs restore_files(files=[], include_keychain=True) so the flow:
  1. enables backup encryption (password below)
  2. takes a FRESH protective backup — now including the IdentityServices /
     Find My / adid identity files (the new protective scope)
  3. sparse restore -> security-recovery wipe
  4. protective restore (keychain + identity files land)
  5. disables encryption again

Afterwards, inspect the device's Settings for the "verify your Apple ID" prompt.
"""
import asyncio
import sys
import time

from pymobiledevice3.lockdown import create_using_usbmux

from goldenrestore import restore_files

PASSWORD = "gnug"
LOG = sys.stdout


def progress(status):
    # status is an OperationStatus (str-like)
    line = f"[{time.strftime('%H:%M:%S')}] {status}"
    print(line, flush=True)


async def main() -> None:
    print(f"=== full restore test, password={PASSWORD} ===", flush=True)
    lockdown = await create_using_usbmux(connection_type="USB")
    print(f"connected udid={lockdown.udid}", flush=True)

    t0 = time.time()
    try:
        await restore_files(
            files=[],
            include_keychain=True,
            skip_setup=True,
            reboot=True,
            backup_password=PASSWORD,
            progress_callback=progress,
            supervised=False,
            organization_name="",
        )
        print(f"=== RESTORE COMPLETE in {time.time()-t0:.0f}s ===", flush=True)
    except Exception as e:
        print(f"=== RESTORE FAILED in {time.time()-t0:.0f}s: {type(e).__name__}: {e} ===", flush=True)
        raise
    finally:
        try:
            await lockdown.close()
        except Exception:
            pass


if __name__ == "__main__":
    asyncio.run(main())
