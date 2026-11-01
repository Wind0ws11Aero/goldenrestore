"""Finish the interrupted restore: the setup skip (Phase 5) and the final
reboot (Phase 6) that were never run.

The Phase 3 restore itself completed (100%); the flow was interrupted during
the Phase 4 reconnect wait, so the device came up at the Setup Assistant
instead of the home screen. Pushing the SkipSetup cloud configuration is
exactly what Phase 5 does.
"""
import asyncio
import sys
import time

sys.path.insert(0, "/Users/jason/Documents")
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.diagnostics import DiagnosticsService

from goldenrestore.src.skip_setup27 import skip_all_setup27


async def main() -> None:
    lockdown = await create_using_usbmux()
    udid = lockdown.udid
    print(f"device {udid}", flush=True)

    print("Phase 5: pushing the setup-skip configuration...", flush=True)
    try:
        await skip_all_setup27(lockdown, udid, supervised=False,
                               organization_name="",
                               progress_callback=lambda x: print(f"  {x}", flush=True))
        print("setup skip pushed", flush=True)
    except Exception as e:
        print(f"setup skip FAILED: {type(e).__name__}: {e}", flush=True)
        raise

    print("waiting 10s before the final reboot...", flush=True)
    await asyncio.sleep(10)

    print("Phase 6: rebooting...", flush=True)
    async with DiagnosticsService(lockdown) as diag:
        await diag.restart()
    print("reboot command sent", flush=True)
    await lockdown.close()


asyncio.run(main())
