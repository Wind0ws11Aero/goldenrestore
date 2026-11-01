"""Isolate the backup-encryption toggle that used to terminate the connection.

Uses the correct mobilebackup2 message (ChangePassword) exactly as Finder and
tools/idevicebackup2.c do. Enable = NewPassword, disable = OldPassword.

Run with the iOS 27 device attached (and unlocked, in case it fires an
on-device passcode confirmation):

    # terminal 2 while this runs:
    pymobiledevice3 syslog live 2>/dev/null | grep -iE "backupd|mobilebackup|securityd|keybag"
"""
import asyncio
from pathlib import Path

from pymobiledevice3.lockdown import create_using_usbmux, LockdownClient
from pymobiledevice3.services.device_link import DeviceLink
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service

PASSWORD = "gnug"


async def probe_change_password(lockdown: LockdownClient,
                                key: str, password: str) -> str:
    """Send one ChangePassword on a fresh session; return what came back."""
    message = {"MessageName": "ChangePassword",
               "TargetIdentifier": lockdown.udid, key: password}
    async with Mobilebackup2Service(lockdown) as mb:
        await mb.connect()
        dl = DeviceLink(mb._service, Path("."), preserve_file=None)
        await dl.version_exchange()
        await mb.version_exchange(dl)
        print(f"  -> handshake OK, sending {message}")
        await dl.send_process_message(message)
        try:
            content = await dl.dl_loop()  # answers RemoveItems etc.
        except asyncio.CancelledError:
            raise
        except BaseException as e:
            return f"DIED: {type(e).__name__}: {e}"
        return f"final ProcessMessage, content: {content!r}"


async def main() -> None:
    lockdown = await create_using_usbmux(connection_type="USB")
    domain = await lockdown.get_value(domain="com.apple.mobile.backup") or {}
    print("com.apple.mobile.backup lockdown domain:")
    for key, value in domain.items():
        print(f"  {key} = {value}")

    already_on = bool(domain.get("WillEncrypt"))
    if not already_on:
        print(f"\nProbe A: enable encryption (NewPassword={PASSWORD!r})")
        print(f"  {await probe_change_password(lockdown, 'NewPassword', PASSWORD)}")
    else:
        print("\nProbe A skipped: encryption already enabled")

    print("\nProbe B: disable encryption again (OldPassword)")
    print(f"  {await probe_change_password(lockdown, 'OldPassword', PASSWORD)}")

    domain = await lockdown.get_value(domain="com.apple.mobile.backup") or {}
    print(f"\nWillEncrypt afterwards: {domain.get('WillEncrypt')}")


asyncio.run(main())
