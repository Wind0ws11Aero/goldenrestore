"""Standalone managed-preference locations.

Derived from the GoldenNugget tweak registry: the HomeDomain app plists that
``mcxd`` mirrors managed preferences into. The protective-backup keep-set
(``protective._SKIP_APP_PREF_FILES``) and the reset flow exclude these so a
stale app-plist mirror never resurrects a tweak after the managed entry is
cleared.
"""

MANAGED_PREF_PREFIX = "/var/Managed Preferences/"

# Managed-pref FileLocation names used as a tweak spec location, plus ``ota``
# (which the registry always adds). The filenames mirror
# ``src/tweaks/basic_plist_locations.py``.
_MANAGED_SPEC_TARGETS = (
    "com.apple.MobileAsset.plist",           # ota
    "com.apple.springboard.plist",           # springboard
    "com.apple.sharingd.plist",              # airdrop
    "com.apple.ambient.plist",               # ambient
    "com.apple.Accessibility.plist",         # accessibility
    ".GlobalPreferences.plist",              # globalPreferences
    "com.apple.AppStore.plist",              # appStore
    "com.apple.backboardd.plist",            # backboardd
    "com.apple.CoreMotion.plist",            # coreMotion
    "com.apple.Pasteboard.plist",            # pasteboard
    "com.apple.mobilenotes.plist",           # notes
    "com.apple.keyboard.preferences.plist",  # keyboardPreferences
    "com.apple.UIKit.plist",                 # uikit
)


def managed_pref_target(path: str):
    """HomeDomain path of the app plist a managed-preference file mirrors into.

    ``/var/Managed Preferences/mobile/com.apple.springboard.plist`` ->
    ``Library/Preferences/com.apple.springboard.plist``. Returns ``None`` for
    any other location.
    """
    if not path.startswith(MANAGED_PREF_PREFIX):
        return None
    name = path[len(MANAGED_PREF_PREFIX):]
    if name.startswith("mobile/"):
        name = name[len("mobile/"):]
    # managed prefs are flat per-user files; a nested subdirectory is not a
    # real location and must not map onto a nested HomeDomain path
    if "/" in name or not name.endswith(".plist"):
        return None
    return f"Library/Preferences/{name}"


def managed_pref_app_plists() -> frozenset:
    """HomeDomain-relative app plists that carry the managed-preference tweaks.

    mcxd copies every managed preference into the target app's own cfprefs
    domain on disk, so a managed-pref tweak lives in TWO places: the
    ``/var/Managed Preferences`` file the tool owns, and the app plist where the
    merged value stays behind as an ordinary preference once the managed entry
    is gone. Anything that must not resurrect a tweak (the protective-backup
    keep-set, the reset) derives its exclusion list from here.
    """
    return frozenset(f"Library/Preferences/{name}" for name in _MANAGED_SPEC_TARGETS)
