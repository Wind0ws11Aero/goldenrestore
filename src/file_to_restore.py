"""Lightweight file-mode and file-to-restore definitions.

Kept stdlib-only so the tweak -> restore import chain stays free of the
device stack. ``_FileMode`` is the single definition site for the POSIX mode
bitfield used by both the MBDB (iOS <=26) and sqlite (iOS 27+) manifests.
"""
from enum import IntFlag
from os import PathLike


class _FileMode(IntFlag):
    S_IFMT   = 0o0170000
    S_IFIFO  = 0o0010000
    S_IFCHR  = 0o0020000
    S_IFDIR  = 0o0040000
    S_IFBLK  = 0o0060000
    S_IFREG  = 0o0100000
    S_IFLNK  = 0o0120000
    S_IFSOCK = 0o0140000

    S_IRUSR  = 0o0000400
    S_IWUSR  = 0o0000200
    S_IXUSR  = 0o0000100

    S_IRGRP  = 0o0000040
    S_IWGRP  = 0o0000020
    S_IXGRP  = 0o0000010

    S_IROTH  = 0o0000004
    S_IWOTH  = 0o0000002
    S_IXOTH  = 0o0000001

    S_ISUID  = 0o0004000
    S_ISGID  = 0o0002000
    S_ISVTX  = 0o0001000


class FileToRestore:
    """A single file the device restore agent should install.

    ``contents`` and ``contents_path`` are two ways of supplying the payload;
    provide one of them (``contents`` wins when both are set).
    """

    def __init__(self,
                 contents: bytes | str | None,
                 restore_path: str,
                 contents_path: str | PathLike[str] | None = None,
                 domain: str | None = "",
                 owner: int = 501,
                 group: int = 501,
                 mode: _FileMode = None):
        self.contents = contents
        self.contents_path = contents_path
        self.restore_path = restore_path
        self.domain = domain
        self.owner = owner
        self.group = group
        self.mode = mode
