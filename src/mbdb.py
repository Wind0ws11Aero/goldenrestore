"""Binary MBDB (manifest) reader/writer.

The ``mbdb`` container format used by iOS 26 and below (Status.plist 2.4).
iOS 27+ uses a sqlite ``Manifest.db`` instead (see :mod:`goldennugget.backup`).

Supports both reading (``from_bytes`` / ``MbdbRecord.from_stream``) and
writing (``to_bytes``), mirroring the sparserestore layout.
"""
from dataclasses import dataclass
from io import BytesIO

from .file_to_restore import _FileMode


def _write_string(d: BytesIO, value: str) -> None:
    # the length prefix counts encoded bytes, not characters
    data = value.encode("utf-8")
    d.write(len(data).to_bytes(2, "big"))
    d.write(data)


def _read_string(d: BytesIO, length: int) -> str:
    return d.read(length).decode("utf-8") if length != 0xffff else ""


@dataclass
class MbdbRecord:
    domain: str
    filename: str
    link: str
    hash: bytes
    key: bytes
    mode: _FileMode
    inode: int
    user_id: int
    group_id: int
    mtime: int
    atime: int
    ctime: int
    size: int
    flags: int
    properties: list

    @classmethod
    def from_stream(cls, d: BytesIO):
        domain_len = int.from_bytes(d.read(2), "big")
        domain = _read_string(d, domain_len)

        filename_len = int.from_bytes(d.read(2), "big")
        filename = _read_string(d, filename_len)

        link_len = int.from_bytes(d.read(2), "big")
        link = _read_string(d, link_len)

        hash_len = int.from_bytes(d.read(2), "big")
        hash = d.read(hash_len) if hash_len != 0xffff else b""

        key_len = int.from_bytes(d.read(2), "big")
        key = d.read(key_len) if key_len != 0xffff else b""

        mode = _FileMode(int.from_bytes(d.read(2), "big"))
        inode = int.from_bytes(d.read(8), "big")
        user_id = int.from_bytes(d.read(4), "big")
        group_id = int.from_bytes(d.read(4), "big")
        mtime = int.from_bytes(d.read(4), "big")
        atime = int.from_bytes(d.read(4), "big")
        ctime = int.from_bytes(d.read(4), "big")
        size = int.from_bytes(d.read(8), "big")
        flags = int.from_bytes(d.read(1), "big")

        properties_count = int.from_bytes(d.read(1), "big")
        properties = []
        for _ in range(properties_count):
            name_len = int.from_bytes(d.read(2), "big")
            name = _read_string(d, name_len)
            value_len = int.from_bytes(d.read(2), "big")
            value = _read_string(d, value_len)
            properties.append((name, value))

        return cls(domain, filename, link, hash, key, mode, inode, user_id,
                   group_id, mtime, atime, ctime, size, flags, properties)

    def to_bytes(self) -> bytes:
        d = BytesIO()

        _write_string(d, self.domain)
        _write_string(d, self.filename)
        _write_string(d, self.link)

        d.write(len(self.hash).to_bytes(2, "big"))
        d.write(self.hash)

        d.write(len(self.key).to_bytes(2, "big"))
        d.write(self.key)

        d.write(self.mode.to_bytes(2, "big"))
        d.write(self.inode.to_bytes(8, "big"))
        d.write(self.user_id.to_bytes(4, "big"))
        d.write(self.group_id.to_bytes(4, "big"))
        d.write(self.mtime.to_bytes(4, "big"))
        d.write(self.atime.to_bytes(4, "big"))
        d.write(self.ctime.to_bytes(4, "big"))
        d.write(self.size.to_bytes(8, "big"))
        d.write(self.flags.to_bytes(1, "big"))

        d.write(len(self.properties).to_bytes(1, "big"))
        for name, value in self.properties:
            _write_string(d, name)
            _write_string(d, value)

        return d.getvalue()


@dataclass
class Mbdb:
    records: list

    @classmethod
    def from_bytes(cls, data: bytes):
        d = BytesIO(data)

        if d.read(4) != b"mbdb":
            raise ValueError("Invalid MBDB file")

        if d.read(2) != b"\x05\x00":
            raise ValueError("Invalid MBDB version")

        records = []
        while d.tell() < len(data):
            records.append(MbdbRecord.from_stream(d))

        return cls(records)

    def to_bytes(self) -> bytes:
        d = BytesIO()

        d.write(b"mbdb")
        d.write(b"\x05\x00")

        for record in self.records:
            d.write(record.to_bytes())

        return d.getvalue()
