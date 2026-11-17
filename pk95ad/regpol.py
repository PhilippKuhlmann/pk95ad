"""Registry.pol (PReg version 1) reader and writer.

Format: b"PReg" + uint32 LE version 1, then entries
    [key;value;type;size;data]
where "[", ";", "]" and the two strings are UTF-16 LE (strings null-terminated) and type and size
are uint32 LE. REG_SZ data is UTF-16 LE including the terminating null.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

REG_SZ = 1
REG_EXPAND_SZ = 2
REG_BINARY = 3
REG_DWORD = 4
REG_MULTI_SZ = 7
REG_QWORD = 11

SIGNATURE = b"PReg"
VERSION = 1

_OPEN = "[".encode("utf-16-le")
_SEP = ";".encode("utf-16-le")
_CLOSE = "]".encode("utf-16-le")
_NUL = b"\x00\x00"


class PolError(ValueError):
    """The file is not a valid Registry.pol."""


@dataclass(frozen=True)
class Entry:
    key: str
    value: str
    type: int
    data: bytes

    def ident(self) -> tuple[str, str]:
        """Registry names are case-insensitive."""
        return (self.key.lower(), self.value.lower())


def sz(key: str, value: str, text: str, typ: int = REG_SZ) -> Entry:
    return Entry(key, value, typ, (text + "\0").encode("utf-16-le"))


def dword(key: str, value: str, number: int) -> Entry:
    return Entry(key, value, REG_DWORD, struct.pack("<I", number & 0xFFFFFFFF))


def entry_value(e: Entry):
    """Python value of an entry: str for REG_SZ/REG_EXPAND_SZ, int for DWORD/QWORD, else bytes."""
    if e.type in (REG_SZ, REG_EXPAND_SZ):
        return e.data.decode("utf-16-le", errors="replace").split("\0", 1)[0]
    if e.type == REG_DWORD and len(e.data) >= 4:
        return struct.unpack("<I", e.data[:4])[0]
    if e.type == REG_QWORD and len(e.data) >= 8:
        return struct.unpack("<Q", e.data[:8])[0]
    return e.data


def _expect(buf: bytes, pos: int, token: bytes) -> int:
    if buf[pos:pos + 2] != token:
        raise PolError(f"Registry.pol: unerwartetes Zeichen an Position {pos}.")
    return pos + 2


def _string(buf: bytes, pos: int) -> tuple[str, int]:
    end = pos
    while True:
        if end + 2 > len(buf):
            raise PolError("Registry.pol: Zeichenkette ohne Ende.")
        if buf[end:end + 2] == _NUL:
            break
        end += 2
    try:
        text = buf[pos:end].decode("utf-16-le")
    except UnicodeDecodeError as exc:
        raise PolError("Registry.pol: ungültige Zeichenkette.") from exc
    return text, end + 2


def _uint32(buf: bytes, pos: int) -> tuple[int, int]:
    if pos + 4 > len(buf):
        raise PolError("Registry.pol: Datei endet zu früh.")
    return struct.unpack("<I", buf[pos:pos + 4])[0], pos + 4


def parse(buf: bytes) -> list[Entry]:
    """Entries of a Registry.pol file. An empty buffer is an empty policy."""
    if not buf:
        return []
    if len(buf) < 8 or buf[:4] != SIGNATURE:
        raise PolError("Keine gültige Registry.pol-Datei.")
    version = struct.unpack("<I", buf[4:8])[0]
    if version != VERSION:
        raise PolError(f"Registry.pol: unbekannte Version {version}.")
    pos = 8
    out: list[Entry] = []
    while pos < len(buf):
        pos = _expect(buf, pos, _OPEN)
        key, pos = _string(buf, pos)
        pos = _expect(buf, pos, _SEP)
        value, pos = _string(buf, pos)
        pos = _expect(buf, pos, _SEP)
        typ, pos = _uint32(buf, pos)
        pos = _expect(buf, pos, _SEP)
        size, pos = _uint32(buf, pos)
        pos = _expect(buf, pos, _SEP)
        if pos + size > len(buf):
            raise PolError("Registry.pol: Datei endet zu früh.")
        data = bytes(buf[pos:pos + size])
        pos += size
        pos = _expect(buf, pos, _CLOSE)
        out.append(Entry(key, value, typ, data))
    return out


def serialize(entries: list[Entry]) -> bytes:
    out = bytearray(SIGNATURE)
    out += struct.pack("<I", VERSION)
    for e in entries:
        out += _OPEN
        out += (e.key + "\0").encode("utf-16-le")
        out += _SEP
        out += (e.value + "\0").encode("utf-16-le")
        out += _SEP
        out += struct.pack("<I", e.type)
        out += _SEP
        out += struct.pack("<I", len(e.data))
        out += _SEP
        out += e.data
        out += _CLOSE
    return bytes(out)
