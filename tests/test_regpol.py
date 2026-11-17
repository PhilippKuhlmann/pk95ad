import struct
import unittest

from pk95ad import regpol


def raw_entry(key, value, typ, data):
    u = lambda s: s.encode("utf-16-le")  # noqa: E731
    return (u("[") + u(key + "\0") + u(";") + u(value + "\0") + u(";") + struct.pack("<I", typ) + u(";")
            + struct.pack("<I", len(data)) + u(";") + data + u("]"))


class RegPolTest(unittest.TestCase):
    def test_parse_handwritten_file(self):
        data = (b"PReg" + struct.pack("<I", 1)
                + raw_entry(r"Software\Policies\X", "Deny_All", regpol.REG_DWORD, struct.pack("<I", 1))
                + raw_entry(r"Software\Policies\X", "Path", regpol.REG_SZ, "C:\\a\0".encode("utf-16-le")))
        entries = regpol.parse(data)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].key, r"Software\Policies\X")
        self.assertEqual(regpol.entry_value(entries[0]), 1)
        self.assertEqual(regpol.entry_value(entries[1]), "C:\\a")
        self.assertEqual(regpol.serialize(entries), data)

    def test_roundtrip(self):
        entries = [regpol.dword("K", "V", 7), regpol.sz("K\\Sub", "Ä Ö ü", "Text mit Umlaut ß"),
                   regpol.Entry("K", "**del.X", regpol.REG_SZ, b" \x00")]
        self.assertEqual(regpol.parse(regpol.serialize(entries)), entries)

    def test_empty(self):
        self.assertEqual(regpol.parse(b""), [])
        self.assertEqual(regpol.parse(regpol.serialize([])), [])
        self.assertEqual(regpol.serialize([]), b"PReg\x01\x00\x00\x00")

    def test_invalid(self):
        for data in (b"XXXX\x01\x00\x00\x00", b"PReg\x02\x00\x00\x00", b"PReg\x01\x00\x00\x00[\x00",
                     regpol.serialize([regpol.dword("K", "V", 1)])[:-3]):
            with self.assertRaises(regpol.PolError):
                regpol.parse(data)

    def test_ident_case_insensitive(self):
        self.assertEqual(regpol.dword("Software\\A", "X", 1).ident(), regpol.dword("SOFTWARE\\a", "x", 2).ident())


if __name__ == "__main__":
    unittest.main()
