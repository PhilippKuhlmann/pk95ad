import unittest

from pk95ad import validate as v


class ValidateTest(unittest.TestCase):
    def ok(self, result, expected=None):
        value, err = result
        self.assertIsNone(err, err)
        if expected is not None:
            self.assertEqual(value, expected)

    def bad(self, result):
        self.assertIsNotNone(result[1])

    def test_realm(self):
        self.ok(v.realm("AD.Example.com."), "ad.example.com")
        for value in ("", "example", "ad.local", "-a.example.com", "a..b", "a.b.c.d.e.f", "ad.example.123"):
            with self.subTest(value=value):
                self.bad(v.realm(value))

    def test_netbios_and_hostname(self):
        self.ok(v.netbios_domain("example"), "EXAMPLE")
        self.bad(v.netbios_domain("a" * 16))
        self.bad(v.netbios_domain("1234"))
        self.ok(v.dc_hostname("DC1"), "dc1")
        for value in ("dc_1", "-dc", "dc-", "123", "a" * 16):
            with self.subTest(value=value):
                self.bad(v.dc_hostname(value))

    def test_forwarder(self):
        self.ok(v.forwarder("127.0.0.1"), "127.0.0.1")
        self.ok(v.forwarder("192.168.1.1:5353"), "192.168.1.1:5353")
        self.ok(v.forwarder("[fd00::1]:53"), "[fd00::1]:53")
        self.ok(v.forwarder("fd00::1"), "fd00::1")
        for value in ("dns.example", "1.2.3.4:0", "1.2.3.4:x", ""):
            with self.subTest(value=value):
                self.bad(v.forwarder(value))

    def test_password(self):
        self.ok(v.password("Sommer2026!"))
        self.ok(v.password("abcDEF123"))
        for value in ("short1A", "alllowercase1", "NoDigitsHere", "Administrator1!x"):
            with self.subTest(value=value):
                self.bad(v.password(value, "Administrator"))

    def test_sam_and_names(self):
        self.ok(v.sam_account_name(" max.muster "), "max.muster")
        for value in ("", "a" * 21, "max@x", "a/b", "trailing."):
            with self.subTest(value=value):
                self.bad(v.sam_account_name(value))
        self.ok(v.object_name("Muster, Max"))
        for value in (" x", "x ", "a/b", "#a", "a\nb", ""):
            with self.subTest(value=value):
                self.bad(v.object_name(value))

    def test_paths(self):
        self.ok(v.unc_path(r"\\nas\home\max"))
        self.ok(v.unc_path(""), "")
        self.bad(v.unc_path(r"C:\home"))
        self.ok(v.home_drive("h:"), "H:")
        self.bad(v.home_drive("HH:"))
        self.ok(v.script_path("vertrieb/logon.cmd"), "vertrieb\\logon.cmd")
        for value in ("..\\x.bat", "\\abs.bat", "a\\\\b.bat"):
            with self.subTest(value=value):
                self.bad(v.script_path(value))

    def test_guid_and_dns(self):
        self.assertEqual(v.guid("{31B2F340-016D-11D2-945F-00C04FB984F9}"), "31b2f340-016d-11d2-945f-00c04fb984f9")
        self.assertIsNone(v.guid("catalog"))
        self.ok(v.dns_name("_ldap._tcp.AD.example.com."), "_ldap._tcp.ad.example.com")
        self.ok(v.dns_name("*.web.ad.example.com"))
        self.bad(v.dns_name("a.*.example.com"))
        self.bad(v.host_target("192.168.1.1"))
        self.ok(v.host_target("mail.example.com"))

    def test_integer_and_boolean(self):
        self.ok(v.integer(5, 0, 10))
        self.bad(v.integer(True, 0, 10))
        self.bad(v.integer(11, 0, 10))
        self.ok(v.boolean(False))
        self.bad(v.boolean("true"))


if __name__ == "__main__":
    unittest.main()
