"""Offline domain join (1.5.0): password handling, composeodj call, rollback, no secrets in logs."""

import base64
import logging
import subprocess
import unittest

from pk95ad import accounts

BLOB = base64.b64encode(b"ODJ provisioning data").decode()


class FakeSession:
    realm = "ad.example.com"
    domain_sid = "S-1-5-21-1-2-3"
    base = "DC=ad,DC=example,DC=com"
    settings = {"netbios_domain": "EXAMPLE", "hostname": "dc1", "host_ip": "192.0.2.10"}

    def search(self, **kw):
        return [object()]

    def guid(self, msg):
        return "11111111-2222-3333-4444-555555555555"


class OdjTest(unittest.TestCase):
    def test_machine_password(self):
        pw = accounts.machine_password()
        self.assertEqual(len(pw), 120)
        self.assertTrue(any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                        and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw))
        self.assertNotEqual(pw, accounts.machine_password())

    def test_compose_passes_password_only_in_the_environment(self):
        seen = {}

        def run(argv, **kw):
            seen.update(argv=argv, env=kw["env"], stdin=kw["stdin"])
            return subprocess.CompletedProcess(argv, 0, BLOB[:10] + "\n" + BLOB[10:] + "\n", "")

        blob = accounts.compose_odj(FakeSession(), "files", "Secret-Pw-1", run=run)
        self.assertEqual(blob, BLOB)
        argv = seen["argv"]
        self.assertEqual(argv[:3], ["net", "offlinejoin", "composeodj"])
        for part in ("--realm=AD.EXAMPLE.COM", "--workgroup=EXAMPLE", "domain_sid=S-1-5-21-1-2-3",
                     "domain_guid=11111111-2222-3333-4444-555555555555", "forest_name=ad.example.com",
                     "printblob", "dc1.ad.example.com", "192.0.2.10"):
            self.assertIn(part, argv)
        self.assertEqual(argv[argv.index("-U") + 1], "FILES$")  # not the DC's own name
        self.assertFalse(any("Secret-Pw-1" in a for a in argv))
        self.assertEqual(seen["env"]["PASSWD"], "Secret-Pw-1")
        self.assertNotIn("USER", seen["env"])
        self.assertEqual(seen["stdin"], subprocess.DEVNULL)

    def test_compose_failure_hides_the_password(self):
        def run(argv, **kw):
            return subprocess.CompletedProcess(argv, 255, "", "Failed: bad password Secret-Pw-1\n")

        with self.assertRaises(accounts.OdjError) as e:
            accounts.compose_odj(FakeSession(), "files", "Secret-Pw-1", run=run)
        self.assertNotIn("Secret-Pw-1", str(e.exception))
        self.assertIn("Code 255", str(e.exception))
        with self.assertRaises(accounts.OdjError):
            accounts.compose_odj(FakeSession(), "files", "x", run=lambda a, **k: subprocess.CompletedProcess(a, 0, "%%%", ""))

    def test_flow_rolls_back_a_created_account(self):
        deleted = []

        def failing(pw):
            raise accounts.OdjError("composeodj kaputt")

        with self.assertRaises(accounts.OdjError):
            accounts.odj_flow(lambda: ("CN=FILES", True, "pw"), failing, deleted.append)
        self.assertEqual(deleted, ["CN=FILES"])
        # A reset (existing account) is not deleted.
        with self.assertRaises(accounts.OdjError):
            accounts.odj_flow(lambda: ("CN=OLD", False, "pw"), failing, deleted.append)
        self.assertEqual(deleted, ["CN=FILES"])
        self.assertEqual(accounts.odj_flow(lambda: ("CN=NEW", True, "pw"), lambda pw: BLOB, deleted.append),
                         ("CN=NEW", True, BLOB))

    def test_no_secret_in_logs(self):
        records = []

        class Capture(logging.Handler):
            def emit(self, record):
                records.append(self.format(record))

        root = logging.getLogger()
        handler = Capture()
        root.addHandler(handler)
        old = root.level
        root.setLevel(logging.DEBUG)
        try:
            accounts.odj_flow(lambda: ("CN=NEW", True, "Secret-Pw-1"),
                              lambda pw: accounts.compose_odj(FakeSession(), "files", pw, run=lambda a, **k:
                                                              subprocess.CompletedProcess(a, 0, BLOB, "")),
                              lambda dn: None)
        finally:
            root.removeHandler(handler)
            root.setLevel(old)
        self.assertFalse(any(BLOB in r or "Secret-Pw-1" in r for r in records))


if __name__ == "__main__":
    unittest.main()
