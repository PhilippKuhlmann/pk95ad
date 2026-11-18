import os
import tempfile
import unittest

from pk95ad import config, gpo, idmap, monitor, resolver, smbconf, sysvol
from pk95ad.directory import gentime_ms, ms_to_nt, nt_to_ms, password_message
from pk95ad.errors import ApiError

SETTINGS = {"realm": "ad.example.com", "netbios_domain": "EXAMPLE", "hostname": "dc1", "host_ip": "192.0.2.10",
            "dns_forwarder": "127.0.0.1"}


class SmbConfTest(unittest.TestCase):
    def test_render(self):
        cfg = config.Config()
        text = smbconf.render(SETTINGS, cfg)
        for line in ("netbios name = DC1", "realm = AD.EXAMPLE.COM", "workgroup = EXAMPLE", "dns port = 5300",
                     "interfaces = lo 192.0.2.10", "bind interfaces only = yes",
                     "rpc server dynamic port range = 49152-49200", "acl_xattr:security_acl_name = user.NTACL",
                     "path = /var/lib/samba/sysvol/ad.example.com/scripts"):
            self.assertIn(line, text)
        opts = smbconf.provision_options(SETTINGS, cfg)
        self.assertIn("acl_xattr:security_acl_name=user.NTACL", opts)
        self.assertIn("dns port=5300", opts)
        self.assertIn("ntpsigndsocket /var/lib/samba/ntp_signd", smbconf.chrony(cfg))

    def test_hosts_entry(self):
        base = "127.0.0.1\tlocalhost\n192.0.2.1\tpk95\n"
        out = smbconf.hosts_with_dc(base, SETTINGS)
        self.assertEqual(out, base + "192.0.2.10\tdc1.ad.example.com dc1\t# pk95ad\n")
        moved = smbconf.hosts_with_dc(out, {**SETTINGS, "host_ip": "192.0.2.11"})
        self.assertEqual(moved.count("# pk95ad"), 1)
        self.assertIn("192.0.2.11\tdc1.ad.example.com", moved)
        self.assertEqual(smbconf.hosts_with_dc(out, SETTINGS), out)


class IdmapTest(unittest.TestCase):
    SAMBA_DEFAULT = "dn: CN=CONFIG\ncn: CONFIG\nlowerBound: 3000000\nupperBound: 4000000\n"

    def test_ldif(self):
        self.assertEqual(idmap.ldif_bounds(self.SAMBA_DEFAULT), (3000000, 4000000))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "idmap_init.ldif")
            with open(p, "w") as fh:
                fh.write(self.SAMBA_DEFAULT)
            self.assertIn("65535", idmap.check_ldif(p))
            with open(p, "w") as fh:
                fh.write(self.SAMBA_DEFAULT.replace("3000000", "20000").replace("4000000", "59999"))
            self.assertIsNone(idmap.check_ldif(p))
            self.assertIn("fehlt", idmap.check_ldif(os.path.join(d, "missing.ldif")))

    def test_ranges_do_not_overlap_and_fit_the_lxc(self):
        self.assertLess(idmap.RFC2307_HIGH, idmap.XID_LOW)
        self.assertLess(idmap.XID_HIGH, 65534)  # nobody
        self.assertLessEqual(idmap.MAX_ID, 65535)

    def test_evaluate(self):
        ok = idmap.evaluate(20000, 59999, 20042, [0, 100, 65534, 20000, 20041], [("max", 10000)])
        self.assertTrue(ok["ok"], ok["message"])
        self.assertEqual((ok["next_xid"], ok["allocated"]), (20042, 5))
        old = idmap.evaluate(3000000, 4000000, 3000010, [3000001], [])
        self.assertFalse(old["ok"])
        self.assertIn("neu eingerichtet", old["message"])
        bad_rfc = idmap.evaluate(20000, 59999, None, [], [("anna", 70000)])
        self.assertFalse(bad_rfc["ok"])
        self.assertIn("anna", bad_rfc["message"])
        self.assertEqual(bad_rfc["next_xid"], 20000)
        full = idmap.evaluate(20000, 59999, 58000, [], [])
        self.assertIn("fast aufgebraucht", full["message"])


class ResolverTest(unittest.TestCase):
    LXC = "# from the LXC\nnameserver 10.10.250.1\nnameserver 127.0.0.1\nnameserver 9.9.9.9\nnameserver 1.1.1.1\n" \
          "search kuhlmannit.de\noptions edns0 timeout:5\n"

    def test_render_puts_pk95_dns_first_and_keeps_the_original(self):
        out = resolver.render(resolver.original_lines(self.LXC), "ad.example.com")
        lines = [x for x in out.splitlines() if not x.startswith("#")]
        self.assertEqual(lines, ["nameserver 127.0.0.1", "nameserver 10.10.250.1", "nameserver 9.9.9.9",
                                 "search ad.example.com kuhlmannit.de", "options timeout:2 attempts:2 edns0"])
        # Rewriting our own file keeps the LXC's original, not our lines.
        self.assertEqual(resolver.original_lines(out), self.LXC.splitlines())
        self.assertEqual(resolver.render(resolver.original_lines(out), "ad.example.com"), out)

    def test_ensure_only_when_pk95_dns_answers_the_zone(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "resolv.conf")
            with open(p, "w") as fh:
                fh.write(self.LXC)
            st = resolver.ensure("ad.example.com", dns_probe=lambda z: "noanswer", path=p)
            self.assertFalse(st["ok"])
            self.assertIn("127.0.0.1:53", st["message"])
            st = resolver.ensure("ad.example.com", dns_probe=lambda z: "nxdomain", path=p)
            self.assertIn("bedingte Weiterleitung ad.example.com", st["message"])
            self.assertEqual(open(p).read(), self.LXC)  # untouched
            st = resolver.ensure("ad.example.com", dns_probe=lambda z: "ok", path=p)
            self.assertEqual(st, {"ok": True, "nameserver": "127.0.0.1", "message": ""})
            self.assertTrue(open(p).read().splitlines()[2] == "nameserver 127.0.0.1")

    def test_query_soa(self):
        import socket
        import struct
        import threading

        def serve(sock, rcode, ancount):
            data, addr = sock.recvfrom(512)
            flags = 0x8180 | rcode
            sock.sendto(data[:2] + struct.pack(">HHHHH", flags, 1, ancount, 0, 0) + data[12:], addr)

        for rcode, ancount, expected in ((0, 1, "ok"), (3, 0, "nxdomain"), (2, 0, "noanswer")):
            with self.subTest(expected=expected):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                t = threading.Thread(target=serve, args=(sock, rcode, ancount))
                t.start()
                self.assertEqual(resolver.query_soa("ad.example.com", port=sock.getsockname()[1]), expected)
                t.join()
                sock.close()
        free = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        free.bind(("127.0.0.1", 0))
        port = free.getsockname()[1]
        free.close()
        self.assertEqual(resolver.query_soa("ad.example.com", port=port, timeout=0.3), "noanswer")


class ConfigTest(unittest.TestCase):
    def test_load(self):
        cfg = config.load({"PK95AD_LISTEN": "127.0.0.1:9000", "PK95_CORE_MODE": "1", "PK95_CORE_TOKEN": "t" * 48,
                           "PK95AD_TOKEN": "ignored", "PK95_CORE_URL": "http://127.0.0.1:8080/"})
        self.assertEqual((cfg.listen_host, cfg.listen_port), ("127.0.0.1", 9000))
        self.assertTrue(cfg.core_mode)
        self.assertEqual(cfg.token, "t" * 48)
        self.assertEqual(cfg.core_url, "http://127.0.0.1:8080")
        cfg = config.load({"PK95AD_TOKEN": "x" * 40})
        self.assertFalse(cfg.core_mode)
        self.assertEqual(cfg.token, "x" * 40)
        with self.assertRaises(ValueError):
            config.load({"PK95AD_RPC_PORTS": "all"})


class GptIniTest(unittest.TestCase):
    def test_version(self):
        self.assertEqual(sysvol.gpt_version("[General]\r\nVersion=65539\r\ndisplayName=New\r\n"), 65539)
        self.assertEqual(sysvol.gpt_version(""), 0)

    def test_set_version_keeps_other_lines(self):
        out = sysvol.gpt_set_version("[General]\r\nVersion=1\r\ndisplayName=Neue GPO\r\n", 65537)
        self.assertEqual(out, "[General]\r\nVersion=65537\r\ndisplayName=Neue GPO\r\n")
        self.assertEqual(sysvol.gpt_set_version("", 3), "[General]\r\nVersion=3\r\n")
        self.assertEqual(sysvol.gpt_set_version("[general]\ndisplayName=x\n", 2),
                         "[general]\r\nVersion=2\r\ndisplayName=x\r\n")


class ExtensionNamesTest(unittest.TestCase):
    def test_set_and_remove(self):
        items = gpo.ext_parse("[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]")
        items = gpo.ext_set(items, gpo.REGISTRY_CSE, gpo.TOOLS[("registry", "computer")], True)
        text = gpo.ext_format(items)
        self.assertEqual(text, "[{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{D02B1F72-3407-48AE-BA88-E8213C6761F1}]"
                               "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]")
        items = gpo.ext_set(gpo.ext_parse(text), gpo.REGISTRY_CSE, gpo.TOOLS[("registry", "computer")], False)
        self.assertEqual(gpo.ext_format(items),
                         "[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]")
        self.assertEqual(gpo.ext_format(gpo.ext_set([], gpo.SCRIPTS_CSE, "{X}", False)), "")


class SysvolTest(unittest.TestCase):
    def test_ci_join(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "MACHINE"))
            self.assertEqual(sysvol.ci_join(d, "Machine", "Registry.pol"), os.path.join(d, "MACHINE", "Registry.pol"))
            p = sysvol.ci_join(d, "User", "Scripts", "scripts.ini", create=True)
            self.assertTrue(os.path.isdir(os.path.join(d, "User", "Scripts")))
            self.assertEqual(p, os.path.join(d, "User", "Scripts", "scripts.ini"))

    def test_scripts_api_validation(self):
        cfg = config.Config()
        with tempfile.TemporaryDirectory() as d:
            cfg.samba_dir = d
            for name in ("../x.bat", "x.exe", ".hidden.bat"):
                with self.subTest(name=name):
                    with self.assertRaises(ApiError):
                        sysvol.script_put(cfg, "ad.example.com", name, {"content": "x"})
            self.assertEqual(sysvol.scripts_list(cfg, "ad.example.com"), [])


class ConversionTest(unittest.TestCase):
    def test_nt_time(self):
        self.assertEqual(nt_to_ms("0"), 0)
        self.assertEqual(nt_to_ms(str(0x7FFFFFFFFFFFFFFF)), 0)
        self.assertEqual(nt_to_ms(ms_to_nt(1762700000000)), 1762700000000)
        self.assertEqual(gentime_ms("20251109145320.0Z"), 1762700000000)

    def test_password_messages(self):
        self.assertIn("mindestens 7", password_message(
            "check_password_restrictions: the password is too short. It should be equal or longer than 7 characters!"))
        self.assertIn("komplex", password_message("the password does not meet the complexity criteria!"))
        self.assertIsNone(password_message("something else"))

    def test_dbcheck_errors(self):
        self.assertEqual(monitor.count_errors("Checked 412 objects (0 errors)\n", 0), 0)
        self.assertEqual(monitor.count_errors("Checked 412 objects (3 errors)\n", 1), 3)
        self.assertEqual(monitor.count_errors("boom", 2), 1)


if __name__ == "__main__":
    unittest.main()
