import unittest

from pk95ad import config, ntptime, smbconf
from pk95ad.errors import ApiError

# chronyc -c output (chrony 4.x): tracking has 14 fields; sources 10 fields per line.
TRACKING_SYNCED = ("C0A80001,192.0.2.1,2,1795159290.123456789,-0.003400000,-0.000210000,0.000500000,-12.345,"
                   "-0.001,0.050,0.012345678,0.000456789,64.5,Normal\n")
TRACKING_LOCAL = ("7F7F0101,,10,1795159290.000000000,0.000000000,0.000000000,0.000000000,0.000,0.000,0.000,"
                  "0.000000000,0.000000000,0.0,Normal\n")
SOURCES_N = ("^,*,192.0.2.1,2,6,377,33,0.001800000,0.001810000,0.000020000\n"
             "^,-,198.51.100.7,2,6,377,35,0.002100000,0.002110000,0.000030000\n"
             "^,?,203.0.113.9,0,6,0,-,0.000000000,0.000000000,0.000000000\n")
SOURCES_NAMES = ("^,*,de.pool.ntp.org,2,6,377,33,0.001800000,0.001810000,0.000020000\n"
                 "^,-,de.pool.ntp.org,2,6,377,35,0.002100000,0.002110000,0.000030000\n"
                 "^,?,time.example.com,0,6,0,-,0.000000000,0.000000000,0.000000000\n")


class ServersTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ntptime.check_servers({"servers": ["DE.pool.ntp.org.", "192.0.2.1", "2001:db8::1"]}),
                         ["de.pool.ntp.org", "192.0.2.1", "2001:db8::1"])
        self.assertEqual(ntptime.check_servers({"servers": []}), [])

    def test_422(self):
        cases = [({"servers": ["ntp.example.com:123"]}, "servers.0"), ({"servers": ["a b"]}, "servers.0"),
                 ({"servers": ["ok.example", "server x iburst"]}, "servers.1"), ({"servers": [""]}, "servers.0"),
                 ({"servers": ["a.example", "A.example"]}, "servers.1"), ({"servers": "x"}, "servers"),
                 ({"servers": [f"n{i}.example" for i in range(6)]}, "servers"), ({"servers": ["localhost"]}, "servers.0")]
        for body, field in cases:
            with self.subTest(body=body):
                with self.assertRaises(ApiError) as e:
                    ntptime.check_servers(body)
                self.assertIn(field, e.exception.fields)

    def test_chrony_conf(self):
        text = smbconf.chrony(config.Config(), ["de.pool.ntp.org", "ptbtime1.ptb.de", "192.0.2.1"])
        lines = text.splitlines()
        self.assertIn("pool de.pool.ntp.org iburst maxsources 3", lines)
        self.assertIn("server ptbtime1.ptb.de iburst", lines)
        self.assertIn("server 192.0.2.1 iburst", lines)
        for keep in ("local stratum 10", "allow all", "ntpsigndsocket /var/lib/samba/ntp_signd"):
            self.assertIn(keep, lines)
        self.assertFalse(any(x.startswith(("server", "pool")) for x in smbconf.chrony(config.Config(), []).splitlines()))


class ParseTest(unittest.TestCase):
    def test_tracking(self):
        t = ntptime.parse_tracking(TRACKING_SYNCED)
        self.assertEqual((t["ref_name"], t["stratum"], t["correction_s"], t["leap"]), ("192.0.2.1", 2, -0.0034, "Normal"))
        self.assertIsNone(ntptime.parse_tracking(""))
        self.assertEqual(ntptime.parse_tracking(TRACKING_LOCAL)["stratum"], 10)

    def test_real_chrony_output_with_unresolved_pool(self):
        # chronyc 4.x in the CI container right after PUT /api/time (pool not resolved yet, nothing reached)
        n = "^,?,162.159.200.1,0,6,0,4294967295,0.000000000,0.000000000,0.000000000\n"
        names = ("^,?,time.cloudflare.com,0,6,0,4294967295,0.000000000,0.000000000,0.000000000\n"
                 + "^,?,de.pool.ntp.org,0,6,0,4294967295,0.000000000,0.000000000,0.000000000\n" * 4)
        s = ntptime.parse_sources(n, names)
        self.assertEqual(len(s), 5)
        self.assertEqual((s[0]["name"], s[0]["address"], s[0]["reachable"], s[0]["last_rx_s"]),
                         ("time.cloudflare.com", "162.159.200.1", False, None))
        self.assertEqual({(x["name"], x["address"]) for x in s[1:]}, {("de.pool.ntp.org", "")})
        tracking = ntptime.parse_tracking("7F7F0101,,10,1795242512.354182854,0.000000000,0.000000000,0.000000000,"
                                          "0.000,0.000,0.000,0.000000000,0.000000000,0.0,Normal\n")
        ev = ntptime.evaluate(["time.cloudflare.com", "de.pool.ntp.org"], tracking, s, True, 5.0)
        self.assertEqual((ev["status"], ev["synchronized"], ev["offset_ms"]), ("unknown", False, None))

    def test_sources(self):
        s = ntptime.parse_sources(SOURCES_N, SOURCES_NAMES)
        self.assertEqual(s[0], {"address": "192.0.2.1", "name": "de.pool.ntp.org", "stratum": 2, "reachable": True,
                                "selected": True, "offset_ms": 1.8, "last_rx_s": 33})
        self.assertEqual((s[2]["reachable"], s[2]["offset_ms"], s[2]["last_rx_s"]), (False, None, None))
        self.assertEqual(ntptime.parse_sources("", ""), [])


class EvaluateTest(unittest.TestCase):
    SRV = ["de.pool.ntp.org"]

    def ev(self, correction_s, sources=None, running_for=60.0):
        sources = sources if sources is not None else ntptime.parse_sources(SOURCES_N, SOURCES_NAMES)
        tracking = {"ref_id": "x", "ref_name": "x", "stratum": 2, "correction_s": correction_s, "leap": "Normal"}
        return ntptime.evaluate(self.SRV, tracking, sources, True, running_for)

    def test_thresholds(self):
        ok = self.ev(-0.0034)  # clock 3.4 ms fast
        self.assertEqual((ok["status"], ok["offset_ms"], ok["source"], ok["synchronized"]),
                         ("ok", 3.4, "de.pool.ntp.org", True))
        warn = self.ev(-3.4)
        self.assertEqual(warn["status"], "warn")
        self.assertEqual(warn["message"], "Die Uhr des Proxmox-Hosts geht 3,4 s vor. Ab 5 Minuten scheitern "
                                          "Kerberos-Anmeldungen. Zeitsynchronisation auf dem Proxmox-Host prüfen.")
        self.assertEqual(self.ev(-0.999)["status"], "ok")
        self.assertEqual(self.ev(1.0)["status"], "warn")
        late = self.ev(130.0)  # clock slow
        self.assertEqual(late["status"], "error")
        self.assertIn("2,2 min nach", late["message"])
        self.assertIn("scheitern bereits", self.ev(-400.0)["message"])

    def test_unknown_and_unreachable(self):
        unreachable = ntptime.parse_sources(SOURCES_N.splitlines()[2], SOURCES_NAMES.splitlines()[2])
        starting = ntptime.evaluate(self.SRV, None, unreachable, True, 30.0)
        self.assertEqual((starting["status"], starting["offset_ms"]), ("unknown", None))
        late = ntptime.evaluate(self.SRV, None, unreachable, True, 700.0)
        self.assertEqual((late["status"], late["message"]), ("warn", "Kein NTP-Server erreichbar (de.pool.ntp.org)."))
        self.assertEqual(ntptime.evaluate([], None, [], True, 700.0)["status"], "unknown")
        self.assertEqual(ntptime.evaluate(self.SRV, None, [], False, 0.0)["status"], "unknown")

    def test_time_info_never_needs_chrony(self):
        info = ntptime.time_info(self.SRV, False, 0.0, {"running": False, "available": False, "message": ""},
                                 query=lambda *a: self.fail("chronyc must not run"))
        self.assertTrue(info["now"].endswith("Z") and len(info["now"]) == 24)
        self.assertEqual(set(ntptime.compact(info)), {"now", "offset_ms", "source", "synchronized", "status", "message"})
        calls = []
        info = ntptime.time_info(self.SRV, True, 60.0, {}, query=lambda *a: calls.append(a) or {
            ("-c", "-n", "tracking"): TRACKING_SYNCED, ("-c", "-n", "sources"): SOURCES_N,
            ("-c", "-N", "sources"): SOURCES_NAMES}[a])
        self.assertEqual((info["status"], info["offset_ms"], len(info["sources"])), ("ok", 3.4, 3))


if __name__ == "__main__":
    unittest.main()
