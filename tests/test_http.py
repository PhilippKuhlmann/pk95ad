"""HTTP layer against an unconfigured app (no Samba needed)."""

import http.client
import json
import tempfile
import threading
import unittest
from unittest import mock

from pk95ad import VERSION, config, httpapi, provision, routes
from pk95ad.app import App

TOKEN = "t" * 48


class HttpTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cfg = config.Config(listen_host="127.0.0.1", listen_port=0, data_dir=cls.tmp.name + "/data",
                            samba_dir=cls.tmp.name + "/samba", smb_conf=cls.tmp.name + "/smb.conf",
                            core_mode=True, token=TOKEN, manage_processes=False)
        cls.app = App(cfg)
        cls.server = httpapi.serve("127.0.0.1", 0, routes.build(cls.app), TOKEN, True)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def call(self, method, path, body=None, token=TOKEN, ctype="application/json"):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if token:
            headers["Authorization"] = "Bearer " + token
        data = None
        if body is not None or method in ("POST", "PUT", "DELETE"):
            data = json.dumps(body if body is not None else {}).encode()
            if ctype:
                headers["Content-Type"] = ctype
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        conn.close()
        try:
            payload = json.loads(raw) if raw else None
        except ValueError:
            payload = raw.decode()
        return resp.status, payload

    def test_health_without_token(self):
        status, body = self.call("GET", "/core/health", token=None)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"ok": True, "version": VERSION, "state": "unconfigured"})

    def test_manifest_needs_token(self):
        self.assertEqual(self.call("GET", "/core/manifest", token=None)[0], 401)
        self.assertEqual(self.call("GET", "/core/manifest", token="x" * 48)[0], 401)
        status, body = self.call("GET", "/core/manifest")
        self.assertEqual(status, 200)
        self.assertEqual(body["id"], "ad")
        self.assertEqual(body["protocol"], 1)
        self.assertEqual([m["key"] for m in body["menu"]],
                         ["domain", "users", "groups", "computers", "ous", "gpo", "dns", "scripts"])
        self.assertIn("ad.user.locked_out", body["events"])
        self.assertEqual(body["capabilities"], ["events", "backup"])

    def test_core_note(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/")
        resp = conn.getresponse()
        self.assertEqual(resp.status, 200)
        self.assertIn("PK95 Core", resp.read().decode())
        conn.close()

    def test_not_ready_routes_answer_409(self):
        for method, path in (("GET", "/api/users"), ("GET", "/api/domain"), ("GET", "/api/gpos"),
                             ("GET", "/api/dns/zones"), ("GET", "/api/scripts"), ("GET", "/api/ous"),
                             ("POST", "/api/users"), ("GET", "/api/domain/dbcheck"),
                             ("GET", "/api/users/5f0e1a6c-0000-0000-0000-000000000001")):
            with self.subTest(path=path):
                status, body = self.call(method, path, {} if method == "POST" else None)
                self.assertEqual(status, 409)
                self.assertEqual(body, {"error": "Die Domäne ist noch nicht eingerichtet."})

    def test_errors(self):
        self.assertEqual(self.call("GET", "/api/nothing")[0], 404)
        self.assertEqual(self.call("GET", "/api/users/not-a-guid")[0], 404)
        self.assertEqual(self.call("DELETE", "/api/status", {})[0], 405)
        status, body = self.call("POST", "/api/setup", {}, ctype="text/plain")
        self.assertEqual(status, 415)
        self.assertIn("error", body)

    def test_catalog_without_domain(self):
        status, body = self.call("GET", "/api/gpos/catalog")
        self.assertEqual(status, 200)
        self.assertIn("screen_lock_minutes", [c["key"] for c in body])

    def test_status(self):
        status, body = self.call("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(body["state"], "unconfigured")
        self.assertIsNone(body["domain"])
        self.assertEqual(body["samba"]["state"], "stopped")

    def test_setup_get_and_validation(self):
        with mock.patch.object(provision, "host_ipv4s", return_value=["192.0.2.10"]):
            status, body = self.call("GET", "/api/setup")
            self.assertEqual(status, 200)
            self.assertEqual(body["state"], "unconfigured")
            self.assertEqual(body["defaults"]["host_ips"], ["192.0.2.10"])
            self.assertEqual(body["defaults"]["dns_forwarder"], "127.0.0.1")
            status, body = self.call("POST", "/api/setup", {
                "realm": "home.local", "netbios_domain": "DC1", "hostname": "dc1", "host_ip": "192.0.2.99",
                "admin_password": "kurz"})
        self.assertEqual(status, 422)
        self.assertEqual(set(body["fields"]), {"realm", "hostname", "host_ip", "admin_password"})

    def test_backup_prepare_before_setup(self):
        self.assertEqual(self.call("POST", "/core/backup/prepare", {})[0], 204)

    def test_invalid_json(self):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("POST", "/api/setup", body=b"{nope", headers={"Authorization": "Bearer " + TOKEN,
                                                                     "Content-Type": "application/json"})
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        resp.read()
        conn.close()


class RouterTest(unittest.TestCase):
    def test_nested_braces(self):
        rx = httpapi.compile_path("/api/gpos/{id:[0-9a-f-]{36}}/links/{target:[0-9a-f-]{36}}")
        m = rx.match("/api/gpos/" + "a" * 36 + "/links/" + "b" * 36)
        self.assertEqual(m.groupdict(), {"id": "a" * 36, "target": "b" * 36})
        self.assertIsNone(rx.match("/api/gpos/catalog/links/x"))

    def test_token_ok(self):
        self.assertTrue(httpapi.token_ok("Bearer " + TOKEN, TOKEN))
        self.assertFalse(httpapi.token_ok("Bearer short", "short"))
        self.assertFalse(httpapi.token_ok("Basic " + TOKEN, TOKEN))
        self.assertFalse(httpapi.token_ok(None, TOKEN))


if __name__ == "__main__":
    unittest.main()
