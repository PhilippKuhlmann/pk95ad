import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from pk95ad import events


class Core(BaseHTTPRequestHandler):
    received: list = []
    status = 202

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Core.received.append((self.headers.get("Authorization"), body))
        self.send_response(Core.status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


class SenderTest(unittest.TestCase):
    def setUp(self):
        Core.received = []
        Core.status = 202
        self.server = HTTPServer(("127.0.0.1", 0), Core)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_delivers_in_order_with_token(self):
        s = events.Sender(self.url, "tok")
        s.send(events.SAMBA_DOWN, "critical", "down", "b", {"exit_code": 1})
        s.send(events.SAMBA_UP, "info", "up")
        s.deliver()
        self.assertEqual([b["type"] for _, b in Core.received], ["ad.samba.down", "ad.samba.up"])
        self.assertEqual(Core.received[0][0], "Bearer tok")
        self.assertEqual(Core.received[0][1]["data"], {"exit_code": 1})
        self.assertTrue(Core.received[0][1]["occurred_at"].endswith("Z"))
        self.assertEqual(s.pending(), 0)

    def test_keeps_queue_on_error_and_drops_422(self):
        Core.status = 500
        s = events.Sender(self.url, "tok")
        s.send(events.SAMBA_DOWN, "critical", "down")
        s.deliver()
        self.assertEqual(s.pending(), 1)
        Core.status = 422
        s.deliver()
        self.assertEqual(s.pending(), 0)

    def test_drops_after_one_hour(self):
        now = [0.0]
        s = events.Sender("http://127.0.0.1:1", "tok", clock=lambda: now[0])
        s.send(events.SAMBA_DOWN, "critical", "down")
        now[0] = events.MAX_AGE + 1
        s.deliver(timeout=0.5)
        self.assertEqual(s.pending(), 0)

    def test_standalone_drops(self):
        s = events.Sender("", "")
        s.send(events.SAMBA_DOWN, "critical", "down")
        self.assertEqual(s.pending(), 0)


if __name__ == "__main__":
    unittest.main()
