"""End-to-end test against a running PK95 AD container (used by CI).

    python3 tests/integration/run.py <base-url> <token> <container> <events-port>

Provisions a domain through the API, exercises every API area and checks the SYSVOL ACLs inside the
container (user.NTACL, sysvolcheck, SMB access). Exits non-zero on the first failure.
"""

from __future__ import annotations

import json
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE, TOKEN, CONTAINER, EVENTS_PORT = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
REALM = "ad.pk95.test"


def _random_password() -> str:
    # Generated per run: no passwords in the repository. Prefix guarantees the complexity rules.
    return "Pk-9" + secrets.token_urlsafe(18)


PASSWORD = _random_password()
USER_PW_1 = _random_password()
USER_PW_2 = _random_password()
EVENTS: list[dict] = []


class EventSink(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        ok = self.headers.get("Authorization") == "Bearer " + TOKEN
        if ok:
            EVENTS.append(body)
            print(f"  event: {body.get('type')} – {body.get('title')}")
        self.send_response(202 if ok else 401)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "8")
        self.end_headers()
        self.wfile.write(b'{"id":1}')

    def log_message(self, *args):
        pass


def call(method, path, body=None, expect=None):
    data = json.dumps(body if body is not None else {}).encode() if method != "GET" else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        status, raw = exc.code, exc.read()
    payload = json.loads(raw) if raw else None
    if expect is not None and status != expect:
        fail(f"{method} {path}: expected {expect}, got {status}: {json.dumps(payload, ensure_ascii=False)}")
    return status, payload


def fail(msg):
    print("FAIL: " + msg)
    subprocess.run(["docker", "logs", "--tail", "200", CONTAINER])
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)
    print("  ok: " + msg)


def dexec(*argv, ok=True):
    res = subprocess.run(["docker", "exec", CONTAINER, *argv], capture_output=True, text=True)
    out = (res.stdout + res.stderr).strip()
    print(f"  $ {' '.join(argv)} -> {res.returncode}\n" + "\n".join("    " + x for x in out.splitlines()[-15:]))
    if ok and res.returncode != 0:
        fail(f"command failed: {' '.join(argv)}")
    return res.returncode, out


def wait(cond, what, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        v = cond()
        if v:
            return v
        time.sleep(2)
    fail(f"timeout waiting for {what}")


def main():
    sink = ThreadingHTTPServer(("0.0.0.0", EVENTS_PORT), EventSink)
    threading.Thread(target=sink.serve_forever, daemon=True).start()

    print("== health and manifest")
    wait(_alive, "health", 60)
    _, m = call("GET", "/core/manifest", expect=200)
    check(m["id"] == "ad" and m["protocol"] == 1, "manifest")
    check(call("GET", "/api/users")[0] == 409, "users before setup → 409")

    print("== setup")
    _, st = call("GET", "/api/setup", expect=200)
    check(st["state"] == "unconfigured" and st["defaults"]["host_ips"], f"defaults {st['defaults']}")
    ip = st["defaults"]["host_ips"][0]
    call("POST", "/api/setup", {"realm": "x.local", "hostname": "dc1", "host_ip": ip, "admin_password": "a"},
         expect=422)
    call("POST", "/api/setup", {"realm": REALM, "netbios_domain": "PK95TEST", "hostname": "dc1", "host_ip": ip,
                                "dns_forwarder": "127.0.0.1", "admin_password": PASSWORD}, expect=202)
    call("POST", "/api/setup", {"realm": REALM}, expect=409)

    def setup_done():
        _, s = call("GET", "/api/setup")
        return s if s["state"] in ("ready", "failed") else None
    st = wait(setup_done, "provisioning", 900)
    print("\n".join("    | " + line for line in st["log"]))
    check(st["state"] == "ready", f"setup ready (error: {st['error']})")
    check(any("user.NTACL" in line and "Warnung" not in line for line in st["log"]), "SYSVOL ACL in user.NTACL")
    wait(lambda: call("GET", "/api/status")[1]["samba"]["services"]["ldap"], "Samba LDAP", 180)
    _, status = call("GET", "/api/status", expect=200)
    check(status["samba"]["state"] == "running", f"samba running: {status['samba']}")
    check(all(status["samba"]["services"].values()), f"services {status['samba']['services']}")

    print("== domain")
    _, d = call("GET", "/api/domain", expect=200)
    check(d["realm"] == REALM and d["netbios_domain"] == "PK95TEST", "realm/netbios")
    check(d["fsmo"]["pdc"] == "dc1" and d["dns_port"] == 5300, f"fsmo {d['fsmo']}")
    check(d["domain_level"] == "2008_R2", "domain level")
    _, pp = call("PUT", "/api/domain/password-policy", {"min_length": 10, "lockout_threshold": 3,
                                                          "lockout_duration_minutes": 15,
                                                          "lockout_window_minutes": 15}, expect=200)
    check(pp["min_length"] == 10 and pp["lockout_threshold"] == 3 and pp["lockout_duration_minutes"] == 15,
          f"password policy {pp}")
    call("PUT", "/api/domain/password-policy", {"lockout_window_minutes": 30}, expect=422)

    print("== OUs")
    _, firma = call("POST", "/api/ous", {"name": "Firma", "description": "Test"}, expect=201)
    _, vertrieb = call("POST", "/api/ous", {"name": "Vertrieb", "parent_id": firma["id"]}, expect=201)
    call("POST", "/api/ous", {"name": "Vertrieb", "parent_id": firma["id"]}, expect=422)
    _, vertrieb = call("PUT", f"/api/ous/{vertrieb['id']}", {"name": "Verkauf"}, expect=200)
    check(vertrieb["path"] == "Firma/Verkauf", f"OU path {vertrieb['path']}")
    _, tree = call("GET", "/api/ous", expect=200)
    names = [c["name"] for c in tree["children"]]
    check({"Users", "Computers", "Domain Controllers", "Firma"} <= set(names), f"tree {names}")
    users_container = next(c for c in tree["children"] if c["name"] == "Users")
    call("DELETE", f"/api/ous/{users_container['id']}", expect=403)

    print("== groups")
    _, team = call("POST", "/api/groups", {"name": "Verkauf-Team", "ou_id": vertrieb["id"]}, expect=201)
    _, alle = call("POST", "/api/groups", {"name": "Alle-Mitarbeiter", "scope": "universal",
                                           "member_ids": [team["id"]]}, expect=201)
    check(alle["members"][0]["id"] == team["id"], "nested group member")
    call("PUT", f"/api/groups/{team['id']}/members", {"member_ids": [alle["id"]]}, expect=422)
    _, groups = call("GET", "/api/groups?search=domain%20admins", expect=200)
    da = next(g for g in groups["items"] if g["name"] == "Domain Admins")
    check(da["builtin"], "Domain Admins is builtin")
    call("DELETE", f"/api/groups/{da['id']}", expect=403)

    print("== users")
    _, u = call("POST", "/api/users", {"username": "max", "given_name": "Max", "surname": "Muster",
                                       "email": "max@example.com", "ou_id": vertrieb["id"], "password": "kurz",
                                       "group_ids": [team["id"]]}, expect=422)
    check("password" in u["fields"], f"weak password rejected: {u['fields']}")
    _, u = call("POST", "/api/users", {"username": "max", "given_name": "Max", "surname": "Muster",
                                       "email": "max@example.com", "ou_id": vertrieb["id"],
                                       "password": USER_PW_1, "must_change_password": True,
                                       "script_path": "logon.bat", "group_ids": [team["id"]]}, expect=201)
    check(u["upn"] == f"max@{REALM}" and u["must_change_password"] and u["ou_path"] == "Firma/Verkauf",
          f"user {u['upn']} {u['ou_path']}")
    check([g["name"] for g in u["groups"]] == ["Verkauf-Team"], "user groups")
    call("POST", "/api/users", {"username": "max", "given_name": "X", "password": _random_password()}, expect=422)
    _, u = call("PUT", f"/api/users/{u['id']}", {"enabled": False, "description": "Test",
                                                 "display_name": "Max Mustermann"}, expect=200)
    check(not u["enabled"] and u["display_name"] == "Max Mustermann", "user update")
    call("POST", f"/api/users/{u['id']}/password", {"password": USER_PW_2}, expect=204)
    _, u = call("GET", f"/api/users/{u['id']}", expect=200)
    check(not u["enabled"], "password reset keeps account disabled")
    call("POST", f"/api/users/{u['id']}/unlock", expect=204)
    _, g = call("PUT", f"/api/users/{u['id']}/groups", {"group_ids": [alle["id"]]}, expect=200)
    check([x["name"] for x in g["groups"]] == ["Alle-Mitarbeiter"], "replace groups")
    _, lst = call("GET", "/api/users?search=muster", expect=200)
    check(lst["total"] == 1, "user search")
    _, admin = call("GET", "/api/users?search=administrator", expect=200)
    admin_id = admin["items"][0]["id"]
    call("PUT", f"/api/users/{admin_id}", {"enabled": False}, expect=403)
    _, eff = call("GET", f"/api/groups/{alle['id']}", expect=200)
    check(any(x["username"] == "max" for x in eff["effective_users"]), "effective users")

    print("== computers")
    _, comps = call("GET", "/api/computers", expect=200)
    dc = next(c for c in comps["items"] if c["is_dc"])
    check(dc["name"].lower() == "dc1", "DC listed")
    call("DELETE", f"/api/computers/{dc['id']}", expect=403)

    print("== DNS")
    _, zones = call("GET", "/api/dns/zones", expect=200)
    check({REALM, f"_msdcs.{REALM}"} <= {z["name"] for z in zones}, f"zones {[z['name'] for z in zones]}")
    _, rec = call("POST", f"/api/dns/zones/{REALM}/records",
                  {"name": f"nas.{REALM}", "type": "A", "value": "192.0.2.20"}, expect=201)
    call("POST", f"/api/dns/zones/{REALM}/records", {"name": f"nas.{REALM}", "type": "CNAME",
                                                     "value": f"dc1.{REALM}"}, expect=422)
    _, rec = call("PUT", f"/api/dns/zones/{REALM}/records/{rec['id']}",
                  {"name": f"nas.{REALM}", "type": "A", "value": "192.0.2.21", "ttl": 300}, expect=200)
    call("POST", f"/api/dns/zones/{REALM}/records", {"name": f"_sip._tcp.{REALM}", "type": "SRV",
                                                     "value": f"nas.{REALM}", "port": 5060, "priority": 10},
         expect=201)
    _, recs = call("GET", f"/api/dns/zones/{REALM}/records", expect=200)
    check(any(r["name"] == f"nas.{REALM}" and r["value"] == "192.0.2.21" and r["ttl"] == 300 for r in recs),
          "A record updated")
    soa = next(r for r in recs if r["type"] == "SOA")
    call("DELETE", f"/api/dns/zones/{REALM}/records/{soa['id']}", expect=403)
    call("DELETE", f"/api/dns/zones/{REALM}/records/{rec['id']}", expect=204)
    dexec("sh", "-c", f"host -p 5300 -t A dc1.{REALM} 127.0.0.1 || nslookup -port=5300 dc1.{REALM} 127.0.0.1")

    print("== Group Policy")
    _, gpos = call("GET", "/api/gpos", expect=200)
    check(any(g["name"] == "Default Domain Policy" and g["builtin"] and g["sysvol_ok"] for g in gpos),
          "Default Domain Policy")
    _, gp = call("POST", "/api/gpos", {"name": "PK95 Test"}, expect=201)
    check(gp["sysvol_ok"] and gp["version"] == {"computer": 0, "user": 0}, "new GPO")
    call("POST", "/api/gpos", {"name": "pk95 test"}, expect=422)
    _, gp = call("PUT", f"/api/gpos/{gp['id']}/settings", {"settings": {
        "screen_lock_minutes": 10, "removable_storage_deny": True, "deny_cmd": True,
        "windows_update_mode": "auto", "windows_update_day": 0, "windows_update_hour": 3,
        "logon_scripts": [{"path": "logon.bat", "parameters": ""}]}}, expect=200)
    check(gp["settings"]["screen_lock_minutes"] == 10 and gp["settings"]["removable_storage_deny"] is True,
          "settings read back")
    check(gp["version"] == {"computer": 1, "user": 1} and gp["sysvol_ok"], f"version bump {gp['version']}")
    _, gp = call("PUT", f"/api/gpos/{gp['id']}/settings", {"settings": {"screen_lock_minutes": 15}}, expect=200)
    check(gp["version"] == {"computer": 1, "user": 2}, f"only user half bumped {gp['version']}")
    call("POST", f"/api/gpos/{gp['id']}/links", {"target_id": vertrieb["id"], "enforced": True}, expect=201)
    call("POST", f"/api/gpos/{gp['id']}/links", {"target_id": users_container["id"]}, expect=422)
    call("PUT", f"/api/ous/{vertrieb['id']}", {"block_inheritance": True}, expect=200)
    _, inh = call("GET", f"/api/ous/{vertrieb['id']}/gpo-inheritance", expect=200)
    check([i["name"] for i in inh["items"]] == ["PK95 Test"], f"inheritance {inh}")
    call("PUT", f"/api/ous/{vertrieb['id']}", {"block_inheritance": False}, expect=200)
    _, inh = call("GET", f"/api/ous/{vertrieb['id']}/gpo-inheritance", expect=200)
    check([i["name"] for i in inh["items"]][:1] == ["PK95 Test"] and len(inh["items"]) == 2,
          f"inheritance without block {[i['name'] for i in inh['items']]}")
    guid = gp["guid"]
    dexec("samba-tool", "gpo", "listall")
    dexec("sh", "-c", f"ls -la /var/lib/samba/sysvol/{REALM}/Policies/{guid}/* && "
                      f"cat /var/lib/samba/sysvol/{REALM}/Policies/{guid}/GPT.INI")
    dexec("samba-tool", "gpo", "show", guid, "-H", "ldap://127.0.0.1", "-U", f"Administrator%{PASSWORD}")
    dexec("samba-tool", "gpo", "aclcheck", "-H", "ldap://127.0.0.1", "-U", f"Administrator%{PASSWORD}", ok=False)
    dexec("smbclient", f"//127.0.0.1/sysvol", "-U", f"PK95TEST\\max%{USER_PW_2}", "-c",
          f"ls {REALM}\\Policies\\{guid}\\*", ok=False)  # max is disabled → expected to fail
    dexec("smbclient", f"//127.0.0.1/sysvol", "-U", f"PK95TEST\\Administrator%{PASSWORD}", "-c",
          f"ls {REALM}\\Policies\\{guid}\\User\\*")

    print("== NETLOGON scripts")
    _, sc = call("PUT", "/api/scripts/logon.bat", {"content": "@echo off\nnet use H: \\\\nas\\home\n"},
                 expect=200)
    check("\r" not in sc["content"] and sc["size"] > 0, "script stored")
    _, scripts = call("GET", "/api/scripts", expect=200)
    check([s["name"] for s in scripts] == ["logon.bat"], "script list")
    call("PUT", "/api/scripts/x.exe", {"content": "x"}, expect=422)

    print("== SYSVOL ACLs in user.NTACL")
    dexec("getfattr", "-n", "user.NTACL", "--only-values", "-e", "hex", f"/var/lib/samba/sysvol/{REALM}/Policies")
    rc, _ = dexec("getfattr", "-n", "security.NTACL", f"/var/lib/samba/sysvol/{REALM}/Policies", ok=False)
    check(rc != 0, "no security.NTACL (not writable in this container)")
    dexec("samba-tool", "ntacl", "sysvolcheck")
    dexec("smbclient", "//127.0.0.1/netlogon", "-U", f"PK95TEST\\Administrator%{PASSWORD}", "-c", "ls")

    print("== cleanup and move")
    _, other = call("POST", "/api/ous", {"name": "Andere"}, expect=201)
    call("POST", "/api/move", {"ids": [u["id"], team["id"]], "target_id": other["id"]}, expect=200)
    _, u = call("GET", f"/api/users/{u['id']}", expect=200)
    check(u["ou_path"] == "Andere", "moved user")
    call("DELETE", f"/api/ous/{other['id']}", expect=409)
    call("DELETE", f"/api/gpos/{gp['id']}", expect=204)
    call("DELETE", f"/api/ous/{other['id']}?recursive=1", expect=204)
    call("DELETE", f"/api/ous/{firma['id']}?recursive=1", expect=204)
    call("DELETE", f"/api/scripts/logon.bat", expect=204)

    print("== dbcheck")
    call("POST", "/api/domain/dbcheck", {"fix": False}, expect=202)
    res = wait(lambda: (lambda r: r if not r["running"] else None)(call("GET", "/api/domain/dbcheck")[1]),
               "dbcheck", 600)
    print("    " + "\n    ".join(res["output"].splitlines()[-5:]))
    check(res["ok"] is True, f"dbcheck ok ({res['errors']} errors)")

    print("== backup prepare and restart")
    call("POST", "/core/backup/prepare", expect=204)
    _, status = call("GET", "/api/status", expect=200)
    check(status["samba"]["state"] == "backup", "samba stopped for backup")
    subprocess.run(["docker", "restart", CONTAINER], check=True)
    time.sleep(2)
    wait(_alive, "health after restart", 120)
    wait(lambda: call("GET", "/api/status")[1]["samba"]["services"]["ldap"], "LDAP after restart", 180)
    _, u2 = call("GET", "/api/users?search=administrator", expect=200)
    check(u2["total"] == 1, "data survived restart")

    types = {e["type"] for e in EVENTS}
    if "ad.setup.done" in types:
        print("  ok: event ad.setup.done delivered to Core")
    else:
        print("  WARN: no ad.setup.done event received (container could not reach the runner?)")
    print("ALL OK")


def _alive():
    try:
        with urllib.request.urlopen(BASE + "/core/health", timeout=5) as resp:
            return resp.status == 200
    except OSError:
        return False


if __name__ == "__main__":
    main()
