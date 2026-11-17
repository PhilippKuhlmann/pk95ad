"""First start: validate the wizard input and provision a new domain (docs/api.md → Setup)."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import secrets
import shutil
import socket
import subprocess
import threading
import time
import traceback

from . import events, validate
from .errors import ApiError, Fields, conflict
from .store import load_json, now_ms, save_json
from .supervisor import tcp_open

log = logging.getLogger("pk95ad.setup")

MAX_LOG = 200
SKIP_IFACES = ("docker", "br-", "veth", "virbr", "cni", "flannel", "cali", "vxlan", "kube")


class SetupError(Exception):
    """A failed setup step with a German message."""


def host_ipv4s() -> list[str]:
    """Global IPv4 addresses of the host network (no loopback, Docker bridges or link-local)."""
    try:
        res = subprocess.run(["ip", "-j", "-4", "addr", "show"], capture_output=True, text=True, timeout=5)
        data = json.loads(res.stdout or "[]")
    except (OSError, ValueError, subprocess.TimeoutExpired):
        data = []
    ips = set()
    for iface in data:
        name = iface.get("ifname", "")
        if name == "lo" or name.startswith(SKIP_IFACES):
            continue
        for a in iface.get("addr_info", []):
            if a.get("family") != "inet" or a.get("scope") != "global":
                continue
            try:
                ip = ipaddress.IPv4Address(a.get("local", ""))
            except ValueError:
                continue
            if not ip.is_link_local and not ip.is_loopback:
                ips.add(str(ip))
    return sorted(ips, key=lambda x: ipaddress.IPv4Address(x))


def default_hostname() -> str:
    name = socket.gethostname().split(".")[0].lower()
    v, err = validate.dc_hostname(name)
    return "dc1" if err or v in ("localhost", "") else v


def check_request(body: dict, host_ips: list[str]) -> dict:
    f = Fields()
    realm, err = validate.realm(body.get("realm"))
    f.add("realm", err)
    nb_in = body.get("netbios_domain") or (realm.split(".")[0] if realm and not err else "")
    netbios, err = validate.netbios_domain(nb_in)
    f.add("netbios_domain", err)
    host, err = validate.dc_hostname(body.get("hostname"))
    f.add("hostname", err)
    if host and netbios and host.upper() == netbios:
        f.add("hostname", "Der Name des Domänencontrollers muss sich vom NetBIOS-Namen der Domäne unterscheiden.")
    ip, err = validate.ipv4(body.get("host_ip"))
    f.add("host_ip", err)
    if not err and ip not in host_ips:
        f.add("host_ip", "Diese Adresse gehört nicht zu diesem Host.")
    fwd, err = validate.forwarder(body.get("dns_forwarder") or "127.0.0.1")
    f.add("dns_forwarder", err)
    pw, err = validate.password(body.get("admin_password"), "Administrator")
    f.add("admin_password", err)
    f.raise_if_any()
    return {"realm": realm, "netbios_domain": netbios, "hostname": host, "host_ip": ip, "dns_forwarder": fwd,
            "admin_password": pw}


def check_filesystem(samba_dir: str, say) -> None:
    """user.* xattrs and POSIX ACLs are required (NT ACLs go to user.NTACL, see docs/design.md)."""
    os.makedirs(samba_dir, exist_ok=True)
    test = os.path.join(samba_dir, ".pk95ad-fscheck")
    with open(test, "w", encoding="utf-8") as fh:
        fh.write("x")
    try:
        try:
            os.setxattr(test, "security.pk95ad", b"1")
            say("security.*-Attribute: verfügbar (NT-ACLs liegen trotzdem in user.NTACL).")
        except OSError as exc:
            say(f"security.*-Attribute: nicht verfügbar ({exc.strerror}) – erwartet im unprivilegierten LXC; "
                "NT-ACLs liegen in user.NTACL.")
        try:
            os.setxattr(test, "user.pk95ad", b"1")
            if os.getxattr(test, "user.pk95ad") != b"1":
                raise OSError(0, "Wert stimmt nicht")
        except OSError as exc:
            raise SetupError(f"Das Dateisystem unter {samba_dir} unterstützt keine erweiterten Attribute (user.*): "
                             f"{exc.strerror}. Samba speichert dort die Windows-Berechtigungen.") from exc
        res = subprocess.run(["setfacl", "-m", "u:nobody:r", test], capture_output=True, text=True)
        if res.returncode != 0:
            raise SetupError(f"Das Dateisystem unter {samba_dir} unterstützt keine POSIX-ACLs: "
                             f"{(res.stderr or '').strip()}. Bei ZFS: acltype=posixacl setzen.")
        say("user.*-Attribute und POSIX-ACLs: in Ordnung.")
    finally:
        try:
            os.unlink(test)
        except OSError:
            pass


def wipe(cfg) -> None:
    for d in (cfg.samba_dir, cfg.cache_dir):
        if not os.path.isdir(d):
            continue
        for entry in os.listdir(d):
            p = os.path.join(d, entry)
            if os.path.isdir(p) and not os.path.islink(p):
                shutil.rmtree(p)
            else:
                os.unlink(p)
    for p in (cfg.smb_conf,):
        try:
            os.unlink(p)
        except FileNotFoundError:
            pass


class Setup:
    def __init__(self, app):
        self.app = app
        self.path = app.cfg.path("setup.json")
        data = load_json(self.path, {}) or {}
        self.state = data.get("state", "")
        self.error = data.get("error", "")
        self.started_at = data.get("started_at", 0)
        self.finished_at = data.get("finished_at", 0)
        self.log: list[str] = list(data.get("log", []))[-MAX_LOG:]
        self.running = False
        self._lock = threading.Lock()
        if self.state == "provisioning":
            self.state = "failed"
            self.error = "Die Einrichtung wurde unterbrochen (Neustart). Bitte erneut starten."

    def info(self) -> dict:
        st = self.app.state()
        domain = None
        if st == "ready" and self.app.settings:
            s = self.app.settings
            domain = {k: s.get(k, "") for k in ("realm", "netbios_domain", "hostname", "host_ip")}
        return {
            "state": st,
            "error": self.error if st == "failed" else "",
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "log": list(self.log),
            "defaults": {"hostname": default_hostname(), "host_ips": host_ipv4s(), "dns_forwarder": "127.0.0.1"},
            "domain": domain,
        }

    def _save(self) -> None:
        save_json(self.path, {"state": self.state, "error": self.error, "started_at": self.started_at,
                              "finished_at": self.finished_at, "log": self.log})

    def say(self, line: str) -> None:
        log.info("setup: %s", line)
        self.log.append(line)
        del self.log[:-MAX_LOG]

    def start(self, body: dict) -> None:
        with self._lock:
            st = self.app.state()
            if st == "provisioning":
                raise conflict("Die Einrichtung läuft bereits.")
            if st == "ready":
                raise conflict("Die Domäne ist schon eingerichtet.")
            req = check_request(body, host_ipv4s())
            self.running = True
            self.state = "provisioning"
            self.error = ""
            self.started_at = now_ms()
            self.finished_at = 0
            self.log = []
            self._save()
        threading.Thread(target=self._run, args=(req,), name="setup", daemon=True).start()

    def _exec(self, argv: list[str], redact=(), timeout: int = 900) -> int:
        shown = " ".join(argv)
        for r in redact:
            shown = shown.replace(r, "********")
        self.say("$ " + shown)
        p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, errors="replace")
        timer = threading.Timer(timeout, p.kill)
        timer.start()
        try:
            assert p.stdout is not None
            for line in p.stdout:
                line = line.rstrip()
                for r in redact:
                    line = line.replace(r, "********")
                if line:
                    self.say(line)
            return p.wait()
        finally:
            timer.cancel()

    def _run(self, req: dict) -> None:
        app = self.app
        cfg = app.cfg
        try:
            self.say("Prüfe das Dateisystem …")
            check_filesystem(cfg.samba_dir, self.say)
            self.say("Entferne Reste früherer Versuche …")
            app.stop_services()
            app.directory.close()
            wipe(cfg)

            settings = {k: req[k] for k in ("realm", "netbios_domain", "hostname", "host_ip", "dns_forwarder")}
            from .smbconf import provision_options

            # Provision with a random password, then set the real one through SamDB, so the
            # administrator password never shows up in a command line or the log.
            tmp = secrets.token_urlsafe(24) + "aA1!"
            argv = ["samba-tool", "domain", "provision", "--server-role=dc", "--use-rfc2307",
                    "--dns-backend=SAMBA_INTERNAL", f"--realm={settings['realm'].upper()}",
                    f"--domain={settings['netbios_domain']}", f"--adminpass={tmp}",
                    f"--host-name={settings['hostname']}", f"--host-ip={settings['host_ip']}"]
            argv += [f"--option={o}" for o in provision_options(settings, cfg)]
            rc = self._exec(argv, redact=[tmp])
            if rc != 0:
                raise SetupError(f"samba-tool domain provision ist fehlgeschlagen (Code {rc}). "
                                 "Details stehen im Protokoll.")

            settings["provisioned_at"] = now_ms()
            app.save_settings(settings)
            app.prepare_runtime()

            self.say("Setze das Kennwort von Administrator …")
            with app.directory.session() as s:
                res = s.search(expression="(sAMAccountName=Administrator)", attrs=["dn"])
                if not len(res):
                    raise SetupError("Das Konto Administrator fehlt nach der Einrichtung.")
                s.replace(res[0].dn, {"unicodePwd": ('"' + req["admin_password"] + '"').encode("utf-16-le")})

            # sysvolcheck cannot be used: it reads security.NTACL directly and ignores
            # acl_xattr:security_acl_name. sysvolreset and "ntacl get" go through the VFS and honour it.
            self.say("Setze die SYSVOL-Berechtigungen …")
            if self._exec(["samba-tool", "ntacl", "sysvolreset", "-s", cfg.smb_conf], timeout=300) != 0:
                raise SetupError("Die SYSVOL-Berechtigungen konnten nicht gesetzt werden.")
            sysvol_dir = os.path.join(cfg.samba_dir, "sysvol", settings["realm"].lower())
            try:
                os.getxattr(sysvol_dir, "user.NTACL")
            except OSError as exc:
                raise SetupError(f"Die NT-ACL von SYSVOL fehlt in user.NTACL ({exc.strerror}).") from exc
            if self._exec(["samba-tool", "ntacl", "get", "--as-sddl", "-s", cfg.smb_conf, sysvol_dir],
                          timeout=60) != 0:
                self.say("Warnung: samba-tool ntacl get kann die NT-ACL von SYSVOL nicht lesen.")
            else:
                self.say("NT-ACL von SYSVOL liegt in user.NTACL und ist lesbar.")

            with self._lock:
                self.state = "ready"
                self.running = False
                self.finished_at = now_ms()
                self._save()

            self.say("Starte Samba …")
            app.start_services()
            ok = False
            if cfg.manage_processes:
                for _ in range(90):
                    if tcp_open(settings["host_ip"], 389) and tcp_open(settings["host_ip"], 88):
                        ok = True
                        break
                    time.sleep(1)
            self.say("Samba läuft." if ok else "Warnung: Samba antwortet noch nicht auf LDAP/Kerberos.")
            self._save()
            app.events.send(events.SETUP_DONE, "info", f"Domäne {settings['realm']} eingerichtet",
                            f"Domänencontroller {settings['hostname']}.{settings['realm']} ({settings['host_ip']}).",
                            {"realm": settings["realm"], "netbios_domain": settings["netbios_domain"],
                             "dc": f"{settings['hostname']}.{settings['realm']}"})
        except SetupError as exc:
            self._fail(str(exc))
        except ApiError as exc:
            detail = "; ".join(f"{v}" for v in (exc.fields or {}).values())
            self._fail(exc.message + (f" {detail}" if detail else ""))
        except Exception as exc:  # noqa: BLE001 - report every failure in the wizard
            log.error("setup failed\n%s", traceback.format_exc())
            self._fail(f"Unerwarteter Fehler: {exc}")

    def _fail(self, message: str) -> None:
        self.say("Fehler: " + message)
        try:
            self.app.stop_services()
        except Exception:  # noqa: BLE001
            pass
        self.app.directory.close()
        self.app.clear_settings()
        with self._lock:
            self.state = "failed"
            self.error = message
            self.running = False
            self.finished_at = now_ms()
            self._save()
        self.app.events.send(events.SETUP_FAILED, "critical", "Einrichtung der Domäne fehlgeschlagen", message,
                             {"error": message})
