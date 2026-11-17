"""Application state: settings, Samba/chrony processes, setup, monitor."""

from __future__ import annotations

import logging
import os
import shutil
import threading

from . import VERSION, events, smbconf, validate
from .directory import Directory
from .errors import NOT_READY, conflict, invalid
from .monitor import DbCheck, Monitor
from .provision import Setup
from .store import load_json, now_ms, save_json, write_text
from .supervisor import Process, probe

log = logging.getLogger("pk95ad.app")

BACKUP_RESUME_AFTER = 600.0

MANIFEST_MENU = [
    {"key": "domain", "label": "Domäne", "icon": "server"},
    {"key": "users", "label": "Benutzer", "icon": "user"},
    {"key": "groups", "label": "Gruppen", "icon": "apps"},
    {"key": "computers", "label": "Computer", "icon": "cpu"},
    {"key": "ous", "label": "Organisationseinheiten", "icon": "box"},
    {"key": "gpo", "label": "Gruppenrichtlinien", "icon": "lock"},
    {"key": "dns", "label": "DNS", "icon": "globe"},
    {"key": "scripts", "label": "Anmeldeskripte", "icon": "terminal"},
]


def manifest() -> dict:
    return {
        "id": "ad", "name": "PK95 AD", "version": VERSION, "protocol": 1, "icon": "key",
        "menu": MANIFEST_MENU, "capabilities": ["events", "backup"], "events": list(events.ALL),
    }


class App:
    def __init__(self, cfg, sender: events.Sender | None = None):
        self.cfg = cfg
        os.makedirs(cfg.data_dir, exist_ok=True)
        self.events = sender or events.Sender(cfg.core_url if cfg.core_mode else "", cfg.token)
        self.started_at = now_ms()
        self.settings = load_json(cfg.path("settings.json"), None)
        self.directory = Directory(cfg, lambda: self.settings)
        self.setup = Setup(self)
        self.monitor = Monitor(self)
        self.dbcheck = DbCheck(self)
        self.samba = Process("samba", self._samba_argv, on_crash=self.monitor.samba_crashed, label="Samba")
        self.chrony = Process("chronyd", self._chrony_argv, label="chronyd")
        self.services = {"ldap": False, "kerberos": False, "smb": False, "dns": False}
        self._backup_timer: threading.Timer | None = None
        self._lock = threading.Lock()

    # state ----------------------------------------------------------------------------------------------

    def state(self) -> str:
        if self.setup.running:
            return "provisioning"
        if self.settings and os.path.exists(os.path.join(self.cfg.samba_dir, "private", "sam.ldb")):
            return "ready"
        if self.setup.state == "failed":
            return "failed"
        return "unconfigured"

    def require_ready(self) -> None:
        if self.state() != "ready":
            raise conflict(NOT_READY)

    def save_settings(self, settings: dict) -> None:
        save_json(self.cfg.path("settings.json"), settings)
        self.settings = settings

    def clear_settings(self) -> None:
        try:
            os.unlink(self.cfg.path("settings.json"))
        except FileNotFoundError:
            pass
        self.settings = None

    # processes ------------------------------------------------------------------------------------------

    def _samba_argv(self) -> list[str]:
        return ["samba", "--foreground", "--no-process-group", "--debug-stdout", "-s", self.cfg.smb_conf]

    def _chrony_argv(self) -> list[str]:
        return ["chronyd", "-d", "-x", "-u", "root", "-f", self.cfg.chrony_conf]

    def prepare_runtime(self) -> None:
        """smb.conf, krb5.conf and chrony.conf from the settings (on every start)."""
        if not self.settings:
            return
        write_text(self.cfg.smb_conf, smbconf.render(self.settings, self.cfg))
        krb = os.path.join(self.cfg.samba_dir, "private", "krb5.conf")
        if os.path.exists(krb):
            try:
                shutil.copyfile(krb, self.cfg.krb5_conf)
            except OSError as exc:
                log.warning("cannot copy krb5.conf: %s", exc)
        signd = os.path.join(self.cfg.samba_dir, "ntp_signd")
        try:
            os.makedirs(signd, exist_ok=True)
            os.chmod(signd, 0o750)
        except OSError as exc:
            log.warning("cannot prepare %s: %s", signd, exc)
        if self.cfg.ntp:
            write_text(self.cfg.chrony_conf, smbconf.chrony(self.cfg))
            if self.cfg.manage_processes:
                os.makedirs("/run/chrony", exist_ok=True)

    def start_services(self) -> None:
        if not self.cfg.manage_processes or self.state() != "ready":
            return
        self.prepare_runtime()
        self.samba.start()
        if self.cfg.ntp:
            self.chrony.start()

    def stop_services(self) -> None:
        self.chrony.stop(timeout=10)
        self.samba.stop(timeout=30)

    def probe(self) -> dict:
        s = self.settings or {}
        self.services = probe(s.get("host_ip", ""), self.cfg.dns_port)
        return self.services

    def update_forwarder(self, body: dict) -> None:
        self.require_ready()
        fwd, err = validate.forwarder(body.get("dns_forwarder"))
        if err:
            raise invalid({"dns_forwarder": err})
        with self._lock:
            settings = dict(self.settings)
            settings["dns_forwarder"] = fwd
            self.save_settings(settings)
            self.prepare_runtime()
            if self.cfg.manage_processes and self.samba.state != "backup":
                self.samba.stop(timeout=30)
                self.samba.start()

    # backup ---------------------------------------------------------------------------------------------

    def backup_prepare(self) -> None:
        if self.state() != "ready" or not self.cfg.manage_processes:
            return
        with self.directory._lock:  # no API transaction may be open while Samba stops
            self.directory.close()
            self.samba.stop(timeout=30, state="backup")
        if self._backup_timer:
            self._backup_timer.cancel()
        self._backup_timer = threading.Timer(BACKUP_RESUME_AFTER, self._resume_after_backup)
        self._backup_timer.daemon = True
        self._backup_timer.start()
        log.info("backup prepared: Samba stopped")

    def _resume_after_backup(self) -> None:
        if self.samba.state == "backup":
            log.warning("no container stop after backup prepare, starting Samba again")
            self.samba.start()

    # lifecycle ------------------------------------------------------------------------------------------

    def boot(self) -> None:
        self.events.start()
        if self.state() == "ready":
            self.start_services()
        self.monitor.start()

    def shutdown(self) -> None:
        self.monitor.stop()
        if self._backup_timer:
            self._backup_timer.cancel()
        self.stop_services()
        self.events.stop()

    def status(self) -> dict:
        st = self.state()
        s = self.settings if st == "ready" else None
        samba = self.samba.info()
        samba["services"] = dict(self.services)
        return {
            "version": VERSION,
            "core_mode": self.cfg.core_mode,
            "state": st,
            "started_at": self.started_at,
            "samba": samba,
            "ntp": {"running": self.chrony.running()},
            "domain": None if not s else {k: s.get(k, "") for k in ("realm", "netbios_domain", "hostname",
                                                                     "host_ip")},
        }
