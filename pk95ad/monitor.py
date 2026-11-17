"""Database check (manual and daily) and the 30-second monitor loop (Samba health, lockouts)."""

from __future__ import annotations

import logging
import re
import subprocess
import threading
import time

from . import events
from .errors import conflict
from .store import load_json, now_ms, save_json

log = logging.getLogger("pk95ad.monitor")

MAX_OUTPUT = 64 * 1024
DAILY_AT = (3, 30)
TICK = 30.0
DOWN_AFTER = 60.0


def count_errors(output: str, rc: int) -> int:
    m = re.findall(r"\((\d+) errors?\)", output)
    if m:
        return int(m[-1])
    return 0 if rc == 0 else 1


class DbCheck:
    def __init__(self, app):
        self.app = app
        self.path = app.cfg.path("dbcheck.json")
        self.data = load_json(self.path, None) or {
            "running": False, "fix": False, "started_at": 0, "finished_at": 0, "ok": None, "errors": 0, "output": "",
        }
        self.data["running"] = False
        self._lock = threading.Lock()

    def info(self) -> dict:
        with self._lock:
            return dict(self.data)

    def start(self, fix: bool) -> None:
        with self._lock:
            if self.data["running"]:
                raise conflict("Die Datenbankprüfung läuft bereits.")
            self.data.update({"running": True, "fix": fix, "started_at": now_ms(), "finished_at": 0})
        threading.Thread(target=self._run, args=(fix,), name="dbcheck", daemon=True).start()

    def _run(self, fix: bool) -> None:
        argv = ["samba-tool", "dbcheck", "--cross-ncs", "-s", self.app.cfg.smb_conf]
        if fix:
            argv += ["--fix", "--yes"]
        try:
            res = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=3600)
            out, rc = (res.stdout or "") + (res.stderr or ""), res.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            out, rc = f"dbcheck konnte nicht ausgeführt werden: {exc}\n", -1
        errors = count_errors(out, rc)
        with self._lock:
            self.data.update({"running": False, "finished_at": now_ms(), "ok": errors == 0, "errors": errors,
                              "output": out[-MAX_OUTPUT:]})
            save_json(self.path, self.data)
        if errors:
            fixed = errors if fix and rc == 0 else 0
            body = f"{errors} Fehler gefunden" + (", repariert." if fix else ". Reparatur in PK95 Core → AD → Domäne.")
            self.app.events.send(events.DBCHECK_FAILED, "warning", "AD-Datenbankprüfung meldet Fehler", body,
                                 {"errors": errors, "fixed": fixed})


class Monitor:
    def __init__(self, app):
        self.app = app
        self.state_path = app.cfg.path("state.json")
        self.state = load_json(self.state_path, None) or {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._fail_since: float | None = None
        self._down_since: float | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def _loop(self) -> None:
        while not self._stop.wait(TICK):
            for step in (self.check_samba, self.check_lockouts, self.check_daily):
                try:
                    step()
                except Exception:  # noqa: BLE001 - the loop must keep running
                    log.exception("monitor step %s failed", step.__name__)

    # Samba health -------------------------------------------------------------------------------------

    def samba_crashed(self, rc, message: str) -> None:
        self._mark_down(message, rc)

    def _mark_down(self, message: str, rc=None) -> None:
        if self._down_since is not None:
            return
        self._down_since = time.monotonic()
        self.app.events.send(events.SAMBA_DOWN, "critical", "Samba (AD) ist ausgefallen", message,
                             {"exit_code": rc, "error": message})

    def check_samba(self) -> None:
        app = self.app
        if app.state() != "ready" or not app.cfg.manage_processes or app.samba.state in ("stopped", "backup"):
            self._fail_since = None
            return
        services = app.probe()
        healthy = app.samba.running() and services["ldap"] and services["kerberos"]
        now = time.monotonic()
        if healthy:
            app.samba.mark_running()
            self._fail_since = None
            if self._down_since is not None:
                down = int(now - self._down_since)
                self._down_since = None
                app.events.send(events.SAMBA_UP, "info", "Samba (AD) läuft wieder",
                                f"Nach {down} Sekunden.", {"down_seconds": down})
            return
        if self._fail_since is None:
            self._fail_since = now
        elif now - self._fail_since >= DOWN_AFTER:
            missing = [k for k in ("ldap", "kerberos") if not services[k]]
            self._mark_down("Samba antwortet nicht (" + ", ".join(missing or ["Prozess"]) + ").")

    # Lockouts -----------------------------------------------------------------------------------------

    def check_lockouts(self) -> None:
        app = self.app
        if app.state() != "ready":
            return
        from . import accounts

        with app.directory.session() as s:
            locked = accounts.locked_users(s)
        seen = self.state.setdefault("lockouts", {})
        current = {u["id"]: u for u in locked}
        changed = False
        for u in locked:
            if seen.get(u["id"]) != u["lockout_time"]:
                seen[u["id"]] = u["lockout_time"]
                changed = True
                from .directory import nt_to_ms

                app.events.send(events.USER_LOCKED_OUT, "warning", f"Konto {u['username']} wurde gesperrt",
                                "Zu viele falsche Kennwörter (Kontosperrungsrichtlinie).",
                                {"user_id": u["id"], "username": u["username"],
                                 "locked_at": nt_to_ms(u["lockout_time"])})
        for gid in list(seen):
            if gid not in current:
                del seen[gid]
                changed = True
        if changed:
            save_json(self.state_path, self.state)

    # Daily dbcheck ------------------------------------------------------------------------------------

    def check_daily(self) -> None:
        app = self.app
        if app.state() != "ready":
            return
        lt = time.localtime()
        today = time.strftime("%Y-%m-%d", lt)
        if "dbcheck_day" not in self.state:
            self.state["dbcheck_day"] = today
            save_json(self.state_path, self.state)
            return
        if (lt.tm_hour, lt.tm_min) < DAILY_AT or self.state.get("dbcheck_day") == today:
            return
        if app.dbcheck.info()["running"]:
            return
        self.state["dbcheck_day"] = today
        save_json(self.state_path, self.state)
        app.dbcheck.start(fix=False)
