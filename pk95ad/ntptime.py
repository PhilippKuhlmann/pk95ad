"""DC time and NTP reference servers (docs/api.md → Time, docs/design.md → Time).

chronyd runs with -x in the LXC: it never sets the clock (that belongs to the Proxmox host). The configured
servers are a reference: chrony measures the host clock against them; the app reports the offset and warns.
Domain members keep getting signed NTP from chronyd; with -x it serves its estimate of true time.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from datetime import datetime, timezone

from .errors import Fields

DEFAULT_SERVERS = ["de.pool.ntp.org"]
MAX_SERVERS = 5
WARN_S = 1.0
ERROR_S = 120.0
KERBEROS_S = 300.0
STARTUP_S = 600.0  # no reachable source this long after the start → warn
CHRONYC_TIMEOUT = 1.5
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


# --- settings ----------------------------------------------------------------------------------------

def _server_error(value) -> tuple[str, str | None]:
    if not isinstance(value, str) or not value.strip():
        return "", "Bitte einen Hostnamen oder eine IP-Adresse angeben."
    v = value.strip().lower().rstrip(".")
    try:
        return str(ipaddress.ip_address(v)), None
    except ValueError:
        pass
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(x) for x in labels) or labels[-1].isdigit():
        return v, "Ungültiger Server: Hostname (z. B. de.pool.ntp.org) oder IP-Adresse, ohne Port und Optionen."
    return v, None


def check_servers(body) -> list[str]:
    f = Fields()
    servers = body.get("servers") if isinstance(body, dict) else None
    if not isinstance(servers, list):
        f.add("servers", "Bitte eine Liste von Servern angeben (leer = keine Referenz).")
        f.raise_if_any()
    if len(servers) > MAX_SERVERS:
        f.add("servers", f"Höchstens {MAX_SERVERS} Server.")
    out: list[str] = []
    for i, value in enumerate(servers):
        v, err = _server_error(value)
        if not err and v in out:
            err = "Dieser Server steht schon in der Liste."
        f.add(f"servers.{i}", err)
        out.append(v)
    f.raise_if_any()
    return out


def chrony_lines(servers: list[str]) -> list[str]:
    """server/pool lines for chrony.conf."""
    return [f"pool {s} iburst maxsources 3" if "pool.ntp.org" in s else f"server {s} iburst" for s in servers]


# --- chronyc CSV -------------------------------------------------------------------------------------

def parse_tracking(text: str) -> dict | None:
    """chronyc -c tracking: ref id, ref name, stratum, ref time, correction (s, positive = clock slow), …, leap."""
    line = next((x for x in (text or "").splitlines() if x.count(",") >= 13), None)
    if line is None:
        return None
    p = line.split(",")
    try:
        return {"ref_id": p[0], "ref_name": p[1], "stratum": int(p[2]), "correction_s": float(p[4]),
                "leap": p[13].strip()}
    except (ValueError, IndexError):
        return None


def parse_sources(text_n: str, text_names: str) -> list[dict]:
    """chronyc -c -n sources (addresses) and chronyc -c -N sources (configured names), same order.

    Fields: mode, state (* selected), address, stratum, poll, reach (octal), last rx (s), adjusted offset (s,
    positive = local clock ahead), measured offset, error.
    """
    rows = [x.split(",") for x in (text_n or "").splitlines() if x.count(",") >= 9]
    names = [x.split(",") for x in (text_names or "").splitlines() if x.count(",") >= 9]
    out = []
    for i, p in enumerate(rows):
        if p[0] not in ("^", "="):
            continue  # refclocks and peers are not ours
        try:
            reach = int(p[5], 8)
        except ValueError:
            reach = 0
        try:
            last_rx = int(p[6])
        except ValueError:
            last_rx = None
        try:
            offset_ms = round(float(p[7]) * 1000, 3)
        except ValueError:
            offset_ms = None
        out.append({
            "address": p[2],
            "name": names[i][2] if i < len(names) else p[2],
            "stratum": int(p[3]) if p[3].isdigit() else 0,
            "reachable": reach != 0,
            "selected": p[1] == "*",
            "offset_ms": offset_ms if reach else None,
            "last_rx_s": last_rx if reach else None,
        })
    return out


def run_chronyc(*args: str) -> str:
    try:
        res = subprocess.run(["chronyc", *args], capture_output=True, text=True, timeout=CHRONYC_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return res.stdout if res.returncode == 0 else ""


# --- status ------------------------------------------------------------------------------------------

def _amount(seconds: float) -> str:
    a = abs(seconds)
    if a < 120:
        return f"{a:.1f}".replace(".", ",") + " s"
    return f"{a / 60:.1f}".replace(".", ",") + " min"


def offset_message(offset_s: float) -> str:
    kerberos = ("Kerberos-Anmeldungen scheitern bereits (Grenze 5 Minuten)." if abs(offset_s) >= KERBEROS_S
                else "Ab 5 Minuten scheitern Kerberos-Anmeldungen.")
    return (f"Die Uhr des Proxmox-Hosts geht {_amount(offset_s)} {'vor' if offset_s > 0 else 'nach'}. {kerberos} "
            "Zeitsynchronisation auf dem Proxmox-Host prüfen.")


def evaluate(servers: list[str], tracking: dict | None, sources: list[dict], running: bool,
             running_for_s: float) -> dict:
    """synchronized, offset_ms, source, status, message."""
    selected = next((s for s in sources if s["selected"]), None)
    out = {"synchronized": selected is not None, "offset_ms": None, "source": "", "status": "unknown", "message": ""}
    if not servers:
        out["message"] = "Kein NTP-Referenzserver eingestellt. Die Uhr des Proxmox-Hosts wird nicht geprüft."
        return out
    if not running:
        out["message"] = "Der NTP-Dienst läuft nicht."
        return out
    if selected is None:
        if running_for_s >= STARTUP_S and not any(s["reachable"] for s in sources):
            out.update(status="warn", message=f"Kein NTP-Server erreichbar ({', '.join(servers)}).")
        else:
            out["message"] = "Der Abgleich mit den NTP-Servern läuft noch."
        return out
    if tracking is not None:
        offset_s = -tracking["correction_s"]  # correction > 0: clock slow
    elif selected["offset_ms"] is not None:
        offset_s = selected["offset_ms"] / 1000
    else:
        return out
    out["offset_ms"] = round(offset_s * 1000, 3)
    out["source"] = selected["name"]
    if abs(offset_s) >= ERROR_S:
        out.update(status="error", message=offset_message(offset_s))
    elif abs(offset_s) >= WARN_S:
        out.update(status="warn", message=offset_message(offset_s))
    else:
        out["status"] = "ok"
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def time_info(servers: list[str], running: bool, running_for_s: float, serving: dict, query=run_chronyc) -> dict:
    """GET /api/time. Never blocks for long: every chronyc call has a short timeout."""
    tracking = sources = None
    if running:
        tracking = parse_tracking(query("-c", "-n", "tracking"))
        sources = parse_sources(query("-c", "-n", "sources"), query("-c", "-N", "sources"))
    ev = evaluate(servers, tracking, sources or [], running, running_for_s)
    return {"now": now_iso(), "servers": list(servers), "sources": sources or [], **ev, "serving": serving}


def compact(info: dict) -> dict:
    return {k: info[k] for k in ("now", "offset_ms", "source", "synchronized", "status", "message")}
