"""The DC resolves through PK95 DNS (docs/design.md → DNS of the DC itself).

With host network the container gets a copy of the LXC's /etc/resolv.conf, usually the router, which does not
know the AD zone. samba_dnsupdate checks its records through that resolver, finds nothing and tries to add
every record again ("Record already exists"). PK95 DNS on 127.0.0.1:53 forwards the realm to Samba, so the app
puts it first - but only once it really answers the zone. The LXC's resolvers stay as fallback.
"""

from __future__ import annotations

import ipaddress
import logging
import random
import socket
import struct

log = logging.getLogger("pk95ad.resolver")

PATH = "/etc/resolv.conf"
MARK = "# Written by PK95 AD"
ORIGINAL = "# pk95ad-original: "
LOCAL = "127.0.0.1"
MAXNS = 3  # glibc reads at most three nameservers


def query_soa(zone: str, server: str = LOCAL, port: int = 53, timeout: float = 2.0) -> str:
    """"ok", "nxdomain" (answers, but not the zone), or "noanswer" (nothing listens / error)."""
    qid = random.randint(0, 0xFFFF)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in zone.rstrip(".").split(".")) + b"\x00"
    packet = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", 6, 1)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(packet, (server, port))
            data, _ = sock.recvfrom(4096)
    except OSError:
        return "noanswer"
    if len(data) < 12:
        return "noanswer"
    rid, flags, _qd, ancount = struct.unpack(">HHHH", data[:8])
    if rid != qid:
        return "noanswer"
    rcode = flags & 0xF
    if rcode == 0 and ancount > 0:
        return "ok"
    if rcode in (0, 3):  # NODATA or NXDOMAIN: a server answers, but does not know the zone
        return "nxdomain"
    return "noanswer"


def original_lines(text: str) -> list[str]:
    """The LXC's resolv.conf lines (from our backup comments when we wrote the file before)."""
    if MARK in text:
        return [line[len(ORIGINAL):] for line in text.splitlines() if line.startswith(ORIGINAL)]
    return [line for line in text.splitlines()]


def render(original: list[str], realm: str) -> str:
    nameservers, search, options = [], [], []
    for line in original:
        parts = line.split()
        if not parts or parts[0].startswith(("#", ";")):
            continue
        if parts[0] == "nameserver" and len(parts) > 1:
            try:
                ip = ipaddress.ip_address(parts[1])
            except ValueError:
                continue
            if str(ip) != LOCAL and str(ip) not in nameservers:
                nameservers.append(str(ip))
        elif parts[0] in ("search", "domain"):
            search.extend(d for d in parts[1:] if d.lower() != realm.lower() and d not in search)
        elif parts[0] == "options":
            options.extend(o for o in parts[1:] if not o.startswith(("timeout:", "attempts:")))
    out = [f"{MARK}: PK95 DNS on {LOCAL} first (it forwards {realm} to Samba), then the LXC's resolvers.",
           "# The original file is kept below; the app rewrites this file on every start.",
           f"nameserver {LOCAL}"]
    out += [f"nameserver {ns}" for ns in nameservers[:MAXNS - 1]]
    out.append("search " + " ".join([realm] + search))
    out.append("options " + " ".join(["timeout:2", "attempts:2"] + options))
    out += [ORIGINAL + line for line in original]
    return "\n".join(out) + "\n"


def ensure(realm: str, dns_probe=query_soa, path: str = PATH) -> dict:
    """Point the container's resolver at PK95 DNS when it answers the realm. Returns the status for the API."""
    state = dns_probe(realm)
    if state == "noanswer":
        return {"ok": False, "nameserver": "", "message":
                f"Kein DNS-Server auf {LOCAL}:53 (PK95 DNS). Samba prüft seine DNS-Einträge dann über die DNS-Server "
                f"des LXC, die die Zone {realm} nicht kennen, und meldet im Log „Record already exists“."}
    if state == "nxdomain":
        return {"ok": False, "nameserver": "", "message":
                f"PK95 DNS auf {LOCAL}:53 kennt die Zone {realm} noch nicht. Bitte in PK95 DNS die bedingte "
                f"Weiterleitung {realm} → 127.0.0.1:5300 einrichten."}
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return {"ok": False, "nameserver": "", "message": f"{path} nicht lesbar: {exc.strerror}."}
    new = render(original_lines(text), realm)
    if new != text:
        try:
            with open(path, "w", encoding="utf-8") as fh:  # in place: Docker bind-mounts the file
                fh.write(new)
            log.info("resolv.conf: %s first for %s", LOCAL, realm)
        except OSError as exc:
            return {"ok": False, "nameserver": "", "message": f"{path} nicht schreibbar: {exc.strerror}."}
    return {"ok": True, "nameserver": LOCAL, "message": ""}
