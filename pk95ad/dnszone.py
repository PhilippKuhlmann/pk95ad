"""DNS records of the AD zones, edited directly as dnsNode objects (what Samba's internal DNS serves)."""

from __future__ import annotations

import hashlib
import ipaddress

from . import validate
from .directory import Session
from .errors import Fields, forbidden, not_found

DEFAULT_TTL = 900
WRITABLE = ("A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR")


def _types():
    from samba.dcerpc import dnsp

    return {
        dnsp.DNS_TYPE_A: "A", dnsp.DNS_TYPE_NS: "NS", dnsp.DNS_TYPE_CNAME: "CNAME", dnsp.DNS_TYPE_SOA: "SOA",
        dnsp.DNS_TYPE_PTR: "PTR", dnsp.DNS_TYPE_MX: "MX", dnsp.DNS_TYPE_TXT: "TXT", dnsp.DNS_TYPE_AAAA: "AAAA",
        dnsp.DNS_TYPE_SRV: "SRV",
    }


def _partitions(s: Session):
    forest = str(s.db.get_root_basedn())
    return [("domain", f"CN=MicrosoftDNS,DC=DomainDnsZones,{s.base_str}"),
            ("forest", f"CN=MicrosoftDNS,DC=ForestDnsZones,{forest}")]


def _zone_msgs(s: Session):
    out = []
    for part, base in _partitions(s):
        if s.by_dn(base, ["dn"]) is None:
            continue
        for m in s.search(base=base, scope="one", expression="(objectClass=dnsZone)", attrs=["name"]):
            name = (s.val(m, "name") or m.dn.get_rdn_value()).lower()
            if name.startswith("..") or name == "rootdnsservers":
                continue
            out.append((part, name, m))
    return out


def _find_zone(s: Session, zone: str):
    z = (zone or "").lower().rstrip(".")
    for part, name, m in _zone_msgs(s):
        if name == z:
            return part, name, m
    raise not_found("Zone nicht gefunden.")


def _nodes(s: Session, zone_msg):
    return s.search(base=zone_msg.dn, scope="one", expression="(objectClass=dnsNode)",
                    attrs=["name", "dnsRecord", "dNSTombstoned"])


def _live_records(s: Session, node):
    from samba.dcerpc import dnsp
    from samba.ndr import ndr_unpack

    if s.val(node, "dNSTombstoned").upper() == "TRUE":
        return []
    el = node.get("dnsRecord")
    if el is None:
        return []
    out = []
    for v in el:
        rec = ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v))
        if rec.wType != dnsp.DNS_TYPE_TOMBSTONE:
            out.append(rec)
    return out


def _fqdn(node_name: str, zone: str) -> str:
    return zone if node_name == "@" else f"{node_name}.{zone}".lower()


def _rec_json(s: Session, zone: str, fqdn: str, rec, system_zone: bool) -> dict:
    types = _types()
    t = types.get(rec.wType, f"TYPE{rec.wType}")
    prio = weight = port = 0
    if t in ("A", "AAAA"):
        value = str(rec.data)
    elif t in ("CNAME", "NS", "PTR"):
        value = str(rec.data).rstrip(".").lower()
    elif t == "MX":
        value, prio = str(rec.data.nameTarget).rstrip(".").lower(), rec.data.wPriority
    elif t == "SRV":
        value = str(rec.data.nameTarget).rstrip(".").lower()
        prio, weight, port = rec.data.wPriority, rec.data.wWeight, rec.data.wPort
    elif t == "TXT":
        value = "".join(str(x) for x in (rec.data.str or []))
    elif t == "SOA":
        d = rec.data
        value = f"{d.mname} {d.rname} {d.serial} {d.refresh} {d.retry} {d.expire} {d.minimum}"
    else:
        value = ""
    dc_host = f"{s.settings.get('hostname', '')}.{s.realm}".lower()
    dc_ip = s.settings.get("host_ip", "")
    system = (system_zone or t in ("SOA", "NS") or fqdn.split(".")[0].startswith("_")
              or fqdn == dc_host
              or fqdn in (f"domaindnszones.{s.realm}", f"forestdnszones.{s.realm}")
              or (fqdn == zone and t in ("A", "AAAA") and value == dc_ip)
              or t not in WRITABLE + ("SOA", "NS"))
    return {
        "id": _rid(fqdn, t, value, prio, weight, port),
        "zone": zone, "name": fqdn, "type": t, "value": value, "ttl": rec.dwTtlSeconds,
        "priority": prio, "weight": weight, "port": port,
        "dynamic": rec.dwTimeStamp != 0, "system": bool(system),
    }


def _rid(fqdn, t, value, prio, weight, port) -> str:
    return hashlib.sha256(f"{fqdn}|{t}|{value}|{prio}|{weight}|{port}".encode()).hexdigest()[:16]


def zones(s: Session) -> list[dict]:
    out = []
    for part, name, m in _zone_msgs(s):
        count = sum(len(_live_records(s, n)) for n in _nodes(s, m))
        out.append({"name": name, "partition": part, "reverse": name.endswith((".in-addr.arpa", ".ip6.arpa")),
                    "record_count": count, "system": name == f"_msdcs.{s.realm}"})
    out.sort(key=lambda z: (z["system"], z["name"]))
    return out


def records(s: Session, zone: str, q) -> list[dict]:
    _, name, zm = _find_zone(s, zone)
    system_zone = name == f"_msdcs.{s.realm}"
    out = []
    for node in _nodes(s, zm):
        fqdn = _fqdn(node.dn.get_rdn_value().lower(), name)
        for rec in _live_records(s, node):
            out.append(_rec_json(s, name, fqdn, rec, system_zone))
    if q.q("type"):
        out = [r for r in out if r["type"] == q.q("type").upper()]
    term = q.q("q").lower()
    if term:
        out = [r for r in out if term in r["name"] or term in r["value"].lower()]
    out.sort(key=lambda r: (r["name"], r["type"], r["priority"], r["value"]))
    return out


def _check(s: Session, zone: str, body: dict) -> dict:
    f = Fields()
    name, err = validate.dns_name(body.get("name"))
    f.add("name", err)
    if not err and name != zone and not name.endswith("." + zone):
        f.add("name", f"Der Name muss in der Zone {zone} liegen.")
    t = str(body.get("type") or "").upper()
    if t not in WRITABLE:
        f.add("type", "Erlaubt: " + ", ".join(WRITABLE) + ".")
    reverse = zone.endswith((".in-addr.arpa", ".ip6.arpa"))
    if t == "PTR" and not reverse:
        f.add("type", "PTR-Einträge nur in Reverse-Zonen.")
    ttl = body.get("ttl", DEFAULT_TTL)
    ttl, err = validate.integer(ttl, 0, 604800)
    f.add("ttl", err)
    value = body.get("value")
    prio = weight = port = 0
    if t == "A":
        try:
            value = str(ipaddress.IPv4Address(str(value or "").strip()))
        except ValueError:
            f.add("value", "Bitte eine IPv4-Adresse angeben.")
    elif t == "AAAA":
        try:
            value = str(ipaddress.IPv6Address(str(value or "").strip()))
        except ValueError:
            f.add("value", "Bitte eine IPv6-Adresse angeben.")
    elif t in ("CNAME", "MX", "SRV", "PTR"):
        value, err = validate.host_target(value)
        f.add("value", err)
    elif t == "TXT":
        if not isinstance(value, str) or not 1 <= len(value) <= 4000 or not value.isprintable():
            f.add("value", "1–4000 druckbare Zeichen.")
    if t in ("MX", "SRV"):
        prio, err = validate.integer(body.get("priority", 0), 0, 65535)
        f.add("priority", err)
    if t == "SRV":
        weight, err = validate.integer(body.get("weight", 0), 0, 65535)
        f.add("weight", err)
        port, err = validate.integer(body.get("port"), 1, 65535)
        f.add("port", err)
    if t == "CNAME" and name == zone:
        f.add("name", "Kein CNAME an der Zonenspitze.")
    f.raise_if_any()
    return {"name": name, "type": t, "value": value, "ttl": ttl, "priority": prio, "weight": weight,
            "port": port}


def _make(r: dict, serial: int):
    from samba.dcerpc import dnsp

    codes = {v: k for k, v in _types().items()}
    rec = dnsp.DnssrvRpcRecord()
    rec.wType = codes[r["type"]]
    rec.rank = dnsp.DNS_RANK_ZONE
    rec.flags = 0
    rec.dwSerial = serial
    rec.dwTtlSeconds = r["ttl"]
    rec.dwReserved = 0
    rec.dwTimeStamp = 0
    t = r["type"]
    if t in ("A", "AAAA", "CNAME", "PTR"):
        rec.data = r["value"]
    elif t == "MX":
        mx = dnsp.mx()
        mx.wPriority = r["priority"]
        mx.nameTarget = r["value"]
        rec.data = mx
    elif t == "SRV":
        srv = dnsp.srv()
        srv.wPriority = r["priority"]
        srv.wWeight = r["weight"]
        srv.wPort = r["port"]
        srv.nameTarget = r["value"]
        rec.data = srv
    elif t == "TXT":
        parts = []
        raw = r["value"]
        while raw:
            chunk = raw[:255]
            while len(chunk.encode("utf-8")) > 255:
                chunk = chunk[:-1]
            parts.append(chunk)
            raw = raw[len(chunk):]
        sl = dnsp.string_list()
        sl.count = len(parts)
        sl.str = parts
        rec.data = sl
    return rec


def _node_dn(s: Session, zone_msg, zone: str, fqdn: str):
    rel = "@" if fqdn == zone else fqdn[: -(len(zone) + 1)]
    return s.child_dn(zone_msg.dn, "DC", rel)


def _bump_serial(s: Session, zone_msg) -> int:
    """Raise the zone's SOA serial; returns the new serial (1 when there is no SOA)."""
    from samba.dcerpc import dnsp
    from samba.ndr import ndr_pack, ndr_unpack

    apex = s.by_dn(s.child_dn(zone_msg.dn, "DC", "@"), ["dnsRecord"])
    if apex is None or apex.get("dnsRecord") is None:
        return 1
    values = []
    serial = 1
    for v in apex["dnsRecord"]:
        rec = ndr_unpack(dnsp.DnssrvRpcRecord, bytes(v))
        if rec.wType == dnsp.DNS_TYPE_SOA:
            rec.data.serial = (rec.data.serial + 1) & 0xFFFFFFFF or 1
            serial = rec.data.serial
            values.append(ndr_pack(rec))
        else:
            values.append(bytes(v))
    s.replace(apex.dn, {"dnsRecord": values})
    return serial


def _write_node(s: Session, zone_msg, zone: str, fqdn: str, recs: list) -> None:
    from samba.ndr import ndr_pack

    dn = _node_dn(s, zone_msg, zone, fqdn)
    existing = s.by_dn(dn, ["dnsRecord"])
    packed = [ndr_pack(r) for r in recs]
    if existing is None:
        if packed:
            s.db.add({"dn": str(dn), "objectClass": ["top", "dnsNode"], "dnsRecord": packed})
        return
    if packed:
        s.replace(dn, {"dnsRecord": packed, "dNSTombstoned": "FALSE"})
    else:
        s.db.delete(dn)


def _node_records(s: Session, zone_msg, zone: str, fqdn: str):
    node = s.by_dn(_node_dn(s, zone_msg, zone, fqdn), ["name", "dnsRecord", "dNSTombstoned"])
    return [] if node is None else _live_records(s, node)


def _conflicts(s: Session, zone: str, fqdn: str, recs, new: dict, f: Fields) -> None:
    types = _types()
    others = [types.get(r.wType, "") for r in recs]
    if new["type"] == "CNAME" and others:
        f.add("name", "Neben einem CNAME darf es keine anderen Einträge mit diesem Namen geben.")
    if new["type"] != "CNAME" and "CNAME" in others:
        f.add("name", "Für diesen Namen gibt es schon einen CNAME.")
    for r in recs:
        if _rec_json(s, zone, fqdn, r, False)["id"] == _rid(fqdn, new["type"], new["value"], new["priority"],
                                                             new["weight"], new["port"]):
            f.add("value", "Diesen Eintrag gibt es schon.")


def create(s: Session, zone: str, body: dict) -> dict:
    _, name, zm = _find_zone(s, zone)
    if name == f"_msdcs.{s.realm}":
        raise forbidden("Die Zone _msdcs verwaltet Samba selbst.")
    r = _check(s, name, body)
    with s.transaction():
        # Bump first: the apex node holds the SOA, a later read must see the new serial.
        serial = _bump_serial(s, zm)
        recs = _node_records(s, zm, name, r["name"])
        f = Fields()
        _conflicts(s, name, r["name"], recs, r, f)
        f.raise_if_any()
        _write_node(s, zm, name, r["name"], recs + [_make(r, serial)])
    return _rec_json(s, name, r["name"], _make(r, serial), False)


def _locate(s: Session, zone: str, rid: str):
    _, name, zm = _find_zone(s, zone)
    system_zone = name == f"_msdcs.{s.realm}"
    for node in _nodes(s, zm):
        fqdn = _fqdn(node.dn.get_rdn_value().lower(), name)
        recs = _live_records(s, node)
        for i, rec in enumerate(recs):
            j = _rec_json(s, name, fqdn, rec, system_zone)
            if j["id"] == rid:
                return name, zm, fqdn, recs, i, j
    raise not_found("Eintrag nicht gefunden.")


def update(s: Session, zone: str, rid: str, body: dict) -> dict:
    name, zm, fqdn, recs, idx, cur = _locate(s, zone, rid)
    if cur["system"]:
        raise forbidden("Diesen Eintrag braucht der Domänencontroller; er kann nicht geändert werden.")
    r = _check(s, name, body)
    with s.transaction():
        serial = _bump_serial(s, zm)
        name, zm, fqdn, recs, idx, cur = _locate(s, zone, rid)  # re-read after the SOA change
        rest = recs[:idx] + recs[idx + 1:]
        if r["name"] == fqdn:
            f = Fields()
            _conflicts(s, name, fqdn, rest, r, f)
            f.raise_if_any()
            _write_node(s, zm, name, fqdn, rest + [_make(r, serial)])
        else:
            target = _node_records(s, zm, name, r["name"])
            f = Fields()
            _conflicts(s, name, r["name"], target, r, f)
            f.raise_if_any()
            _write_node(s, zm, name, fqdn, rest)
            _write_node(s, zm, name, r["name"], target + [_make(r, serial)])
    return _rec_json(s, name, r["name"], _make(r, serial), False)


def delete(s: Session, zone: str, rid: str) -> None:
    _, _, _, _, _, cur = _locate(s, zone, rid)
    if cur["system"]:
        raise forbidden("Diesen Eintrag braucht der Domänencontroller; er kann nicht gelöscht werden.")
    with s.transaction():
        _bump_serial(s, zm := _find_zone(s, zone)[2])
        name, zm, fqdn, recs, idx, _ = _locate(s, zone, rid)
        _write_node(s, zm, name, fqdn, recs[:idx] + recs[idx + 1:])
