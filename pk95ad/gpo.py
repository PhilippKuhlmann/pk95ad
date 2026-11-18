"""Group Policy objects: list, create, delete, links, inheritance and the curated settings."""

from __future__ import annotations

import logging
import os
import re
import shutil
import uuid

from . import drives, gplink, gpp, gpsettings, regpol, sysvol, validate
from .directory import Session, gentime_ms
from .errors import ApiError, Fields, conflict, forbidden, invalid, not_found

log = logging.getLogger("pk95ad.gpo")

BUILTIN = {"31b2f340-016d-11d2-945f-00c04fb984f9", "6ac1786c-016f-11d2-945f-00c04fb984f9"}
STATUS = {0: "enabled", 1: "user_disabled", 2: "computer_disabled", 3: "disabled"}
STATUS_FLAGS = {v: k for k, v in STATUS.items()}

REGISTRY_CSE = "{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
SCRIPTS_CSE = "{42B5FAAE-6536-11D2-AE5A-0000F87571E3}"
TOOLS = {
    ("registry", "computer"): "{D02B1F72-3407-48AE-BA88-E8213C6761F1}",
    ("registry", "user"): "{D02B1F73-3407-48AE-BA88-E8213C6761F1}",
    ("scripts", "computer"): "{40B6664F-4972-11D1-A7CA-0000F87571E3}",
    ("scripts", "user"): "{40B66650-4972-11D1-A7CA-0000F87571E3}",
}
FOLDERS = {"computer": "Machine", "user": "User"}
EXT_ATTR = {"computer": "gPCMachineExtensionNames", "user": "gPCUserExtensionNames"}

CSE_NAMES = {
    "{827D319E-6EAC-11D2-A4EA-00C04F79F83A}": "Sicherheit",
    "{C6DC5466-785A-11D2-84D0-00C04FB169F7}": "Software-Installation",
    "{25537BA6-77A8-11D2-9B6C-0000F8080861}": "Ordnerumleitung",
    "{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}": "EFS-Wiederherstellung",
    "{F3CCC681-B74C-4060-9F26-CD84525DCA2A}": "Erweiterte Überwachung",
    "{5794DAFD-BE60-433F-88A2-1A31939AC01F}": "Laufwerkszuordnungen",
    "{17D89FEC-5C44-4972-B12D-241CAEF74509}": "Lokale Benutzer und Gruppen",
    "{AADCED64-746C-4633-A97C-D61349046527}": "Geplante Aufgaben",
    "{B087BE9D-ED37-454F-AF9C-04291E351182}": "Registrierung (Einstellungen)",
    "{7150F9BF-48AD-4DA4-A49C-29EF4A8369BA}": "Dateien",
    "{6232C319-91AC-4931-9385-E70C2B099F0E}": "Ordner",
    "{91FBB303-0CD5-4055-BF42-E512A681B325}": "Dienste",
    "{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}": "Drucker",
    "{0E28E245-9368-4853-AD84-6DA3BA35BB75}": "Umgebung",
    "{E47248BA-94CC-49C4-BBB5-9EB7F05183D0}": "Interneteinstellungen",
    "{A3F3E39B-5D83-4940-B954-28315B82F0A8}": "Ordneroptionen",
    "{0ACDD40C-75AC-47AB-BAA0-BF6DE7E7FE63}": "WLAN",
    "{D76B9641-3288-4F75-942D-087DE603E3EA}": "LAPS",
}
GPO_ATTRS = ["displayName", "flags", "versionNumber", "gPCFileSysPath", "whenCreated", "whenChanged",
             "gPCMachineExtensionNames", "gPCUserExtensionNames"]

_EXT = re.compile(r"\[([^\]]*)\]")
_GUIDS = re.compile(r"\{[0-9A-Fa-f-]{36}\}")


# --- extension names ---------------------------------------------------------------------------------

def ext_parse(value: str) -> list[list[str]]:
    out = []
    for chunk in _EXT.findall(value or ""):
        guids = [g.upper() for g in _GUIDS.findall(chunk)]
        if guids:
            out.append(guids)
    return out


def ext_set(items: list[list[str]], cse: str, tool: str, present: bool) -> list[list[str]]:
    d: dict[str, set[str]] = {}
    for it in items:
        d.setdefault(it[0], set()).update(it[1:])
    if present:
        d.setdefault(cse, set()).add(tool)
    elif cse in d:
        d[cse].discard(tool)
        if not d[cse]:
            del d[cse]
    return [[c] + sorted(t) for c, t in sorted(d.items())]


def ext_format(items: list[list[str]]) -> str:
    return "".join("[" + "".join(it) + "]" for it in items)


# --- helpers -----------------------------------------------------------------------------------------

def _policies_dn(s: Session) -> str:
    return f"CN=Policies,CN=System,{s.base_str}"


def _braced(gid: str) -> str:
    return "{" + gid.upper() + "}"


def _dir(s: Session, gid: str, create: bool = False) -> str:
    policies = sysvol.ci_join(sysvol.domain_dir(s.cfg, s.realm), "Policies")
    path = sysvol.ci_join(policies, _braced(gid))
    if create:
        os.makedirs(path, exist_ok=True)
    return path


def _gpt_text(gdir: str) -> str:
    data = sysvol.read_bytes(sysvol.ci_join(gdir, "GPT.INI"))
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def _find(s: Session, oid: str):
    gid = validate.guid(oid)
    if not gid:
        raise not_found("Gruppenrichtlinie nicht gefunden.")
    msg = s.by_dn(f"CN={_braced(gid)},{_policies_dn(s)}", GPO_ATTRS)
    if msg is None:
        raise not_found("Gruppenrichtlinie nicht gefunden.")
    return gid, msg


def _links_map(s: Session) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for m in s.search(expression="(gPLink=*)", attrs=["gPLink", "objectGUID", "objectClass", "name"]):
        kind = s.kind(m)
        name = s.realm if kind == "domain" else m.dn.get_rdn_value()
        for i, link in enumerate(gplink.by_order(gplink.parse(s.val(m, "gPLink")))):
            out.setdefault(link.guid, []).append({
                "target_id": s.guid(m), "target_name": name, "target_type": kind if kind in ("domain", "ou")
                else "other", "target_path": s.path_of(m.dn), "enabled": link.enabled,
                "enforced": link.enforced, "order": i + 1,
            })
    for links in out.values():
        links.sort(key=lambda x: (x["target_path"].casefold(), x["order"]))
    return out


def _gpo(s: Session, gid: str, msg, links_map) -> dict:
    v = s.num(msg, "versionNumber")
    gdir = _dir(s, gid)
    gpt_ok = os.path.isfile(sysvol.ci_join(gdir, "GPT.INI"))
    return {
        "id": gid,
        "guid": _braced(gid),
        "name": s.val(msg, "displayName"),
        "status": STATUS.get(s.num(msg, "flags") & 3, "enabled"),
        "builtin": gid in BUILTIN,
        "created_at": gentime_ms(s.val(msg, "whenCreated")),
        "changed_at": gentime_ms(s.val(msg, "whenChanged")),
        "version": {"computer": v & 0xFFFF, "user": v >> 16},
        "links": links_map.get(gid, []),
        "sysvol_ok": gpt_ok and sysvol.gpt_version(_gpt_text(gdir)) == v,
        "drive_count": drive_count(gdir),
        "preference_counts": {"drives": drive_count(gdir),
                              **{k.name: prefs_count(gdir, k) for k in gpp.KINDS.values()}},
    }


def _all(s: Session):
    out = []
    for m in s.search(base=_policies_dn(s), scope="one", expression="(objectClass=groupPolicyContainer)",
                      attrs=GPO_ATTRS):
        gid = validate.guid(m.dn.get_rdn_value())
        if gid:
            out.append((gid, m))
    return out


def gpo_list(s: Session) -> list[dict]:
    links = _links_map(s)
    out = [_gpo(s, gid, m, links) for gid, m in _all(s)]
    out.sort(key=lambda g: g["name"].casefold())
    return out


def _load(gdir: str):
    entries, scripts = {}, {}
    for scope, folder in FOLDERS.items():
        try:
            entries[scope] = regpol.parse(sysvol.read_bytes(sysvol.ci_join(gdir, folder, "Registry.pol")))
        except regpol.PolError as exc:
            raise conflict(f"{folder}\\Registry.pol ist beschädigt ({exc}). Bitte mit der Windows-GPMC prüfen.")
        scripts[scope] = {
            "scripts": gpsettings.parse_scripts_ini(sysvol.read_bytes(sysvol.ci_join(gdir, folder, "Scripts",
                                                                                    "scripts.ini"))),
            "psscripts": gpsettings.parse_scripts_ini(sysvol.read_bytes(sysvol.ci_join(gdir, folder, "Scripts",
                                                                                      "psscripts.ini"))),
        }
    return entries, scripts


def gpo_get(s: Session, oid: str) -> dict:
    gid, msg = _find(s, oid)
    out = _gpo(s, gid, msg, _links_map(s))
    entries, scripts = _load(_dir(s, gid))
    out["settings"] = gpsettings.decode(entries, scripts)
    counts = gpsettings.unmanaged_count(entries)
    ext = set()
    for scope in FOLDERS:
        for it in ext_parse(s.val(msg, EXT_ATTR[scope])):
            if it[0] not in (REGISTRY_CSE, SCRIPTS_CSE, drives.CSE, "{00000000-0000-0000-0000-000000000000}",
                             *(k.cse.upper() for k in gpp.KINDS.values())):
                ext.add(CSE_NAMES.get(it[0], it[0]))
    out["other_settings"] = {"computer": counts["computer"], "user": counts["user"], "extensions": sorted(ext)}
    return out


def _check_name(s: Session, value, f: Fields, exclude: str | None = None):
    name, err = validate.optional_text(value, 200)
    if not err and not name:
        err = "Bitte einen Namen angeben."
    f.add("name", err)
    if not err:
        for gid, m in _all(s):
            if gid != exclude and s.val(m, "displayName").casefold() == name.casefold():
                f.add("name", "Eine Gruppenrichtlinie mit diesem Namen gibt es schon.")
                break
    return name


def gpo_create(s: Session, body: dict) -> str:
    f = Fields()
    name = _check_name(s, body.get("name"), f)
    f.raise_if_any()
    gid = str(uuid.uuid4())
    braced = _braced(gid)
    dn = f"CN={braced},{_policies_dn(s)}"
    realm = s.realm
    gdir = _dir(s, gid)
    with s.transaction():
        s.db.add({"dn": dn, "objectClass": "groupPolicyContainer", "displayName": name,
                  "gPCFileSysPath": f"\\\\{realm}\\SysVol\\{realm}\\Policies\\{braced}",
                  "versionNumber": "0", "flags": "0", "gPCFunctionalityVersion": "2"})
        s.db.add({"dn": f"CN=User,{dn}", "objectClass": "container"})
        s.db.add({"dn": f"CN=Machine,{dn}", "objectClass": "container"})
        try:
            os.makedirs(os.path.join(gdir, "Machine"), exist_ok=True)
            os.makedirs(os.path.join(gdir, "User"), exist_ok=True)
            sysvol.write_bytes(os.path.join(gdir, "GPT.INI"), b"[General]\r\nVersion=0\r\n")
        except OSError as exc:
            shutil.rmtree(gdir, ignore_errors=True)
            raise ApiError(500, f"Der Richtlinienordner in SYSVOL konnte nicht angelegt werden: {exc}") from exc
    return gid


def gpo_update(s: Session, oid: str, body: dict) -> None:
    gid, msg = _find(s, oid)
    f = Fields()
    changes = {}
    for key in body:
        if key not in ("name", "status"):
            f.add(key, "Dieses Feld kann hier nicht geändert werden.")
    if "name" in body and body["name"] != s.val(msg, "displayName"):
        if gid in BUILTIN:
            raise forbidden("Die Standardrichtlinien können nicht umbenannt werden.")
        changes["displayName"] = _check_name(s, body.get("name"), f, exclude=gid)
    if "status" in body:
        if body["status"] not in STATUS_FLAGS:
            f.add("status", "Erlaubt: enabled, user_disabled, computer_disabled, disabled.")
        else:
            changes["flags"] = str(STATUS_FLAGS[body["status"]])
    f.raise_if_any()
    s.replace(msg.dn, changes)


def gpo_delete(s: Session, oid: str) -> None:
    gid, msg = _find(s, oid)
    if gid in BUILTIN:
        raise forbidden("Die Standardrichtlinien können nicht gelöscht werden.")
    gdir = _dir(s, gid)
    with s.transaction():
        for m in s.search(expression=f"(gPLink=*{gid}*)", attrs=["gPLink"]):
            links = gplink.remove(gplink.parse(s.val(m, "gPLink")), gid)
            s.replace(m.dn, {"gPLink": gplink.format(links) or None})
        s.db.delete(msg.dn, ["tree_delete:1"])
    shutil.rmtree(gdir, ignore_errors=True)


def gpo_set_settings(s: Session, oid: str, body: dict) -> bool:
    """Apply settings; returns True when files changed (then SYSVOL ACLs need a reset)."""
    gid, msg = _find(s, oid)
    settings = body.get("settings")
    if not isinstance(settings, dict):
        raise invalid({"settings": "Bitte ein Objekt mit Einstellungen angeben."})
    gdir = _dir(s, gid, create=True)
    entries, scripts = _load(gdir)
    new_entries, new_scripts, _, changed = gpsettings.apply(entries, scripts, settings, s.realm)
    if not changed:
        return False

    for scope in changed:
        folder = FOLDERS[scope]
        pol = sysvol.ci_join(gdir, folder, "Registry.pol", create=True)
        if new_entries[scope]:
            sysvol.write_bytes(pol, regpol.serialize(new_entries[scope]))
        else:
            sysvol.remove(pol)
        for kind, fname in (("scripts", "scripts.ini"), ("psscripts", "psscripts.ini")):
            ini = new_scripts[scope][kind]
            path = sysvol.ci_join(gdir, folder, "Scripts", fname, create=not ini.empty())
            if ini.empty():
                sysvol.remove(path)
            else:
                sysvol.write_bytes(path, gpsettings.serialize_scripts_ini(ini))

    version = _bump_version(s, msg, gdir, changed)
    attrs = {"versionNumber": str(version)}
    for scope in FOLDERS:
        items = ext_parse(s.val(msg, EXT_ATTR[scope]))
        has_reg = bool(new_entries[scope])
        has_scripts = not (new_scripts[scope]["scripts"].empty() and new_scripts[scope]["psscripts"].empty())
        items = ext_set(items, REGISTRY_CSE, TOOLS[("registry", scope)], has_reg)
        items = ext_set(items, SCRIPTS_CSE, TOOLS[("scripts", scope)], has_scripts)
        attrs[EXT_ATTR[scope]] = ext_format(items) or None
    s.replace(msg.dn, attrs)
    return True


def _bump_version(s: Session, msg, gdir: str, changed: set[str]) -> int:
    """Raise the version of the changed halves in GPT.INI (written here) and return the new versionNumber."""
    gpt = _gpt_text(gdir)
    v_ad, v_gpt = s.num(msg, "versionNumber"), sysvol.gpt_version(gpt)
    user = max(v_ad >> 16, v_gpt >> 16)
    machine = max(v_ad & 0xFFFF, v_gpt & 0xFFFF)
    if "computer" in changed:
        machine = (machine + 1) & 0xFFFF or 1
    if "user" in changed:
        user = (user + 1) & 0xFFFF or 1
    version = (user << 16) | machine
    sysvol.write_bytes(sysvol.ci_join(gdir, "GPT.INI"), sysvol.gpt_set_version(gpt, version).encode("utf-8"))
    return version


# --- drive maps (Group Policy Preferences) -------------------------------------------------------------

def _drives_path(gdir: str, create: bool = False) -> str:
    return sysvol.ci_join(gdir, "User", "Preferences", "Drives", "Drives.xml", create=create)


def _drives_root(gdir: str):
    try:
        return drives.parse(sysvol.read_bytes(_drives_path(gdir)))
    except drives.DrivesError as exc:
        raise conflict(f"User\\Preferences\\Drives\\Drives.xml: {exc} Bitte mit der Windows-GPMC prüfen.")


def drive_count(gdir: str) -> int:
    try:
        return len(drives.items(_drives_root(gdir)))
    except ApiError:
        return 0


def _group_by_sid(s: Session):
    def lookup(sid: str):
        if not re.match(r"^S-1-[0-9-]+$", sid or ""):
            return None
        res = s.search(expression=f"(objectSid={sid})", attrs=["objectGUID", "sAMAccountName"])
        return {"id": s.guid(res[0]), "name": s.val(res[0], "sAMAccountName")} if len(res) else None
    return lookup


def _group_by_id(s: Session):
    netbios = s.settings.get("netbios_domain", "")

    def lookup(gid):
        try:
            g = s.find(gid, attrs=["objectClass", "objectSid", "sAMAccountName", "groupType"], what="Gruppe")
        except ApiError:
            return "Gruppe nicht gefunden."
        if "group" not in s.classes(g):
            return "Das ist keine Gruppe."
        if not (s.num(g, "groupType") & 0x80000000):
            return "Nur Sicherheitsgruppen wirken bei der Zielgruppenadressierung (keine Verteilergruppen)."
        return {"name": f"{netbios}\\{s.val(g, 'sAMAccountName')}", "sid": s.sid(g)}
    return lookup


def drives_get(s: Session, oid: str) -> dict:
    gid, _ = _find(s, oid)
    root = _drives_root(_dir(s, gid))
    by_sid = _group_by_sid(s)
    return {"items": [drives.to_json(e, by_sid) for e in drives.items(root)]}


def drives_put(s: Session, oid: str, body: dict) -> bool:
    """Replace the drive maps; returns True when files changed (then SYSVOL ACLs need a reset)."""
    gid, msg = _find(s, oid)
    gdir = _dir(s, gid, create=True)
    root = _drives_root(gdir)
    new_root, changed = drives.apply(root, body.get("items"), _group_by_id(s))
    if not changed:
        return False
    path = _drives_path(gdir, create=bool(drives.items(new_root)))
    if drives.items(new_root):
        sysvol.write_bytes(path, drives.serialize(new_root))
    else:
        sysvol.remove(path)
    version = _bump_version(s, msg, gdir, {"user"})
    items = ext_set(ext_parse(s.val(msg, EXT_ATTR["user"])), drives.CSE, drives.TOOL, bool(drives.items(new_root)))
    s.replace(msg.dn, {"versionNumber": str(version), EXT_ATTR["user"]: ext_format(items) or None})
    return True


# --- other preference lists (local groups, printers, shortcuts) -------------------------------------------

def _prefs_root(gdir: str, kind: gpp.Kind):
    try:
        return gpp.parse(kind, sysvol.read_bytes(sysvol.ci_join(gdir, *kind.path)))
    except gpp.PrefsError as exc:
        where = "\\".join(kind.path)
        raise conflict(f"{where}: {exc} Bitte mit der Windows-GPMC prüfen.")


def prefs_count(gdir: str, kind: gpp.Kind) -> int:
    try:
        return len(gpp.items(_prefs_root(gdir, kind)))
    except ApiError:
        return 0


def _context(s: Session) -> gpp.Context:
    netbios = s.settings.get("netbios_domain", "")

    def account(msg):
        c = s.classes(msg)
        if "computer" in c or not ({"user", "group"} & c):
            return None
        kind = "group" if "group" in c else "user"
        if kind == "group" and not (s.num(msg, "groupType") & 0x80000000):
            return None  # distribution groups are not in the token
        return {"id": s.guid(msg), "name": f"{netbios}\\{s.val(msg, 'sAMAccountName')}", "sid": s.sid(msg), "kind": kind}

    attrs = ["objectClass", "objectGUID", "objectSid", "sAMAccountName", "groupType"]

    def account_by_id(oid):
        try:
            msg = s.find(oid, attrs=attrs, what="Konto")
        except ApiError:
            return "Konto nicht gefunden."
        return account(msg) or "Nur Domänenbenutzer und Sicherheitsgruppen."

    def account_by_sid(sid):
        if not re.match(r"^S-1-[0-9-]+$", sid or ""):
            return None
        res = s.search(expression=f"(objectSid={sid})", attrs=attrs)
        a = account(res[0]) if len(res) else None
        return {"id": a["id"], "name": a["name"], "kind": a["kind"]} if a else None

    da_sid = f"{s.domain_sid}-512"
    da = account_by_sid(da_sid)
    return gpp.Context(group_by_sid=_group_by_sid(s), group_by_id=_group_by_id(s), account_by_id=account_by_id,
                       account_by_sid=account_by_sid, domain_admins_sid=da_sid,
                       domain_admins_id=da["id"] if da else "",
                       domain_admins_name=da["name"] if da else f"{netbios}\\Domain Admins")


def prefs_get(s: Session, oid: str, kind: gpp.Kind) -> dict:
    gid, _ = _find(s, oid)
    root = _prefs_root(_dir(s, gid), kind)
    ctx = _context(s)
    return {"items": [gpp.to_json(kind, e, ctx) for e in gpp.items(root)]}


def prefs_put(s: Session, oid: str, kind: gpp.Kind, body: dict) -> bool:
    """Replace one preference list; returns True when files changed (then SYSVOL ACLs need a reset)."""
    gid, msg = _find(s, oid)
    gdir = _dir(s, gid, create=True)
    root = _prefs_root(gdir, kind)
    new_root, changed = gpp.apply(kind, root, body.get("items"), _context(s))
    if not changed:
        return False
    has_items = bool(gpp.items(new_root))
    path = sysvol.ci_join(gdir, *kind.path, create=has_items)
    if has_items:
        sysvol.write_bytes(path, gpp.serialize(new_root))
    else:
        sysvol.remove(path)
    version = _bump_version(s, msg, gdir, {kind.scope})
    attr = EXT_ATTR[kind.scope]
    items = ext_set(ext_parse(s.val(msg, attr)), kind.cse.upper(), kind.tool.upper(), has_items)
    s.replace(msg.dn, {"versionNumber": str(version), attr: ext_format(items) or None})
    return True


# --- links -------------------------------------------------------------------------------------------

def _link_target(s: Session, target_id, field: str = "target_id"):
    try:
        m = s.find(target_id, attrs=["gPLink", "objectClass", "objectGUID"], what="Ziel")
    except ApiError:
        raise invalid({field: "Ziel nicht gefunden."})
    if s.kind(m) not in ("domain", "ou"):
        raise invalid({field: "Verknüpfen geht nur mit der Domäne oder einer Organisationseinheit."})
    return m


def link_add(s: Session, oid: str, body: dict) -> None:
    gid, msg = _find(s, oid)
    f = Fields()
    enabled, err = validate.boolean(body.get("enabled", True))
    f.add("enabled", err)
    enforced, err = validate.boolean(body.get("enforced", False))
    f.add("enforced", err)
    if not body.get("target_id"):
        f.add("target_id", "Bitte ein Ziel auswählen.")
    f.raise_if_any()
    t = _link_target(s, body["target_id"])
    links = gplink.parse(s.val(t, "gPLink"))
    if any(link.guid == gid for link in links):
        raise invalid({"target_id": "Die Richtlinie ist hier schon verknüpft."})
    link_dn = f"cn={_braced(gid)},cn=policies,cn=system,{s.base_str}"
    s.replace(t.dn, {"gPLink": gplink.format(gplink.add(links, link_dn, gplink.opts(enabled, enforced)))})


def link_update(s: Session, oid: str, target_id: str, body: dict) -> None:
    gid, _ = _find(s, oid)
    t = _link_target(s, target_id)
    links = gplink.parse(s.val(t, "gPLink"))
    cur = next((link for link in links if link.guid == gid), None)
    if cur is None:
        raise not_found("Verknüpfung nicht gefunden.")
    f = Fields()
    enabled, enforced = cur.enabled, cur.enforced
    if "enabled" in body:
        enabled, err = validate.boolean(body["enabled"])
        f.add("enabled", err)
    if "enforced" in body:
        enforced, err = validate.boolean(body["enforced"])
        f.add("enforced", err)
    order = None
    if "order" in body:
        order, err = validate.integer(body["order"], 1, len(links))
        f.add("order", err)
    f.raise_if_any()
    links = gplink.set_opts(links, gid, gplink.opts(enabled, enforced))
    if order:
        links = gplink.move(links, gid, order)
    s.replace(t.dn, {"gPLink": gplink.format(links)})


def link_delete(s: Session, oid: str, target_id: str) -> None:
    gid, _ = _find(s, oid)
    t = _link_target(s, target_id)
    links = gplink.parse(s.val(t, "gPLink"))
    if not any(link.guid == gid for link in links):
        raise not_found("Verknüpfung nicht gefunden.")
    s.replace(t.dn, {"gPLink": gplink.format(gplink.remove(links, gid)) or None})


def inheritance(s: Session, oid: str) -> dict:
    msg = s.find(oid, attrs=["objectClass", "gPOptions"], what="Organisationseinheit")
    if s.kind(msg) not in ("domain", "ou", "container", "builtin"):
        raise not_found("Organisationseinheit nicht gefunden.")
    dns = []
    d = msg.dn
    while not s.is_base(d):
        dns.append(d)
        d = d.parent()
        if d is None or s.comp_num(d) < s.comp_num(s.base):
            break
    dns.append(s.base)
    chain = []
    for dn in reversed(dns):
        m = s.by_dn(dn, ["gPLink", "gPOptions", "objectGUID"])
        if m is None:
            continue
        chain.append({"id": s.guid(m), "name": s.realm if s.is_base(dn) else dn.get_rdn_value(),
                      "links": gplink.parse(s.val(m, "gPLink")), "block": bool(s.num(m, "gPOptions") & 1)})
    gpos = {gid: {"name": s.val(m, "displayName"), "enabled": (s.num(m, "flags") & 3) != 3} for gid, m in _all(s)}
    return {"block_inheritance": bool(s.num(msg, "gPOptions") & 1), "items": gplink.inheritance(chain, gpos)}
