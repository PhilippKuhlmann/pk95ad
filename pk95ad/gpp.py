"""Group Policy Preferences lists (1.3.0): local groups, printers, shortcuts (docs/api.md → Preferences).

One generic engine like Drives.xml: items with uid and changed, item-level targeting on one security group,
read-only for GPMC items PK95 AD does not edit, max 50 items. Each Kind only knows its own XML and fields.
Pure functions on ElementTree elements; the directory lookups come in through a context object.
"""

from __future__ import annotations

import copy
import re
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timezone

from . import validate
from .errors import Fields

TARGET = "target"  # name of the item-level targeting field in the API
MAX_ITEMS = 50
ACTIONS = {"create": "C", "replace": "R", "update": "U", "delete": "D"}
IMAGES = {"C": "0", "R": "1", "U": "2", "D": "3"}
PASSWORD_WARNING = "Enthält ein gespeichertes Kennwort (unsicher, MS14-025). Bitte in der GPMC entfernen."
_UID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")


class PrefsError(ValueError):
    """The preferences file cannot be read."""


@dataclass
class Context:
    """Directory lookups for one request."""
    group_by_sid: object    # sid -> {"id", "name"} | None (security groups for targeting)
    group_by_id: object     # id -> {"name": "NB\\G", "sid"} | German error string
    account_by_id: object   # id -> {"name": "NB\\x", "sid", "kind": "user"|"group"} | error string
    account_by_sid: object  # sid -> {"id", "name", "kind"} | None
    domain_admins_sid: str = ""
    domain_admins_id: str = ""
    domain_admins_name: str = ""


@dataclass
class Kind:
    name: str            # API/count key, e.g. "local_groups"
    route: str           # URL segment, e.g. "local-groups"
    scope: str           # "computer" | "user"
    path: tuple          # file below the GPO folder
    root_tag: str
    root_clsid: str
    item_tag: str
    item_clsid: str
    cse: str
    tool: str
    fields: object       # (elem, ctx) -> dict of kind fields
    check: object        # (item, ctx, f, name) -> validated dict
    build: object        # (elem, v, ctx) -> None (sets name/status/image and Properties)
    unique: object       # (v) -> hashable key that must be unique in the list, or None
    unique_error: str = "Doppelt in dieser Richtlinie."
    extra_readonly: object = None  # (elem, ctx) -> German reason or ""
    bypass_errors: bool = True


# --- common XML handling ---------------------------------------------------------------------------------

def parse(kind: Kind, data: bytes) -> ET.Element:
    if not data.strip():
        return ET.Element(kind.root_tag, {"clsid": kind.root_clsid})
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise PrefsError(f"{kind.path[-1]} ist kein gültiges XML ({exc}).") from exc
    if root.tag != kind.root_tag:
        raise PrefsError(f"{kind.path[-1]} hat kein <{kind.root_tag}>-Element.")
    return root


def serialize(root: ET.Element) -> bytes:
    body = ET.tostring(root, encoding="unicode", short_empty_elements=True)
    return ('<?xml version="1.0" encoding="utf-8"?>\r\n' + body).encode("utf-8")


def items(root: ET.Element) -> list[ET.Element]:
    return [e for e in root if e.get("uid") is not None or e.find("Properties") is not None]


def props(elem: ET.Element) -> ET.Element:
    p = elem.find("Properties")
    return p if p is not None else ET.Element("Properties")


def filter_group(elem: ET.Element):
    """(sid, name, not) of the single group filter, None without filters, False when it is something else."""
    filters = elem.find("Filters")
    if filters is None or len(filters) == 0:
        return None
    if len(filters) != 1 or filters[0].tag != "FilterGroup":
        return False
    f = filters[0]
    if f.get("bool", "AND") != "AND" or f.get("localGroup", "0") != "0" or f.get("primaryGroup", "0") != "0":
        return False
    return f.get("sid", ""), f.get("name", ""), f.get("not", "0") == "1"


def changed_ms(value: str) -> int:
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return 0
    return int(dt.timestamp() * 1000)


def readonly_reason(kind: Kind, elem: ET.Element, ctx: Context) -> str:
    if elem.tag != kind.item_tag:
        return "Diese Art Eintrag kann PK95 AD nicht bearbeiten. Nur in der GPMC bearbeitbar."
    p = props(elem)
    if p.get("cpassword"):
        return PASSWORD_WARNING
    if p.get("userName") or p.get("username"):
        return "Verwendet ein anderes Benutzerkonto. Nur in der GPMC bearbeitbar."
    if elem.get("disabled") == "1" or p.get("disabled") == "1":
        return "In der GPMC deaktiviert. Nur dort bearbeitbar."
    if filter_group(elem) is False:
        return "Zielgruppenadressierung mit Bedingungen, die PK95 AD nicht bearbeitet. Nur in der GPMC bearbeitbar."
    if kind.extra_readonly:
        return kind.extra_readonly(elem, ctx) or ""
    return ""


def to_json(kind: Kind, elem: ET.Element, ctx: Context) -> dict:
    reason = readonly_reason(kind, elem, ctx)
    target = None
    fg = filter_group(elem)
    if fg:
        sid, name, negate = fg
        g = ctx.group_by_sid(sid) if sid else None
        target = {"group_id": g["id"] if g else "", "group_name": g["name"] if g else name.split("\\")[-1],
                  "not": negate}
        if not g and not reason:
            reason = f"Die Zielgruppe {name or sid} gibt es nicht mehr."
    out = {"uid": (elem.get("uid") or "").upper()}
    if elem.tag == kind.item_tag:
        try:
            out.update(kind.fields(elem, ctx))
        except (KeyError, ValueError) as exc:
            reason = reason or f"Eintrag nicht lesbar ({exc})."
    out.update({TARGET: target, "changed_at": changed_ms(elem.get("changed", "")), "readonly": bool(reason),
                "warning": reason})
    return out


def _semantic(elem: ET.Element) -> str:
    """Everything but the bookkeeping attributes, to decide whether 'changed' moves."""
    e = copy.deepcopy(elem)
    for a in ("changed", "uid"):
        e.attrib.pop(a, None)
    return ET.tostring(e, encoding="unicode")


def check_target(item: dict, ctx: Context, f: Fields, name: str):
    target = item.get(TARGET)
    if target is None:
        return None
    if not isinstance(target, dict) or not target.get("group_id"):
        f.add(f"{name}.{TARGET}.group_id", "Bitte eine Gruppe auswählen.")
        return None
    g = ctx.group_by_id(target.get("group_id"))
    if isinstance(g, str):
        f.add(f"{name}.{TARGET}.group_id", g)
        return None
    negate, err = validate.boolean(target.get("not", False))
    f.add(f"{name}.{TARGET}.not", err)
    return {"name": g["name"], "sid": g["sid"], "not": bool(negate)}


def check_action(item: dict, f: Fields, name: str) -> str:
    action = item.get("action", "update")
    if action not in ACTIONS:
        f.add(f"{name}.action", "Erlaubt: create, replace, update, delete.")
        return "update"
    return action


def _write_target(elem: ET.Element, target) -> None:
    for old in elem.findall("Filters"):
        elem.remove(old)
    if target:
        filters = ET.SubElement(elem, "Filters")
        ET.SubElement(filters, "FilterGroup", {
            "bool": "AND", "not": "1" if target["not"] else "0", "name": target["name"], "sid": target["sid"],
            "userContext": "1", "primaryGroup": "0", "localGroup": "0"})


def apply(kind: Kind, root: ET.Element, body_items, ctx: Context, now: datetime | None = None):
    """New root from the PUT body. Returns (root, changed); raises ApiError 422 with items.N.<field>."""
    f = Fields()
    if not isinstance(body_items, list):
        f.add("items", "Bitte eine Liste angeben.")
        f.raise_if_any()
    if len(body_items) > MAX_ITEMS:
        f.add("items", f"Höchstens {MAX_ITEMS} Einträge.")
        f.raise_if_any()
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S")
    existing = {(e.get("uid") or "").upper(): e for e in items(root)}
    keys: dict = {}
    # Kept read-only items occupy their unique key wherever they are in the list.
    for it in body_items:
        uid = it.get("uid") if isinstance(it, dict) else None
        base = existing.get(uid.upper()) if isinstance(uid, str) else None
        if base is not None and readonly_reason(kind, base, ctx) and base.tag == kind.item_tag:
            try:
                key = kind.unique(kind.fields(base, ctx))
            except (KeyError, ValueError):
                key = None
            if key is not None:
                keys.setdefault(key, -1)

    new_items, seen = [], set()
    for i, it in enumerate(body_items):
        name = f"items.{i}"
        if not isinstance(it, dict):
            f.add(name, "Bitte ein Objekt angeben.")
            continue
        uid = it.get("uid")
        uid = uid.upper() if isinstance(uid, str) and _UID.match(uid) else None
        if uid in seen:
            uid = None
        base = existing.get(uid) if uid else None
        if base is not None and readonly_reason(kind, base, ctx):
            new_items.append(copy.deepcopy(base))
            seen.add(uid)
            continue
        before = len(f)
        v = kind.check(it, ctx, f, name)
        target = check_target(it, ctx, f, name)
        if len(f) == before:
            key = kind.unique(v)
            if key is not None:
                if key in keys:
                    f.add(f"{name}.{kind.unique_field}" if hasattr(kind, "unique_field") else name, kind.unique_error)
                keys.setdefault(key, i)
        if len(f) != before:
            continue
        new_uid = uid or "{" + str(uuid.uuid4()).upper() + "}"
        elem = copy.deepcopy(base) if base is not None else ET.Element(kind.item_tag)
        elem.set("clsid", kind.item_clsid)
        kind.build(elem, v, ctx)
        elem.set("changed", base.get("changed", stamp) if base is not None else stamp)
        elem.set("uid", new_uid)
        if base is None and kind.bypass_errors:
            elem.set("bypassErrors", "1")
        _write_target(elem, target)
        if base is None or _semantic(elem) != _semantic(base):
            elem.set("changed", stamp)
        new_items.append(elem)
        seen.add(new_uid)
    f.raise_if_any()

    new_root = ET.Element(kind.root_tag, dict(root.attrib) or {"clsid": kind.root_clsid})
    new_root.set("clsid", root.get("clsid") or kind.root_clsid)
    for e in new_items:
        new_root.append(e)
    return new_root, serialize(new_root) != serialize(root)


def _set_common(elem: ET.Element, name: str, action: str) -> None:
    """name/status/image like the GPMC (image = icon index of the action)."""
    elem.set("name", name)
    elem.set("status", name)
    elem.set("image", IMAGES[action])


def _order_props(p: ET.Element, values: dict) -> None:
    """Set the Properties attributes in the GPMC's order; unknown attributes stay behind them."""
    rest = {k: v for k, v in p.attrib.items() if k not in values}
    p.attrib.clear()
    p.attrib.update(values)
    p.attrib.update(rest)


# --- local groups (Machine\Preferences\Groups\Groups.xml) -------------------------------------------------

BUILTIN_GROUPS = {
    "administrators": ("S-1-5-32-544", "Administrators (built-in)"),
    "users": ("S-1-5-32-545", "Users (built-in)"),
    "backup_operators": ("S-1-5-32-551", "Backup Operators (built-in)"),
    "remote_desktop_users": ("S-1-5-32-555", "Remote Desktop Users (built-in)"),
    "network_configuration_operators": ("S-1-5-32-556", "Network Configuration Operators (built-in)"),
    "event_log_readers": ("S-1-5-32-573", "Event Log Readers (built-in)"),
    "remote_management_users": ("S-1-5-32-580", "Remote Management Users (built-in)"),
}
_GROUP_BY_SID = {sid: key for key, (sid, _) in BUILTIN_GROUPS.items()}
MAX_MEMBERS = 100


def _lg_fields(elem: ET.Element, ctx: Context) -> dict:
    p = props(elem)
    members = []
    m_parent = p.find("Members")
    for m in (list(m_parent) if m_parent is not None else []):
        acc = ctx.account_by_sid(m.get("sid", "")) if m.get("sid") else None
        members.append({"id": acc["id"] if acc else "", "name": acc["name"] if acc else m.get("name", ""),
                        "kind": acc["kind"] if acc else "", "action": "remove" if m.get("action") == "REMOVE" else "add"})
    return {"group": _GROUP_BY_SID.get(p.get("groupSid", "").upper(), ""), "members": members,
            "remove_other_users": p.get("deleteAllUsers") == "1", "remove_other_groups": p.get("deleteAllGroups") == "1"}


def _lg_readonly(elem: ET.Element, ctx: Context) -> str:
    p = props(elem)
    if p.get("groupSid", "").upper() not in _GROUP_BY_SID:
        return f"Lokale Gruppe {p.get('groupName') or p.get('groupSid')} wird von PK95 AD nicht verwaltet."
    if (p.get("action", "U") != "U" or p.get("newName") or p.get("removeAccounts") == "1"
            or p.get("userAction")):
        return "Umbenennen, Löschen, Kontenentfernung oder „aktueller Benutzer“ nur in der GPMC bearbeitbar."
    m_parent = p.find("Members")
    for m in (list(m_parent) if m_parent is not None else []):
        if not m.get("sid") or ctx.account_by_sid(m.get("sid")) is None:
            return f"Mitglied {m.get('name') or m.get('sid')} ist kein Domänenkonto. Nur in der GPMC bearbeitbar."
    return ""


def _lg_check(item: dict, ctx: Context, f: Fields, name: str) -> dict:
    group = item.get("group")
    if group not in BUILTIN_GROUPS:
        f.add(f"{name}.group", "Erlaubt: " + ", ".join(BUILTIN_GROUPS) + ".")
    v = {"group": group, "members": []}
    for flag in ("remove_other_users", "remove_other_groups"):
        v[flag], err = validate.boolean(item.get(flag, False))
        f.add(f"{name}.{flag}", err)
    members = item.get("members", [])
    if not isinstance(members, list):
        f.add(f"{name}.members", "Bitte eine Liste von Mitgliedern angeben.")
        members = []
    if len(members) > MAX_MEMBERS:
        f.add(f"{name}.members", f"Höchstens {MAX_MEMBERS} Mitglieder.")
    seen = set()
    for j, m in enumerate(members):
        mname = f"{name}.members.{j}"
        if not isinstance(m, dict) or not m.get("id"):
            f.add(f"{mname}.id", "Bitte ein Konto auswählen.")
            continue
        action = m.get("action", "add")
        if action not in ("add", "remove"):
            f.add(f"{mname}.action", "Erlaubt: add, remove.")
            continue
        acc = ctx.account_by_id(m["id"])
        if isinstance(acc, str):
            f.add(f"{mname}.id", acc)
            continue
        if acc["sid"] in seen:
            f.add(f"{mname}.id", "Dieses Konto steht schon in der Liste.")
            continue
        seen.add(acc["sid"])
        if group == "administrators" and acc["sid"] == ctx.domain_admins_sid and action == "remove":
            f.add(f"{mname}.action", "Domain Admins kann nicht aus den lokalen Administratoren entfernt werden.")
            continue
        v["members"].append({"name": acc["name"], "sid": acc["sid"], "action": action})
    # Never lock out: with "remove others" the Administrators keep Domain Admins.
    if (group == "administrators" and (v["remove_other_users"] or v["remove_other_groups"])
            and ctx.domain_admins_sid and ctx.domain_admins_sid not in seen):
        v["members"].insert(0, {"name": ctx.domain_admins_name, "sid": ctx.domain_admins_sid, "action": "add"})
    return v


def _lg_build(elem: ET.Element, v: dict, ctx: Context) -> None:
    sid, gname = BUILTIN_GROUPS[v["group"]]
    elem.set("name", gname)  # local group items carry no status attribute
    elem.set("image", IMAGES["U"])
    p = elem.find("Properties")
    if p is None:
        p = ET.SubElement(elem, "Properties")
    _order_props(p, {"action": "U", "newName": "", "description": p.get("description", ""),
                     "deleteAllUsers": "1" if v["remove_other_users"] else "0",
                     "deleteAllGroups": "1" if v["remove_other_groups"] else "0",
                     "removeAccounts": "0", "groupSid": sid, "groupName": gname})
    for old in p.findall("Members"):
        p.remove(old)
    members = ET.SubElement(p, "Members")
    for m in v["members"]:
        ET.SubElement(members, "Member", {"name": m["name"], "action": "ADD" if m["action"] == "add" else "REMOVE",
                                          "sid": m["sid"]})


LOCAL_GROUPS = Kind(
    name="local_groups", route="local-groups", scope="computer",
    path=("Machine", "Preferences", "Groups", "Groups.xml"),
    root_tag="Groups", root_clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}",
    item_tag="Group", item_clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}",
    cse="{17D89FEC-5C44-4972-B12D-241CAEF74509}", tool="{79F92669-4224-476C-9C5C-6EFB4D87DF4A}",
    fields=_lg_fields, check=_lg_check, build=_lg_build,
    unique=lambda v: v.get("group") or None, unique_error="Diese lokale Gruppe steht schon in der Richtlinie.",
    extra_readonly=_lg_readonly, bypass_errors=False,
)
LOCAL_GROUPS.unique_field = "group"


# --- printers (User\Preferences\Printers\Printers.xml) ---------------------------------------------------

_SHARE = re.compile(r"^\\\\[^\\/\s]+\\[^\\/]+$")


def _pr_fields(elem: ET.Element, ctx: Context) -> dict:
    p = props(elem)
    action = next((k for k, a in ACTIONS.items() if a == p.get("action", "U")), "update")
    return {"path": p.get("path", ""), "action": action, "default": p.get("default") == "1"}


def _pr_check(item: dict, ctx: Context, f: Fields, name: str) -> dict:
    path = validate.text(item.get("path"))
    if not _SHARE.match(path) or len(path) > 260:
        f.add(f"{name}.path", "Bitte die Freigabe angeben: \\\\server\\drucker.")
    default, err = validate.boolean(item.get("default", False))
    f.add(f"{name}.default", err)
    return {"path": path, "action": check_action(item, f, name), "default": bool(default)}


def _pr_build(elem: ET.Element, v: dict, ctx: Context) -> None:
    action = ACTIONS[v["action"]]
    _set_common(elem, v["path"].rsplit("\\", 1)[-1], action)
    p = elem.find("Properties")
    if p is None:
        p = ET.SubElement(elem, "Properties")
    _order_props(p, {"action": action, "comment": p.get("comment", ""), "path": v["path"],
                     "location": p.get("location", ""), "default": "1" if v["default"] else "0",
                     "skipLocal": p.get("skipLocal", "0"), "deleteAll": "0", "persistent": p.get("persistent", "0"),
                     "deleteMaps": "0", "port": ""})


PRINTERS = Kind(
    name="printers", route="printers", scope="user",
    path=("User", "Preferences", "Printers", "Printers.xml"),
    root_tag="Printers", root_clsid="{1F577D12-3D1B-471e-A1B7-060317597B9C}",
    item_tag="SharedPrinter", item_clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}",
    cse="{BC75B1ED-5833-4858-9BB8-CBF0B166DF9D}", tool="{A8C42CEA-CDB8-4388-97F4-5831F933DA84}",
    fields=_pr_fields, check=_pr_check, build=_pr_build,
    unique=lambda v: v["path"].lower(), unique_error="Dieser Drucker steht schon in der Richtlinie.",
    extra_readonly=lambda e, c: ("Nur in der GPMC bearbeitbar (Aktion „Alle löschen“)."
                                 if props(e).get("deleteAll") == "1" else ""),
)
PRINTERS.unique_field = "path"


# --- shortcuts (User\Preferences\Shortcuts\Shortcuts.xml) ------------------------------------------------

LOCATIONS = {"desktop": "%DesktopDir%", "start_menu": "%StartMenuDir%", "programs": "%ProgramsDir%"}
TARGET_TYPES = {"url": "URL", "file": "FILESYSTEM"}
_SHORTCUT_NAME = re.compile(r'^[^\\/:*?"<>|\x00-\x1f]{1,100}$')
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]{0,1990}$", re.I)
_ICON = re.compile(r"^(\\\\[^\\/\s]+\\.+|%[A-Za-z]+%\\.+|[A-Za-z]:\\.+)$")


def _sc_split(shortcut_path: str):
    for key, var in LOCATIONS.items():
        if shortcut_path.lower().startswith(var.lower() + "\\"):
            return key, shortcut_path[len(var) + 1:]
    return "", shortcut_path


def _sc_fields(elem: ET.Element, ctx: Context) -> dict:
    p = props(elem)
    location, name = _sc_split(p.get("shortcutPath", ""))
    action = next((k for k, a in ACTIONS.items() if a == p.get("action", "U")), "update")
    tt = next((k for k, t in TARGET_TYPES.items() if t == p.get("targetType")), "")
    return {"name": name, "target_type": tt, "target_path": p.get("targetPath", ""), "location": location,
            "arguments": p.get("arguments", ""), "icon_path": p.get("iconPath", ""),
            "icon_index": int(p.get("iconIndex", "0") or 0), "action": action}


def _sc_readonly(elem: ET.Element, ctx: Context) -> str:
    p = props(elem)
    if p.get("targetType") not in TARGET_TYPES.values():
        return "Verknüpfung auf ein Shell-Objekt. Nur in der GPMC bearbeitbar."
    if not _sc_split(p.get("shortcutPath", ""))[0]:
        return "Verknüpfung an einem anderen Ort. Nur in der GPMC bearbeitbar."
    if p.get("pidl") or p.get("startIn") or p.get("shortcutKey", "0") not in ("", "0"):
        return "Verknüpfung mit Zusatzoptionen der GPMC. Nur dort bearbeitbar."
    return ""


def _sc_check(item: dict, ctx: Context, f: Fields, name: str) -> dict:
    v = {"action": check_action(item, f, name)}
    sname = item.get("name")
    if not isinstance(sname, str) or not _SHORTCUT_NAME.match(sname.strip()) or sname.strip() in (".", ".."):
        f.add(f"{name}.name", 'Name mit 1–100 Zeichen, ohne \\ / : * ? " < > |.')
        sname = "x"
    v["name"] = sname.strip()
    tt = item.get("target_type")
    if tt not in TARGET_TYPES:
        f.add(f"{name}.target_type", "Erlaubt: url, file.")
    v["target_type"] = tt
    tp = validate.text(item.get("target_path"))
    if tt == "url" and not _URL.match(tp):
        f.add(f"{name}.target_path", "Bitte eine Adresse angeben (https://…).")
    if tt == "file":
        tp, err = validate.unc_path(tp)
        f.add(f"{name}.target_path", err or (None if tp else "Bitte einen UNC-Pfad angeben, z. B. \\\\server\\freigabe\\datei."))
    v["target_path"] = tp
    location = item.get("location", "desktop")
    if location not in LOCATIONS:
        f.add(f"{name}.location", "Erlaubt: desktop, start_menu, programs.")
    v["location"] = location
    args, err = validate.optional_text(item.get("arguments"), 260)
    f.add(f"{name}.arguments", err)
    if args and tt != "file":
        f.add(f"{name}.arguments", "Nur bei Verknüpfungen auf Dateien.")
    v["arguments"] = args
    icon, err = validate.optional_text(item.get("icon_path"), 260)
    if not err and icon and not _ICON.match(icon):
        err = "UNC- oder %Variable%-Pfad, z. B. %SystemRoot%\\System32\\shell32.dll."
    f.add(f"{name}.icon_path", err)
    v["icon_path"] = icon
    idx, err = validate.integer(item.get("icon_index", 0), 0, 255)  # xs:unsignedByte in MS-GPPREF
    f.add(f"{name}.icon_index", err)
    v["icon_index"] = idx if not err else 0
    return v


def _sc_build(elem: ET.Element, v: dict, ctx: Context) -> None:
    action = ACTIONS[v["action"]]
    _set_common(elem, v["name"], action)
    p = elem.find("Properties")
    if p is None:
        p = ET.SubElement(elem, "Properties")
    _order_props(p, {"pidl": "", "targetType": TARGET_TYPES[v["target_type"]], "action": action,
                     "comment": p.get("comment", ""), "shortcutKey": "0", "startIn": "", "arguments": v["arguments"],
                     "iconIndex": str(v["icon_index"]), "targetPath": v["target_path"], "iconPath": v["icon_path"],
                     "window": p.get("window", ""), "shortcutPath": f"{LOCATIONS[v['location']]}\\{v['name']}"})


SHORTCUTS = Kind(
    name="shortcuts", route="shortcuts", scope="user",
    path=("User", "Preferences", "Shortcuts", "Shortcuts.xml"),
    root_tag="Shortcuts", root_clsid="{872ECB34-B2EC-401b-A585-D32574AA90EE}",
    item_tag="Shortcut", item_clsid="{4F2F7C55-2790-433e-8127-0739D1CFA327}",
    cse="{C418DD9D-0D14-4efb-8FBF-CFE535C8FAC7}", tool="{CEFFA6E2-E3BD-421B-852C-6F6A79A59BC1}",
    fields=_sc_fields, check=_sc_check, build=_sc_build,
    unique=lambda v: (v["location"], v["name"].lower()), unique_error="Eine Verknüpfung mit diesem Namen gibt es hier schon.",
    extra_readonly=_sc_readonly,
)
SHORTCUTS.unique_field = "name"

KINDS = {k.route: k for k in (LOCAL_GROUPS, PRINTERS, SHORTCUTS)}
