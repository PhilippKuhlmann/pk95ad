"""Group Policy Preferences → Drive Maps (User\\Preferences\\Drives\\Drives.xml), docs/api.md → Drive maps.

Pure functions on ElementTree elements, so the XML can be tested without Samba. Items the GPMC wrote with
features PK95 AD does not edit (stored password, other targeting filters, run-as user, disabled) are kept
byte-for-byte as long as their uid is sent back.
"""

from __future__ import annotations

import copy
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from . import validate
from .errors import Fields

DRIVES_CLSID = "{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}"
DRIVE_CLSID = "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}"
CSE = "{5794DAFD-BE60-433F-88A2-1A31939AC01F}"
TOOL = "{2EA1A81B-48E5-45E9-8BB7-A6E3AC170006}"
MAX_ITEMS = 50

ACTIONS = {"create": "C", "replace": "R", "update": "U", "delete": "D"}
IMAGES = {"C": "0", "R": "1", "U": "2", "D": "3"}  # icon index the GPMC writes per action
VISIBILITY = {"unchanged": "NOCHANGE", "hide": "HIDE", "show": "SHOW"}
PASSWORD_WARNING = "Enthält ein gespeichertes Kennwort (unsicher, MS14-025). Bitte in der GPMC entfernen."
_UID = re.compile(r"^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$")


class DrivesError(ValueError):
    """Drives.xml cannot be read."""


def parse(data: bytes) -> ET.Element:
    """Root <Drives> element (a new one for an empty file)."""
    if not data.strip():
        return ET.Element("Drives", {"clsid": DRIVES_CLSID})
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise DrivesError(f"Drives.xml ist kein gültiges XML ({exc}).") from exc
    if root.tag != "Drives":
        raise DrivesError("Drives.xml hat kein <Drives>-Element.")
    return root


def serialize(root: ET.Element) -> bytes:
    body = ET.tostring(root, encoding="unicode", short_empty_elements=True)
    return ('<?xml version="1.0" encoding="utf-8"?>\r\n' + body).encode("utf-8")


def items(root: ET.Element) -> list[ET.Element]:
    return [e for e in root if e.tag == "Drive"]


def _props(elem: ET.Element) -> ET.Element:
    p = elem.find("Properties")
    return p if p is not None else ET.Element("Properties")


def _filter_group(elem: ET.Element):
    """(sid, name, not) of the single group filter, None when there is no filter, False when it is other."""
    filters = elem.find("Filters")
    if filters is None or len(filters) == 0:
        return None
    if len(filters) != 1 or filters[0].tag != "FilterGroup":
        return False
    f = filters[0]
    if f.get("bool", "AND") != "AND" or f.get("localGroup", "0") != "0" or f.get("primaryGroup", "0") != "0":
        return False
    return f.get("sid", ""), f.get("name", ""), f.get("not", "0") == "1"


def readonly_reason(elem: ET.Element) -> str:
    p = _props(elem)
    if p.get("cpassword"):
        return PASSWORD_WARNING
    if p.get("userName"):
        return "Verbindet mit einem anderen Benutzerkonto („Verbinden als“). Nur in der GPMC bearbeitbar."
    if elem.get("disabled") == "1":
        return "In der GPMC deaktiviert. Nur dort bearbeitbar."
    if p.get("action", "U") not in IMAGES:
        return "Unbekannte Aktion. Nur in der GPMC bearbeitbar."
    if _filter_group(elem) is False:
        return "Zielgruppenadressierung mit Bedingungen, die PK95 AD nicht bearbeitet. Nur in der GPMC bearbeitbar."
    return ""


def changed_ms(value: str) -> int:
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return 0
    return int(dt.timestamp() * 1000)


def to_json(elem: ET.Element, group_by_sid) -> dict:
    """group_by_sid(sid) -> {"id", "name"} or None."""
    p = _props(elem)
    action = next((k for k, v in ACTIONS.items() if v == p.get("action", "U")), "update")
    visibility = next((k for k, v in VISIBILITY.items() if v == p.get("thisDrive", "NOCHANGE")), "unchanged")
    target = None
    fg = _filter_group(elem)
    if fg:
        sid, name, negate = fg
        g = group_by_sid(sid) if sid else None
        target = {"group_id": g["id"] if g else "", "group_name": g["name"] if g else name.split("\\")[-1],
                  "not": negate}
    reason = readonly_reason(elem)
    if not reason and fg and not target["group_id"]:
        reason = f"Die Zielgruppe {fg[1] or fg[0]} gibt es nicht mehr."
    return {
        "uid": (elem.get("uid") or "").upper(),
        "letter": (p.get("letter") or "").upper()[:1],
        "first_available": p.get("useLetter", "1") == "0",
        "path": p.get("path", ""),
        "label": p.get("label", ""),
        "action": action,
        "reconnect": p.get("persistent", "0") == "1",
        "visibility": visibility,
        "target": target,
        "changed_at": changed_ms(elem.get("changed", "")),
        "readonly": bool(reason),
        "warning": reason,
    }


def _build(base: ET.Element | None, v: dict, uid: str, changed: str) -> ET.Element:
    """A <Drive> element from validated values; keeps unknown attributes of base."""
    elem = copy.deepcopy(base) if base is not None else ET.Element("Drive")
    action = ACTIONS[v["action"]]
    name = v["path"] if v["first_available"] else f"{v['letter']}:"
    attrs = {"clsid": DRIVE_CLSID, "name": name, "status": name, "image": IMAGES[action], "changed": changed,
             "uid": uid}
    if base is None:
        attrs["bypassErrors"] = "1"
    for k, val in attrs.items():
        elem.set(k, val)
    p = elem.find("Properties")
    if p is None:
        p = ET.SubElement(elem, "Properties")
    props = {"action": action, "thisDrive": VISIBILITY[v["visibility"]], "allDrives": p.get("allDrives", "NOCHANGE"),
             "userName": "", "path": v["path"], "label": v["label"], "persistent": "1" if v["reconnect"] else "0",
             "useLetter": "0" if v["first_available"] else "1", "letter": v["letter"]}
    for k, val in props.items():
        p.set(k, val)
    for f in elem.findall("Filters"):
        elem.remove(f)
    if v["target"]:
        t = v["target"]
        filters = ET.SubElement(elem, "Filters")
        ET.SubElement(filters, "FilterGroup", {
            "bool": "AND", "not": "1" if t["not"] else "0", "name": t["name"], "sid": t["sid"],
            "userContext": "1", "primaryGroup": "0", "localGroup": "0"})
    return elem


def _semantic(elem: ET.Element) -> tuple:
    p = _props(elem)
    fg = _filter_group(elem) or None
    return (p.get("action"), p.get("thisDrive"), p.get("path"), p.get("label"), p.get("persistent"),
            p.get("useLetter"), p.get("letter"), fg)


def apply(root: ET.Element, body_items, group_by_id, now: datetime | None = None) -> tuple[ET.Element, bool]:
    """New root from the PUT body. group_by_id(id) -> {"name": "NB\\Group", "sid"} or an error string.

    Returns (root, changed). Raises ApiError 422 with fields items.N.<field>.
    """
    f = Fields()
    if not isinstance(body_items, list):
        f.add("items", "Bitte eine Liste von Laufwerken angeben.")
        f.raise_if_any()
    if len(body_items) > MAX_ITEMS:
        f.add("items", f"Höchstens {MAX_ITEMS} Laufwerke.")
        f.raise_if_any()
    stamp = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%d %H:%M:%S")
    existing = {(e.get("uid") or "").upper(): e for e in items(root)}
    new_items: list[ET.Element] = []
    seen_uids: set[str] = set()
    letters: dict[str, int] = {}
    # Read-only items that are kept occupy their letter whatever their position in the list.
    for it in body_items:
        uid = it.get("uid") if isinstance(it, dict) else None
        base = existing.get(uid.upper()) if isinstance(uid, str) else None
        if base is not None and readonly_reason(base):
            p = _props(base)
            if p.get("useLetter", "1") != "0" and p.get("letter"):
                letters.setdefault(p.get("letter").upper(), -1)

    for i, it in enumerate(body_items):
        name = f"items.{i}"
        if not isinstance(it, dict):
            f.add(name, "Bitte ein Objekt angeben.")
            continue
        uid = it.get("uid")
        uid = uid.upper() if isinstance(uid, str) and _UID.match(uid) else None
        if uid in seen_uids:
            uid = None  # a duplicated uid becomes a new item
        base = existing.get(uid) if uid else None
        if base is not None and readonly_reason(base):
            new_items.append(copy.deepcopy(base))
            seen_uids.add(uid)
            continue

        v = {}
        letter = it.get("letter")
        if not isinstance(letter, str) or not re.match(r"^[A-Za-z]:?$", letter.strip()):
            f.add(f"{name}.letter", "Bitte einen Laufwerksbuchstaben A–Z angeben.")
            letter = "Z"
        v["letter"] = letter.strip()[0].upper()
        v["first_available"], err = validate.boolean(it.get("first_available", False))
        f.add(f"{name}.first_available", err)
        path, err = validate.unc_path(it.get("path"))
        if not err and not path:
            err = "Bitte einen UNC-Pfad angeben, z. B. \\\\server\\freigabe."
        f.add(f"{name}.path", err)
        v["path"] = path
        v["label"], err = validate.optional_text(it.get("label"), 128)
        f.add(f"{name}.label", err)
        action = it.get("action", "update")
        if action not in ACTIONS:
            f.add(f"{name}.action", "Erlaubt: create, replace, update, delete.")
            action = "update"
        v["action"] = action
        v["reconnect"], err = validate.boolean(it.get("reconnect", True))
        f.add(f"{name}.reconnect", err)
        visibility = it.get("visibility", "unchanged")
        if visibility not in VISIBILITY:
            f.add(f"{name}.visibility", "Erlaubt: unchanged, hide, show.")
            visibility = "unchanged"
        v["visibility"] = visibility
        v["target"] = None
        target = it.get("target")
        if target is not None:
            if not isinstance(target, dict) or not target.get("group_id"):
                f.add(f"{name}.target.group_id", "Bitte eine Gruppe auswählen.")
            else:
                g = group_by_id(target.get("group_id"))
                if isinstance(g, str):
                    f.add(f"{name}.target.group_id", g)
                else:
                    negate, err = validate.boolean(target.get("not", False))
                    f.add(f"{name}.target.not", err)
                    v["target"] = {"name": g["name"], "sid": g["sid"], "not": bool(negate)}
        if v["first_available"] is False and not f.get(f"{name}.letter"):
            if v["letter"] in letters:
                f.add(f"{name}.letter", f"Laufwerk {v['letter']}: ist in dieser Richtlinie schon belegt.")
            letters.setdefault(v["letter"], i)
        if any(k.startswith(name + ".") or k == name for k in f):
            continue

        new_uid = uid or "{" + str(uuid.uuid4()).upper() + "}"
        candidate = _build(base, v, new_uid, base.get("changed", stamp) if base is not None else stamp)
        if base is None or _semantic(candidate) != _semantic(base):
            candidate.set("changed", stamp)
        new_items.append(candidate)
        seen_uids.add(new_uid)
    f.raise_if_any()

    new_root = ET.Element("Drives", dict(root.attrib) or {"clsid": DRIVES_CLSID})
    new_root.set("clsid", root.get("clsid") or DRIVES_CLSID)
    for e in new_items:
        new_root.append(e)
    changed = serialize(new_root) != serialize(root)
    return new_root, changed
