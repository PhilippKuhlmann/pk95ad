"""Users, groups and computers (docs/api.md)."""

from __future__ import annotations

import re

from . import validate
from .directory import (
    NT_NEVER, UF_ACCOUNTDISABLE, UF_DONT_EXPIRE_PASSWD, UF_LOCKOUT, UF_NORMAL_ACCOUNT, UF_SERVER_TRUST,
    Session, gentime_ms, ms_to_nt, nt_to_ms, upn_suffixes,
)
from .errors import ApiError, Fields, forbidden, invalid, not_found
from .store import now_ms

MAX_ITEMS = 2000
IN_CHAIN = "1.2.840.113556.1.4.1941"
RID_ADMINISTRATOR = 500
RID_KRBTGT = 502

WELL_KNOWN = {
    "S-1-1-0": "Jeder",
    "S-1-5-4": "Interaktiv",
    "S-1-5-9": "Enterprise Domain Controllers",
    "S-1-5-11": "Authentifizierte Benutzer",
    "S-1-5-17": "IUSR",
    "S-1-5-18": "System",
}

USER_ATTRS = [
    "objectGUID", "objectSid", "objectClass", "sAMAccountName", "userPrincipalName", "displayName", "givenName",
    "sn", "mail", "description", "userAccountControl", "msDS-User-Account-Control-Computed", "pwdLastSet",
    "accountExpires", "lastLogonTimestamp", "isCriticalSystemObject", "whenCreated", "whenChanged",
    "badPwdCount", "lockoutTime", "profilePath", "homeDirectory", "homeDrive", "scriptPath", "primaryGroupID",
    "memberOf", "cn",
]
GROUP_ATTRS = [
    "objectGUID", "objectSid", "objectClass", "sAMAccountName", "cn", "description", "mail", "groupType",
    "member", "memberOf", "isCriticalSystemObject",
]
COMPUTER_ATTRS = [
    "objectGUID", "objectSid", "objectClass", "sAMAccountName", "cn", "dNSHostName", "operatingSystem",
    "operatingSystemVersion", "description", "userAccountControl", "lastLogonTimestamp", "whenCreated",
    "memberOf",
]

GT_BUILTIN_LOCAL = 0x1
GT_GLOBAL = 0x2
GT_DOMAIN_LOCAL = 0x4
GT_UNIVERSAL = 0x8
GT_SECURITY = 0x80000000
SCOPES = {"global": GT_GLOBAL, "domain_local": GT_DOMAIN_LOCAL, "universal": GT_UNIVERSAL}


def _enc(s: Session, value: str) -> str:
    return s.ldb.binary_encode(value)


def _search_filter(s: Session, text: str, attrs: list[str]) -> str:
    v = (text or "").strip()
    if not v:
        return ""
    e = _enc(s, v)
    return "(|" + "".join(f"({a}=*{e}*)" for a in attrs) + ")"


def _scope(s: Session, ou_id: str, recursive: bool):
    if not ou_id:
        return None, "sub"
    msg = s.find(ou_id, attrs=["objectClass"], what="Organisationseinheit")
    return msg.dn, ("sub" if recursive else "one")


def _builtin(s: Session, msg) -> bool:
    sid = s.sid(msg)
    if s.rid(sid) < 1000 or not sid.startswith(s.domain_sid + "-"):
        return True
    if s.val(msg, "isCriticalSystemObject").upper() == "TRUE":
        return True
    return str(msg.dn.parent()).lower() == f"cn=builtin,{s.base_str}".lower()


# --- users -------------------------------------------------------------------------------------------

def _user(s: Session, msg, details: bool = False) -> dict:
    uac = s.num(msg, "userAccountControl")
    computed = s.num(msg, "msDS-User-Account-Control-Computed")
    sid = s.sid(msg)
    rid = s.rid(sid)
    ou_id, ou_path = s.parent_info(msg.dn)
    builtin = rid < 1000
    out = {
        "id": s.guid(msg),
        "username": s.val(msg, "sAMAccountName"),
        "upn": s.val(msg, "userPrincipalName"),
        "display_name": s.val(msg, "displayName") or s.val(msg, "cn"),
        "given_name": s.val(msg, "givenName"),
        "surname": s.val(msg, "sn"),
        "email": s.val(msg, "mail"),
        "description": s.val(msg, "description"),
        "ou_id": ou_id,
        "ou_path": ou_path,
        "enabled": not uac & UF_ACCOUNTDISABLE,
        "locked": bool(computed & UF_LOCKOUT),
        "must_change_password": s.val(msg, "pwdLastSet", "x") == "0",
        "password_never_expires": bool(uac & UF_DONT_EXPIRE_PASSWD),
        "expires_at": nt_to_ms(s.val(msg, "accountExpires", "0")),
        "last_logon": nt_to_ms(s.val(msg, "lastLogonTimestamp", "0")),
        "builtin": builtin,
        "protected": builtin,
    }
    if details:
        pgid = s.num(msg, "primaryGroupID")
        primary = None
        if pgid:
            res = s.search(expression=f"(objectSid={s.domain_sid}-{pgid})", attrs=["objectGUID", "sAMAccountName"])
            if len(res):
                primary = {"id": s.guid(res[0]), "name": s.val(res[0], "sAMAccountName")}
        out.update({
            "dn": str(msg.dn),
            "sid": sid,
            "created_at": gentime_ms(s.val(msg, "whenCreated")),
            "changed_at": gentime_ms(s.val(msg, "whenChanged")),
            "password_last_set": nt_to_ms(s.val(msg, "pwdLastSet", "0")),
            "bad_password_count": s.num(msg, "badPwdCount"),
            "locked_at": nt_to_ms(s.val(msg, "lockoutTime", "0")) if computed & UF_LOCKOUT else 0,
            "profile_path": s.val(msg, "profilePath"),
            "home_directory": s.val(msg, "homeDirectory"),
            "home_drive": s.val(msg, "homeDrive"),
            "script_path": s.val(msg, "scriptPath"),
            "primary_group": primary,
            "groups": _groups_brief(s, s.vals(msg, "memberOf")),
        })
    return out


def _groups_brief(s: Session, dns: list[str]) -> list[dict]:
    out = []
    for dn in dns:
        g = s.by_dn(dn, GROUP_ATTRS)
        if g is None:
            continue
        typ, scope = _group_type(s.num(g, "groupType"))
        out.append({"id": s.guid(g), "name": s.val(g, "sAMAccountName") or s.val(g, "cn"),
                    "scope": scope, "type": typ, "builtin": _builtin(s, g)})
    out.sort(key=lambda x: x["name"].casefold())
    return out


def _find_user(s: Session, oid: str):
    msg = s.find(oid, attrs=USER_ATTRS, what="Benutzer")
    c = s.classes(msg)
    if "user" not in c or "computer" in c:
        raise not_found("Benutzer nicht gefunden.")
    return msg


def users_list(s: Session, q) -> dict:
    base, scope = _scope(s, q.q("ou_id"), q.flag("recursive"))
    expr = "(&(sAMAccountType=805306368)" + _search_filter(
        s, q.q("search"), ["sAMAccountName", "displayName", "mail", "userPrincipalName"]) + ")"
    items = [_user(s, m) for m in s.search(base=base, scope=scope, expression=expr, attrs=USER_ATTRS)]
    if not q.flag("all"):
        items = [u for u in items if u["username"].lower() != "krbtgt"]
    items.sort(key=lambda u: (u["display_name"] or u["username"]).casefold())
    return {"items": items[:MAX_ITEMS], "total": len(items)}


def user_get(s: Session, oid: str) -> dict:
    return _user(s, _find_user(s, oid), details=True)


def _expires(value, f: Fields, field: str = "expires_at"):
    if value is None or value == 0:
        return 0
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        f.add(field, "Bitte 0 (nie) oder einen Zeitpunkt in Millisekunden angeben.")
        return 0
    if value <= now_ms():
        f.add(field, "Das Ablaufdatum muss in der Zukunft liegen.")
    return value


def _user_fields(s: Session, body: dict, f: Fields, create: bool, current=None) -> dict:
    """Validated attribute values for the keys present in body."""
    v: dict = {}
    if create or "username" in body:
        v["username"], err = validate.sam_account_name(body.get("username"))
        f.add("username", err)
    for key, attr in (("given_name", "givenName"), ("surname", "sn")):
        if create or key in body:
            v[key], err = validate.optional_text(body.get(key), 64)
            f.add(key, err)
    if create or "display_name" in body:
        dn_value = body.get("display_name")
        if create and not (isinstance(dn_value, str) and dn_value.strip()):
            dn_value = " ".join(x for x in (v.get("given_name"), v.get("surname")) if x) or v.get("username", "")
        if isinstance(dn_value, str):
            dn_value = dn_value.strip()
        v["display_name"], err = validate.object_name(dn_value, max_len=64, what="Anzeigenamen")
        f.add("display_name", err)
    if create or "upn" in body:
        upn = validate.text(body.get("upn"))
        if not upn and create:
            upn = f"{v.get('username', '')}@{s.realm}"
        if upn:
            name, _, suffix = upn.rpartition("@")
            if not name or not suffix or re.search(r'[\s"/\\\[\]:;|=,+*?<>@]', name):
                f.add("upn", "Bitte name@domäne angeben.")
            elif suffix.lower() not in upn_suffixes(s):
                f.add("upn", "Unbekanntes UPN-Suffix. Erlaubt: " + ", ".join(upn_suffixes(s)) + ".")
            upn = f"{name}@{suffix.lower()}"
        v["upn"] = upn
    if create or "email" in body:
        v["email"], err = validate.email(body.get("email"))
        f.add("email", err)
    if create or "description" in body:
        v["description"], err = validate.optional_text(body.get("description"), 1024)
        f.add("description", err)
    for key in ("profile_path", "home_directory"):
        if create or key in body:
            v[key], err = validate.unc_path(body.get(key))
            f.add(key, err)
    if create or "home_drive" in body:
        v["home_drive"], err = validate.home_drive(body.get("home_drive"))
        f.add("home_drive", err)
    if create or "script_path" in body:
        v["script_path"], err = validate.script_path(body.get("script_path"))
        f.add("script_path", err)
    for key, default in (("enabled", True), ("must_change_password", False), ("password_never_expires", False)):
        if key in body:
            v[key], err = validate.boolean(body.get(key))
            f.add(key, err)
        elif create:
            v[key] = default
    if create or "expires_at" in body:
        v["expires_at"] = _expires(body.get("expires_at"), f)
    drive = v.get("home_drive", current["home_drive"] if current else "")
    home = v.get("home_directory", current["home_directory"] if current else "")
    if drive and not home:
        f.add("home_drive", "Nur zusammen mit einem Basisordner.")
    return v


def _check_unique(s: Session, v: dict, f: Fields, exclude_dn=None) -> None:
    if v.get("username") and not s.unique_sam(v["username"], exclude_dn):
        f.add("username", "Diesen Anmeldenamen gibt es schon (Benutzer, Gruppe oder Computer).")
    if v.get("upn"):
        res = s.search(expression=f"(userPrincipalName={_enc(s, v['upn'])})", attrs=["dn"])
        if any(exclude_dn is None or str(m.dn).lower() != str(exclude_dn).lower() for m in res):
            f.add("upn", "Diesen UPN gibt es schon.")


def _resolve_groups(s: Session, ids, field: str, f: Fields) -> list:
    out = []
    if ids is None:
        return out
    if not isinstance(ids, list):
        f.add(field, "Bitte eine Liste von Gruppen angeben.")
        return out
    for i, gid in enumerate(ids):
        try:
            g = s.find(gid, attrs=GROUP_ATTRS, what="Gruppe")
        except ApiError:
            f.add(f"{field}.{i}", "Gruppe nicht gefunden.")
            continue
        if "group" not in s.classes(g):
            f.add(f"{field}.{i}", "Das ist keine Gruppe.")
            continue
        out.append(g)
    return out


def _pwd(password: str) -> bytes:
    return ('"' + password + '"').encode("utf-16-le")


ATTR_MAP = {
    "given_name": "givenName", "surname": "sn", "display_name": "displayName", "upn": "userPrincipalName",
    "email": "mail", "description": "description", "profile_path": "profilePath",
    "home_directory": "homeDirectory", "home_drive": "homeDrive", "script_path": "scriptPath",
    "username": "sAMAccountName",
}


def user_create(s: Session, body: dict) -> dict:
    f = Fields()
    v = _user_fields(s, body, f, create=True)
    password = body.get("password")
    if not isinstance(password, str) or not password:
        f.add("password", "Bitte ein Kennwort angeben.")
    parent = s.users_container()
    if body.get("ou_id"):
        try:
            parent = s.target_container(body["ou_id"], "ou_id")
        except ApiError as exc:
            f.update(exc.fields or {})
    groups = _resolve_groups(s, body.get("group_ids"), "group_ids", f)
    f.raise_if_any()
    _check_unique(s, v, f)
    dn = s.child_dn(parent, "CN", v["display_name"])
    if s.exists(dn):
        f.add("display_name", "In dieser Organisationseinheit gibt es schon ein Objekt mit diesem Namen.")
    f.raise_if_any()

    uac = UF_NORMAL_ACCOUNT
    if v["password_never_expires"]:
        uac |= UF_DONT_EXPIRE_PASSWD
    if not v["enabled"]:
        uac |= UF_ACCOUNTDISABLE
    msg = {"dn": str(dn), "objectClass": "user", "userAccountControl": str(uac), "unicodePwd": _pwd(password)}
    for key, attr in ATTR_MAP.items():
        if v.get(key):
            msg[attr] = v[key]
    with s.transaction():
        s.db.add(msg)
        extra = {}
        if v["must_change_password"]:
            extra["pwdLastSet"] = "0"
        if v["expires_at"]:
            extra["accountExpires"] = str(ms_to_nt(v["expires_at"]))
        s.replace(dn, extra)
        for g in groups:
            s.modify_values(g.dn, "member", add=[str(dn)])
    return _user(s, s.by_dn(dn, USER_ATTRS), details=True)


def user_update(s: Session, oid: str, body: dict) -> dict:
    msg = _find_user(s, oid)
    cur = _user(s, msg, details=True)
    rid = s.rid(cur["sid"])
    if rid == RID_KRBTGT:
        raise forbidden("Das Konto krbtgt kann nicht geändert werden.")
    f = Fields()
    allowed = set(ATTR_MAP) | {"enabled", "must_change_password", "password_never_expires", "expires_at"}
    for key in body:
        if key not in allowed:
            f.add(key, "Dieses Feld kann hier nicht geändert werden.")
    f.raise_if_any()
    v = _user_fields(s, body, f, create=False, current=cur)
    f.raise_if_any()
    if cur["protected"]:
        if "username" in v and v["username"] != cur["username"]:
            raise forbidden("Integrierte Konten können nicht umbenannt werden.")
        if "display_name" in v and v["display_name"] != cur["display_name"]:
            raise forbidden("Integrierte Konten können nicht umbenannt werden.")
        if rid == RID_ADMINISTRATOR and v.get("enabled") is False:
            raise forbidden("Das Konto Administrator kann nicht deaktiviert werden.")
    _check_unique(s, {k: v[k] for k in ("username", "upn") if k in v and v[k] != cur.get(k)}, f, msg.dn)
    new_dn = None
    if "display_name" in v and v["display_name"] != cur["display_name"]:
        new_dn = s.child_dn(msg.dn.parent(), "CN", v["display_name"])
        if str(new_dn).lower() != str(msg.dn).lower() and s.exists(new_dn):
            f.add("display_name", "In dieser Organisationseinheit gibt es schon ein Objekt mit diesem Namen.")
    if "upn" in v and not v["upn"]:
        f.add("upn", "Bitte einen UPN angeben.")
    f.raise_if_any()

    changes = {attr: v[key] for key, attr in ATTR_MAP.items() if key in v and key != "username"}
    if "username" in v:
        changes["sAMAccountName"] = v["username"]
    uac = s.num(msg, "userAccountControl")
    if "enabled" in v:
        uac = (uac & ~UF_ACCOUNTDISABLE) if v["enabled"] else (uac | UF_ACCOUNTDISABLE)
    if "password_never_expires" in v:
        uac = (uac | UF_DONT_EXPIRE_PASSWD) if v["password_never_expires"] else (uac & ~UF_DONT_EXPIRE_PASSWD)
    if uac != s.num(msg, "userAccountControl"):
        changes["userAccountControl"] = str(uac)
    if "expires_at" in v:
        changes["accountExpires"] = str(ms_to_nt(v["expires_at"])) if v["expires_at"] else str(NT_NEVER)
    if "must_change_password" in v and v["must_change_password"] != cur["must_change_password"]:
        changes["pwdLastSet"] = "0" if v["must_change_password"] else "-1"
    with s.transaction():
        s.replace(msg.dn, changes)
        if new_dn is not None and str(new_dn).lower() != str(msg.dn).lower():
            s.db.rename(msg.dn, new_dn)
    return user_get(s, oid)


def user_delete(s: Session, oid: str) -> None:
    msg = _find_user(s, oid)
    if s.rid(s.sid(msg)) < 1000:
        raise forbidden("Integrierte Konten können nicht gelöscht werden.")
    s.db.delete(msg.dn, ["tree_delete:1"])


def user_password(s: Session, oid: str, body: dict) -> None:
    msg = _find_user(s, oid)
    if s.rid(s.sid(msg)) == RID_KRBTGT:
        raise forbidden("Das Konto krbtgt kann nicht geändert werden.")
    password = body.get("password")
    f = Fields()
    if not isinstance(password, str) or not password:
        f.add("password", "Bitte ein Kennwort angeben.")
    must, err = validate.boolean(body.get("must_change_password", False))
    f.add("must_change_password", err)
    f.raise_if_any()
    with s.transaction():
        s.replace(msg.dn, {"unicodePwd": _pwd(password)})
        if must:
            s.replace(msg.dn, {"pwdLastSet": "0"})


def user_unlock(s: Session, oid: str) -> None:
    msg = _find_user(s, oid)
    s.replace(msg.dn, {"lockoutTime": "0"})


def user_set_groups(s: Session, oid: str, body: dict) -> dict:
    msg = _find_user(s, oid)
    if s.rid(s.sid(msg)) == RID_KRBTGT:
        raise forbidden("Das Konto krbtgt kann nicht geändert werden.")
    f = Fields()
    if not isinstance(body.get("group_ids"), list):
        f.add("group_ids", "Bitte eine Liste von Gruppen angeben.")
    groups = _resolve_groups(s, body.get("group_ids"), "group_ids", f)
    f.raise_if_any()
    pgid = s.num(msg, "primaryGroupID")
    primary_sid = f"{s.domain_sid}-{pgid}"
    wanted = {str(g.dn).lower(): g for g in groups if s.sid(g) != primary_sid}
    current = {dn.lower(): dn for dn in s.vals(msg, "memberOf")}
    user_dn = str(msg.dn)
    with s.transaction():
        for key, g in wanted.items():
            if key not in current:
                s.modify_values(g.dn, "member", add=[user_dn])
        for key, dn in current.items():
            if key not in wanted:
                s.modify_values(s.dn(dn), "member", delete=[user_dn])
    return {"groups": _groups_brief(s, s.vals(_find_user(s, oid), "memberOf"))}


# --- groups ------------------------------------------------------------------------------------------

def _group_type(gt: int) -> tuple[str, str]:
    gt &= 0xFFFFFFFF
    typ = "security" if gt & GT_SECURITY else "distribution"
    if gt & GT_BUILTIN_LOCAL:
        scope = "builtin_local"
    elif gt & GT_GLOBAL:
        scope = "global"
    elif gt & GT_DOMAIN_LOCAL:
        scope = "domain_local"
    else:
        scope = "universal"
    return typ, scope


def _group_type_value(typ: str, scope: str) -> str:
    v = SCOPES[scope] | (GT_SECURITY if typ == "security" else 0)
    if v >= 2**31:
        v -= 2**32
    return str(v)


def _primary_counts(s: Session) -> dict[int, int]:
    counts: dict[int, int] = {}
    for m in s.search(expression="(primaryGroupID=*)", attrs=["primaryGroupID"]):
        rid = s.num(m, "primaryGroupID")
        counts[rid] = counts.get(rid, 0) + 1
    return counts


def _group(s: Session, msg, primary_counts=None, details: bool = False) -> dict:
    typ, scope = _group_type(s.num(msg, "groupType"))
    sid = s.sid(msg)
    ou_id, ou_path = s.parent_info(msg.dn)
    builtin = _builtin(s, msg)
    primary = 0
    if sid.startswith(s.domain_sid + "-"):
        if primary_counts is None:
            primary = len(s.search(expression=f"(primaryGroupID={s.rid(sid)})", attrs=["dn"]))
        else:
            primary = primary_counts.get(s.rid(sid), 0)
    out = {
        "id": s.guid(msg),
        "name": s.val(msg, "sAMAccountName") or s.val(msg, "cn"),
        "description": s.val(msg, "description"),
        "email": s.val(msg, "mail"),
        "type": typ,
        "scope": scope,
        "ou_id": ou_id,
        "ou_path": ou_path,
        "member_count": len(s.vals(msg, "member")) + primary,
        "builtin": builtin,
        "protected": builtin,
    }
    if details:
        members = []
        for dn in s.vals(msg, "member"):
            m = s.by_dn(dn, ["objectGUID", "objectSid", "objectClass", "sAMAccountName", "cn",
                             "isCriticalSystemObject"])
            if m is not None:
                members.append(_member(s, m))
        if primary:
            for m in s.search(expression=f"(primaryGroupID={s.rid(sid)})",
                              attrs=["objectGUID", "objectSid", "objectClass", "sAMAccountName", "cn"]):
                item = _member(s, m)
                item["primary"] = True
                members.append(item)
        members.sort(key=lambda x: x["name"].casefold())
        effective = []
        expr = f"(&(sAMAccountType=805306368)(memberOf:{IN_CHAIN}:={_enc(s, str(msg.dn))}))"
        seen = set()
        for m in s.search(expression=expr, attrs=["objectGUID", "sAMAccountName", "displayName", "cn"]):
            seen.add(s.guid(m))
            effective.append({"id": s.guid(m), "name": s.val(m, "displayName") or s.val(m, "cn"),
                              "username": s.val(m, "sAMAccountName")})
        for item in members:
            if item.get("primary") and item["kind"] == "user" and item["id"] not in seen:
                effective.append({"id": item["id"], "name": item["name"], "username": item["username"]})
        effective.sort(key=lambda x: x["name"].casefold())
        out.update({
            "dn": str(msg.dn),
            "sid": sid,
            "members": members,
            "member_of": [{"id": g["id"], "name": g["name"]} for g in _groups_brief(s, s.vals(msg, "memberOf"))],
            "effective_users": effective[:MAX_ITEMS],
        })
    return out


def _member(s: Session, m) -> dict:
    c = s.classes(m)
    if "computer" in c:
        kind = "computer"
    elif "group" in c:
        kind = "group"
    elif "user" in c:
        kind = "user"
    else:
        kind = "foreign"
    name = s.val(m, "sAMAccountName") or s.val(m, "cn")
    if kind == "foreign":
        name = WELL_KNOWN.get(s.val(m, "cn"), s.val(m, "cn"))
    return {"id": s.guid(m), "name": name, "username": s.val(m, "sAMAccountName"), "kind": kind,
            "builtin": kind in ("group", "user") and _builtin(s, m)}


def _find_group(s: Session, oid: str):
    msg = s.find(oid, attrs=GROUP_ATTRS, what="Gruppe")
    if "group" not in s.classes(msg):
        raise not_found("Gruppe nicht gefunden.")
    return msg


def groups_list(s: Session, q) -> dict:
    base, scope = _scope(s, q.q("ou_id"), q.flag("recursive"))
    expr = "(&(objectClass=group)" + _search_filter(s, q.q("search"), ["sAMAccountName", "cn", "description",
                                                                          "mail"]) + ")"
    counts = _primary_counts(s)
    items = [_group(s, m, counts) for m in s.search(base=base, scope=scope, expression=expr, attrs=GROUP_ATTRS)]
    if q.q("type"):
        items = [g for g in items if g["type"] == q.q("type")]
    if q.q("scope"):
        items = [g for g in items if g["scope"] == q.q("scope")]
    items.sort(key=lambda g: g["name"].casefold())
    return {"items": items[:MAX_ITEMS], "total": len(items)}


def group_get(s: Session, oid: str) -> dict:
    return _group(s, _find_group(s, oid), details=True)


def _type_scope(body: dict, f: Fields, cur_type="security", cur_scope="global"):
    typ = body.get("type", cur_type)
    scope = body.get("scope", cur_scope)
    if typ not in ("security", "distribution"):
        f.add("type", "Erlaubt: security, distribution.")
    if scope not in SCOPES:
        f.add("scope", "Erlaubt: global, domain_local, universal.")
    return typ, scope


def group_create(s: Session, body: dict) -> dict:
    f = Fields()
    name, err = validate.sam_account_name(body.get("name"), max_len=64)
    f.add("name", err)
    desc, err = validate.optional_text(body.get("description"), 1024)
    f.add("description", err)
    mail, err = validate.email(body.get("email"))
    f.add("email", err)
    typ, scope = _type_scope(body, f)
    parent = s.users_container()
    if body.get("ou_id"):
        try:
            parent = s.target_container(body["ou_id"], "ou_id")
        except ApiError as exc:
            f.update(exc.fields or {})
    f.raise_if_any()
    if not s.unique_sam(name):
        f.add("name", "Diesen Namen gibt es schon (Benutzer, Gruppe oder Computer).")
    dn = s.child_dn(parent, "CN", name)
    if s.exists(dn):
        f.add("name", "In dieser Organisationseinheit gibt es schon ein Objekt mit diesem Namen.")
    f.raise_if_any()
    msg = {"dn": str(dn), "objectClass": "group", "sAMAccountName": name,
           "groupType": _group_type_value(typ, scope)}
    if desc:
        msg["description"] = desc
    if mail:
        msg["mail"] = mail
    with s.transaction():
        s.db.add(msg)
        created = s.by_dn(dn, GROUP_ATTRS)
        if body.get("member_ids"):
            _set_members(s, created, body.get("member_ids"))
    return _group(s, s.by_dn(dn, GROUP_ATTRS), details=True)


def group_update(s: Session, oid: str, body: dict) -> dict:
    msg = _find_group(s, oid)
    cur = _group(s, msg)
    f = Fields()
    for key in body:
        if key not in ("name", "description", "email", "type", "scope"):
            f.add(key, "Dieses Feld kann hier nicht geändert werden.")
    f.raise_if_any()
    changes = {}
    if "description" in body:
        changes["description"], err = validate.optional_text(body.get("description"), 1024)
        f.add("description", err)
    if "email" in body:
        changes["mail"], err = validate.email(body.get("email"))
        f.add("email", err)
    new_name = None
    if "name" in body and body["name"] != cur["name"]:
        if cur["builtin"]:
            raise forbidden("Integrierte Gruppen können nicht umbenannt werden.")
        new_name, err = validate.sam_account_name(body.get("name"), max_len=64)
        f.add("name", err)
        if not err and not s.unique_sam(new_name, msg.dn):
            f.add("name", "Diesen Namen gibt es schon (Benutzer, Gruppe oder Computer).")
    if ("type" in body and body["type"] != cur["type"]) or ("scope" in body and body["scope"] != cur["scope"]):
        if cur["builtin"]:
            raise forbidden("Typ und Bereich integrierter Gruppen können nicht geändert werden.")
        typ, scope = _type_scope(body, f, cur["type"], cur["scope"])
        if not f:
            changes["groupType"] = _group_type_value(typ, scope)
    f.raise_if_any()
    with s.transaction():
        if "groupType" in changes:
            try:
                s.replace(msg.dn, {"groupType": changes.pop("groupType")})
            except s.ldb.LdbError as exc:
                text = exc.args[1] if len(exc.args) > 1 else str(exc)
                raise invalid({"scope": "Samba lehnt den Wechsel ab (AD-Regeln für Gruppenbereiche): " + text})
        s.replace(msg.dn, changes)
        if new_name:
            s.replace(msg.dn, {"sAMAccountName": new_name})
            new_dn = s.child_dn(msg.dn.parent(), "CN", new_name)
            if str(new_dn).lower() != str(msg.dn).lower():
                if s.exists(new_dn):
                    raise invalid({"name": "In dieser Organisationseinheit gibt es schon ein Objekt mit diesem Namen."})
                s.db.rename(msg.dn, new_dn)
    return group_get(s, oid)


def _set_members(s: Session, msg, ids) -> None:
    f = Fields()
    if not isinstance(ids, list):
        f.add("member_ids", "Bitte eine Liste von Mitgliedern angeben.")
        f.raise_if_any()
    targets = {}
    gdn = str(msg.dn)
    for i, mid in enumerate(ids):
        try:
            m = s.find(mid, attrs=["objectClass", "objectGUID"], what="Mitglied")
        except ApiError:
            f.add(f"member_ids.{i}", "Objekt nicht gefunden.")
            continue
        kind = s.kind(m)
        if kind not in ("user", "group", "computer"):
            f.add(f"member_ids.{i}", "Nur Benutzer, Gruppen und Computer können Mitglied sein.")
            continue
        if kind == "group":
            if str(m.dn).lower() == gdn.lower():
                f.add(f"member_ids.{i}", "Eine Gruppe kann nicht Mitglied von sich selbst sein.")
                continue
            loop = s.search(base=msg.dn, scope="base", attrs=["dn"],
                            expression=f"(memberOf:{IN_CHAIN}:={_enc(s, str(m.dn))})")
            if len(loop):
                f.add(f"member_ids.{i}", "Das würde eine Schleife ergeben.")
                continue
        targets[str(m.dn).lower()] = str(m.dn)
    f.raise_if_any()
    current = {dn.lower(): dn for dn in s.vals(msg, "member")}
    add = [dn for key, dn in targets.items() if key not in current]
    delete = [dn for key, dn in current.items() if key not in targets]
    try:
        s.modify_values(msg.dn, "member", add=add, delete=delete)
    except s.ldb.LdbError as exc:
        text = exc.args[1] if len(exc.args) > 1 else str(exc)
        raise invalid({"member_ids": "Samba lehnt die Mitgliedschaft ab (AD-Regeln für Gruppenbereiche): "
                                     + text})


def group_set_members(s: Session, oid: str, body: dict) -> dict:
    msg = _find_group(s, oid)
    with s.transaction():
        _set_members(s, msg, body.get("member_ids"))
    return group_get(s, oid)


def group_delete(s: Session, oid: str) -> None:
    msg = _find_group(s, oid)
    if _builtin(s, msg):
        raise forbidden("Integrierte Gruppen können nicht gelöscht werden.")
    s.db.delete(msg.dn)


# --- computers ---------------------------------------------------------------------------------------

def _computer(s: Session, msg, details: bool = False) -> dict:
    uac = s.num(msg, "userAccountControl")
    ou_id, ou_path = s.parent_info(msg.dn)
    out = {
        "id": s.guid(msg),
        "name": s.val(msg, "cn"),
        "dns_hostname": s.val(msg, "dNSHostName"),
        "os": s.val(msg, "operatingSystem"),
        "os_version": s.val(msg, "operatingSystemVersion"),
        "description": s.val(msg, "description"),
        "enabled": not uac & UF_ACCOUNTDISABLE,
        "is_dc": bool(uac & UF_SERVER_TRUST),
        "ou_id": ou_id,
        "ou_path": ou_path,
        "last_logon": nt_to_ms(s.val(msg, "lastLogonTimestamp", "0")),
        "created_at": gentime_ms(s.val(msg, "whenCreated")),
    }
    if details:
        out.update({"dn": str(msg.dn), "sid": s.sid(msg),
                    "groups": [{"id": g["id"], "name": g["name"]}
                               for g in _groups_brief(s, s.vals(msg, "memberOf"))]})
    return out


def _find_computer(s: Session, oid: str):
    msg = s.find(oid, attrs=COMPUTER_ATTRS, what="Computer")
    if "computer" not in s.classes(msg):
        raise not_found("Computer nicht gefunden.")
    return msg


def computers_list(s: Session, q) -> dict:
    base, scope = _scope(s, q.q("ou_id"), q.flag("recursive"))
    expr = "(&(objectClass=computer)" + _search_filter(s, q.q("search"), ["cn", "dNSHostName", "description"]) + ")"
    items = [_computer(s, m) for m in s.search(base=base, scope=scope, expression=expr, attrs=COMPUTER_ATTRS)]
    items.sort(key=lambda c: c["name"].casefold())
    return {"items": items[:MAX_ITEMS], "total": len(items)}


def computer_get(s: Session, oid: str) -> dict:
    return _computer(s, _find_computer(s, oid), details=True)


def computer_update(s: Session, oid: str, body: dict) -> dict:
    msg = _find_computer(s, oid)
    f = Fields()
    changes = {}
    for key in body:
        if key not in ("description", "enabled"):
            f.add(key, "Dieses Feld kann hier nicht geändert werden.")
    if "description" in body:
        changes["description"], err = validate.optional_text(body.get("description"), 1024)
        f.add("description", err)
    if "enabled" in body:
        enabled, err = validate.boolean(body.get("enabled"))
        f.add("enabled", err)
        uac = s.num(msg, "userAccountControl")
        if not err:
            if uac & UF_SERVER_TRUST and not enabled:
                raise forbidden("Domänencontroller können nicht deaktiviert werden.")
            changes["userAccountControl"] = str((uac & ~UF_ACCOUNTDISABLE) if enabled else (uac | UF_ACCOUNTDISABLE))
    f.raise_if_any()
    s.replace(msg.dn, changes)
    return computer_get(s, oid)


def computer_delete(s: Session, oid: str) -> None:
    msg = _find_computer(s, oid)
    if s.num(msg, "userAccountControl") & UF_SERVER_TRUST:
        raise forbidden("Domänencontroller können nicht gelöscht werden.")
    s.db.delete(msg.dn, ["tree_delete:1"])


def locked_users(s: Session) -> list[dict]:
    """Users whose lockout is active (for the lockout monitor)."""
    out = []
    for m in s.search(expression="(&(sAMAccountType=805306368)(lockoutTime>=1))",
                      attrs=["objectGUID", "sAMAccountName", "lockoutTime", "msDS-User-Account-Control-Computed"]):
        if s.num(m, "msDS-User-Account-Control-Computed") & UF_LOCKOUT:
            out.append({"id": s.guid(m), "username": s.val(m, "sAMAccountName"),
                        "lockout_time": s.num(m, "lockoutTime")})
    return out
