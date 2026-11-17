"""Directory access through Samba's Python bindings (in-process SamDB as system).

All access goes through Directory.session(): one SamDB handle behind a lock (ldb handles are not
thread-safe). Samba modules are imported lazily so the rest of the app runs without them (tests).
"""

from __future__ import annotations

import contextlib
import logging
import re
import threading
from datetime import datetime, timezone

from . import validate
from .errors import ApiError, Fields, conflict, forbidden, invalid, not_found

log = logging.getLogger("pk95ad.directory")

NT_EPOCH = 116444736000000000  # 100 ns intervals from 1601 to 1970
NT_NEVER = 0x7FFFFFFFFFFFFFFF
NEG_NEVER = -0x8000000000000000
TICKS_MIN = 60 * 10_000_000
TICKS_DAY = 24 * 60 * TICKS_MIN

UF_ACCOUNTDISABLE = 0x2
UF_LOCKOUT = 0x10
UF_NORMAL_ACCOUNT = 0x200
UF_WORKSTATION_TRUST = 0x1000
UF_SERVER_TRUST = 0x2000
UF_DONT_EXPIRE_PASSWD = 0x10000

ERR_NO_SUCH_OBJECT = 32
ERR_INSUFFICIENT_ACCESS = 50
ERR_ENTRY_ALREADY_EXISTS = 68
ERR_CONSTRAINT_VIOLATION = 19
ERR_NOT_ALLOWED_ON_NON_LEAF = 66

LEVELS = {0: "2000", 1: "2003_interim", 2: "2003", 3: "2008", 4: "2008_R2", 5: "2012", 6: "2012_R2", 7: "2016"}


# --- conversions -------------------------------------------------------------------------------------

def nt_to_ms(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return 0
    if n <= 0 or n >= NT_NEVER:
        return 0
    return max(0, (n - NT_EPOCH) // 10_000)


def ms_to_nt(ms: int) -> int:
    return int(ms) * 10_000 + NT_EPOCH


def gentime_ms(value: str) -> int:
    if not value:
        return 0
    try:
        dt = datetime.strptime(value[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return 0
    return int(dt.timestamp() * 1000)


def password_message(text: str) -> str | None:
    """German text for Samba's password policy errors, None when it is not one."""
    t = text.lower()
    if "too short" in t:
        m = re.search(r"(\d+) characters", text)
        n = f" (mindestens {m.group(1)} Zeichen)" if m else ""
        return f"Das Kennwort ist zu kurz{n}."
    if "complexity" in t:
        return ("Das Kennwort ist nicht komplex genug: es braucht drei von vier Zeichenarten (Groß-, "
                "Kleinbuchstaben, Ziffern, Sonderzeichen) und darf den Anmeldenamen nicht enthalten.")
    if "history" in t or "already used" in t:
        return "Dieses Kennwort wurde schon einmal verwendet (Kennwortverlauf)."
    if "too young" in t or "minimum password age" in t:
        return "Das Kennwort darf noch nicht wieder geändert werden (minimales Kennwortalter)."
    if "check_password_restrictions" in t or "password" in t:
        return "Das Kennwort erfüllt die Kennwortrichtlinie der Domäne nicht."
    return None


def ldb_error(exc, field: str | None = None) -> ApiError:
    code = exc.args[0] if exc.args else 0
    text = str(exc.args[1]) if len(exc.args) > 1 else str(exc)
    if code == ERR_NO_SUCH_OBJECT:
        return not_found("Objekt nicht gefunden.")
    if code == ERR_INSUFFICIENT_ACCESS:
        return forbidden("Samba verweigert die Änderung: " + text)
    if code == ERR_ENTRY_ALREADY_EXISTS:
        return invalid({field or "name": "Es gibt hier schon ein Objekt mit diesem Namen."})
    if code == ERR_NOT_ALLOWED_ON_NON_LEAF:
        return conflict("Das Objekt enthält weitere Objekte.")
    msg = password_message(text) if code == ERR_CONSTRAINT_VIOLATION else None
    if msg:
        return invalid({"password": msg})
    if field:
        return invalid({field: "Samba: " + text})
    return ApiError(422, "Samba: " + text)


# --- session -----------------------------------------------------------------------------------------

class Directory:
    def __init__(self, cfg, settings_fn):
        self.cfg = cfg
        self.settings_fn = settings_fn
        self._lock = threading.RLock()
        self._db = None

    def _open(self):
        from samba.auth import system_session
        from samba.param import LoadParm
        from samba.samdb import SamDB

        lp = LoadParm()
        lp.load(self.cfg.smb_conf)
        self.lp = lp
        return SamDB(url=lp.private_path("sam.ldb"), session_info=system_session(), lp=lp)

    def close(self) -> None:
        with self._lock:
            self._db = None

    @contextlib.contextmanager
    def session(self):
        import ldb

        with self._lock:
            if self._db is None:
                self._db = self._open()
            s = Session(self, self._db)
            try:
                yield s
            except ldb.LdbError as exc:
                if s.in_transaction:
                    s.cancel()
                code = exc.args[0] if exc.args else 0
                if code in (1, 52, 80):  # operations error, unavailable, other
                    log.warning("ldb error %s, reopening sam.ldb: %s", code, exc)
                    self._db = None
                raise ldb_error(exc) from exc
            except BaseException:
                if s.in_transaction:
                    s.cancel()
                raise


class Session:
    def __init__(self, directory: Directory, db):
        import ldb

        self.ldb = ldb
        self.d = directory
        self.cfg = directory.cfg
        self.db = db
        self.settings = directory.settings_fn() or {}
        self.realm = self.settings.get("realm", "")
        self.base = db.get_default_basedn()
        self.base_str = str(self.base)
        self.in_transaction = False
        self._domain_sid = None
        self._containers = None

    # transactions
    def begin(self):
        self.db.transaction_start()
        self.in_transaction = True

    def commit(self):
        self.db.transaction_commit()
        self.in_transaction = False

    def cancel(self):
        try:
            self.db.transaction_cancel()
        finally:
            self.in_transaction = False

    @contextlib.contextmanager
    def transaction(self):
        self.begin()
        try:
            yield
        except BaseException:
            if self.in_transaction:
                self.cancel()
            raise
        self.commit()

    # search helpers
    def search(self, base=None, scope: str = "sub", expression=None, attrs=None, controls=None):
        scopes = {"base": self.ldb.SCOPE_BASE, "one": self.ldb.SCOPE_ONELEVEL, "sub": self.ldb.SCOPE_SUBTREE}
        return self.db.search(base=self.base if base is None else base, scope=scopes[scope],
                              expression=expression, attrs=attrs or ["*"], controls=controls or [])

    def exists(self, dn) -> bool:
        try:
            return len(self.search(base=dn, scope="base", attrs=["dn"])) > 0
        except self.ldb.LdbError as exc:
            if exc.args[0] == ERR_NO_SUCH_OBJECT:
                return False
            raise

    def find(self, oid, attrs=None, what: str = "Objekt"):
        g = validate.guid(oid)
        if not g:
            raise not_found(f"{what} nicht gefunden.")
        try:
            res = self.search(base=f"<GUID={g}>", scope="base", attrs=attrs)
        except self.ldb.LdbError as exc:
            if exc.args[0] == ERR_NO_SUCH_OBJECT:
                raise not_found(f"{what} nicht gefunden.") from exc
            raise
        if len(res) == 0:
            raise not_found(f"{what} nicht gefunden.")
        return res[0]

    def by_dn(self, dn, attrs=None):
        try:
            res = self.search(base=dn, scope="base", attrs=attrs)
        except self.ldb.LdbError as exc:
            if exc.args[0] == ERR_NO_SUCH_OBJECT:
                return None
            raise
        return res[0] if len(res) else None

    @staticmethod
    def val(msg, attr: str, default: str = "") -> str:
        el = msg.get(attr)
        if el is None or len(el) == 0:
            return default
        return str(el[0])

    @staticmethod
    def vals(msg, attr: str) -> list[str]:
        el = msg.get(attr)
        return [str(v) for v in el] if el is not None else []

    @staticmethod
    def num(msg, attr: str, default: int = 0) -> int:
        el = msg.get(attr)
        if el is None or len(el) == 0:
            return default
        try:
            return int(str(el[0]))
        except ValueError:
            return default

    @staticmethod
    def classes(msg) -> set[str]:
        el = msg.get("objectClass")
        return {str(v).lower() for v in el} if el is not None else set()

    def guid(self, msg) -> str:
        from samba.dcerpc import misc
        from samba.ndr import ndr_unpack

        el = msg.get("objectGUID")
        return str(ndr_unpack(misc.GUID, bytes(el[0]))) if el is not None and len(el) else ""

    def sid(self, msg) -> str:
        from samba.dcerpc import security
        from samba.ndr import ndr_unpack

        el = msg.get("objectSid")
        return str(ndr_unpack(security.dom_sid, bytes(el[0]))) if el is not None and len(el) else ""

    @staticmethod
    def rid(sid: str) -> int:
        try:
            return int(sid.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            return 0

    @property
    def domain_sid(self) -> str:
        if self._domain_sid is None:
            self._domain_sid = str(self.db.get_domain_sid())
        return self._domain_sid

    # DN helpers
    def dn(self, text):
        return self.ldb.Dn(self.db, str(text))

    def child_dn(self, parent, rdn_attr: str, value: str):
        dn = self.ldb.Dn(self.db, f"{rdn_attr}=x," + str(parent))
        dn.set_component(0, rdn_attr, value)
        return dn

    @staticmethod
    def comp_num(dn) -> int:
        try:
            return len(dn)
        except TypeError:
            i = 0
            while dn.get_component_name(i) is not None:
                i += 1
            return i

    def is_base(self, dn) -> bool:
        return str(dn).lower() == self.base_str.lower()

    def path_of(self, dn) -> str:
        """Slash-separated path of a container below the domain ("" for the root)."""
        n = self.comp_num(dn) - self.comp_num(self.base)
        if n <= 0:
            return ""
        return "/".join(dn.get_component_value(i) for i in reversed(range(n)))

    def containers(self) -> dict[str, str]:
        """dn (lowercase) -> objectGUID of every container-like object (cached per session)."""
        if self._containers is None:
            res = self.search(expression="(|(objectClass=organizationalUnit)(objectClass=container)"
                                         "(objectClass=builtinDomain)(objectClass=domainDNS))",
                              attrs=["objectGUID"])
            self._containers = {str(m.dn).lower(): self.guid(m) for m in res}
        return self._containers

    def parent_info(self, dn) -> tuple[str, str]:
        """(ou_id, ou_path) of the object's parent container."""
        parent = dn.parent()
        return self.containers().get(str(parent).lower(), ""), self.path_of(parent)

    def users_container(self):
        return self.dn(f"CN=Users,{self.base_str}")

    def target_container(self, oid, field: str, kinds=("domain", "ou", "container")):
        """DN of a container given by id (for create/move targets)."""
        try:
            msg = self.find(oid, attrs=["objectClass", "objectGUID"], what="Container")
        except ApiError:
            raise invalid({field: "Diese Organisationseinheit gibt es nicht."})
        kind = self.kind(msg)
        if kind not in kinds:
            raise invalid({field: "Hier können keine Objekte liegen."})
        return msg.dn

    def kind(self, msg) -> str:
        c = self.classes(msg)
        if self.is_base(msg.dn) or "domaindns" in c:
            return "domain"
        if "computer" in c:
            return "computer"
        if "user" in c:
            return "user"
        if "group" in c:
            return "group"
        if "organizationalunit" in c:
            return "ou"
        if "builtindomain" in c:
            return "builtin"
        if "container" in c:
            return "container"
        if "grouppolicycontainer" in c:
            return "gpo"
        return "other"

    def unique_sam(self, name: str, exclude_dn=None) -> bool:
        res = self.search(expression=f"(sAMAccountName={self.ldb.binary_encode(name)})", attrs=["dn"])
        return all(exclude_dn is not None and str(m.dn).lower() == str(exclude_dn).lower() for m in res)

    def replace(self, dn, attrs: dict) -> None:
        """Replace attributes; "" or None or [] removes the attribute."""
        if not attrs:
            return
        m = self.ldb.Message()
        m.dn = dn if not isinstance(dn, str) else self.dn(dn)
        for name, value in attrs.items():
            if value is None or value == "" or value == []:
                values = []
            elif isinstance(value, (list, tuple)):
                values = list(value)
            else:
                values = [value]
            m[name] = self.ldb.MessageElement(values, self.ldb.FLAG_MOD_REPLACE, name)
        self.db.modify(m)

    def modify_values(self, dn, attr: str, add=(), delete=()) -> None:
        if not add and not delete:
            return
        m = self.ldb.Message()
        m.dn = dn
        i = 0
        for v in add:
            m[f"a{i}"] = self.ldb.MessageElement([v], self.ldb.FLAG_MOD_ADD, attr)
            i += 1
        for v in delete:
            m[f"a{i}"] = self.ldb.MessageElement([v], self.ldb.FLAG_MOD_DELETE, attr)
            i += 1
        self.db.modify(m)


# --- organizational units ----------------------------------------------------------------------------

OU_ATTRS = ["objectGUID", "objectClass", "name", "description", "gPOptions", "isCriticalSystemObject"]


def _node(s: Session, msg) -> dict:
    kind = s.kind(msg)
    base = s.is_base(msg.dn)
    parent = None if base else msg.dn.parent()
    name = s.realm if base else msg.dn.get_rdn_value()
    protected = kind in ("domain", "container", "builtin") or (
        kind == "ou" and parent is not None and s.is_base(parent) and name.lower() == "domain controllers")
    return {
        "id": s.guid(msg),
        "name": name,
        "dn": str(msg.dn),
        "type": kind if kind in ("domain", "ou", "container", "builtin") else "container",
        "description": s.val(msg, "description"),
        "path": s.path_of(msg.dn),
        "parent_id": "" if parent is None else s.containers().get(str(parent).lower(), ""),
        "protected": protected,
        "block_inheritance": bool(s.num(msg, "gPOptions") & 1),
        "children": [],
    }


def ou_tree(s: Session) -> dict:
    root_msg = s.search(base=s.base, scope="base", attrs=OU_ATTRS)[0]
    extra = s.search(scope="one", attrs=OU_ATTRS,
                     expression="(|(&(objectClass=container)(|(cn=Users)(cn=Computers)))"
                                "(objectClass=builtinDomain))")
    ous = s.search(expression="(objectClass=organizationalUnit)", attrs=OU_ATTRS)
    nodes = {}
    root = _node(s, root_msg)
    nodes[str(root_msg.dn).lower()] = root
    pending = [(m, _node(s, m)) for m in list(extra) + list(ous)]
    for m, n in pending:
        nodes[str(m.dn).lower()] = n
    for m, n in pending:
        parent = nodes.get(str(m.dn.parent()).lower())
        if parent is not None:
            parent["children"].append(n)
    for n in nodes.values():
        n["children"].sort(key=lambda c: c["name"].casefold())
    return root


def ou_get(s: Session, oid: str) -> tuple[object, dict]:
    msg = s.find(oid, attrs=OU_ATTRS, what="Organisationseinheit")
    n = _node(s, msg)
    if s.kind(msg) not in ("domain", "ou", "container", "builtin"):
        raise not_found("Organisationseinheit nicht gefunden.")
    return msg, n


def ou_create(s: Session, body: dict) -> dict:
    f = Fields()
    name, err = validate.object_name(body.get("name"), what="Namen")
    f.add("name", err)
    desc, err = validate.optional_text(body.get("description"), 1024)
    f.add("description", err)
    parent_id = body.get("parent_id")
    parent_dn = s.base
    if parent_id:
        try:
            parent_dn = s.target_container(parent_id, "parent_id", kinds=("domain", "ou"))
        except ApiError as exc:
            f.update(exc.fields or {"parent_id": exc.message})
    f.raise_if_any()
    dn = s.child_dn(parent_dn, "OU", name)
    if s.exists(dn):
        raise invalid({"name": "Es gibt hier schon eine Organisationseinheit mit diesem Namen."})
    msg = {"dn": str(dn), "objectClass": "organizationalUnit"}
    if desc:
        msg["description"] = desc
    s.db.add(msg)
    s._containers = None
    _, node = ou_get(s, s.guid(s.by_dn(dn, ["objectGUID"])))
    return node


def ou_update(s: Session, oid: str, body: dict) -> dict:
    msg, node = ou_get(s, oid)
    f = Fields()
    changes = {}
    if "description" in body:
        desc, err = validate.optional_text(body.get("description"), 1024)
        f.add("description", err)
        changes["description"] = desc
    if "block_inheritance" in body:
        v, err = validate.boolean(body.get("block_inheritance"))
        f.add("block_inheritance", err)
        if not err and node["type"] != "ou" and v:
            f.add("block_inheritance", "Nur bei Organisationseinheiten möglich.")
        changes["gPOptions"] = "1" if v else "0"
    new_name = None
    if "name" in body and body.get("name") != node["name"]:
        if node["protected"]:
            raise forbidden("Dieser Container kann nicht umbenannt werden.")
        new_name, err = validate.object_name(body.get("name"), what="Namen")
        f.add("name", err)
    f.raise_if_any()
    with s.transaction():
        if changes:
            s.replace(msg.dn, changes)
        if new_name:
            new_dn = s.child_dn(msg.dn.parent(), "OU", new_name)
            if s.exists(new_dn):
                raise invalid({"name": "Es gibt hier schon eine Organisationseinheit mit diesem Namen."})
            s.db.rename(msg.dn, new_dn)
    s._containers = None
    return ou_get(s, oid)[1]


def ou_delete(s: Session, oid: str, recursive: bool) -> None:
    msg, node = ou_get(s, oid)
    if node["protected"]:
        raise forbidden("Dieser Container kann nicht gelöscht werden.")
    children = s.search(base=msg.dn, scope="one", attrs=["dn"])
    if len(children) and not recursive:
        raise conflict("Die Organisationseinheit ist nicht leer.")
    dcs = s.search(base=msg.dn, expression=f"(userAccountControl:1.2.840.113556.1.4.803:={UF_SERVER_TRUST})",
                   attrs=["dn"])
    if len(dcs):
        raise forbidden("In der Organisationseinheit liegt ein Domänencontroller.")
    s.db.delete(msg.dn, ["tree_delete:1"] if recursive else [])
    s._containers = None


def move(s: Session, body: dict) -> dict:
    ids = body.get("ids")
    f = Fields()
    if not isinstance(ids, list) or not ids:
        f.add("ids", "Bitte Objekte auswählen.")
    if not body.get("target_id"):
        f.add("target_id", "Bitte ein Ziel auswählen.")
    f.raise_if_any()
    target = s.target_container(body["target_id"], "target_id")
    moves = []
    for i, oid in enumerate(ids):
        try:
            msg = s.find(oid, attrs=["objectClass", "objectSid", "userAccountControl", "isCriticalSystemObject"])
        except ApiError:
            f.add(f"ids.{i}", "Objekt nicht gefunden.")
            continue
        kind = s.kind(msg)
        if kind not in ("user", "group", "computer", "ou"):
            f.add(f"ids.{i}", "Dieses Objekt kann nicht verschoben werden.")
            continue
        if kind == "ou":
            if _node(s, msg)["protected"]:
                f.add(f"ids.{i}", "Dieser Container kann nicht verschoben werden.")
                continue
            if s.kind(s.by_dn(target, ["objectClass"])) not in ("domain", "ou"):
                f.add("target_id", "Organisationseinheiten können nur in die Domäne oder eine andere "
                                   "Organisationseinheit verschoben werden.")
                continue
            t = str(target).lower()
            if t == str(msg.dn).lower() or t.endswith("," + str(msg.dn).lower()):
                f.add("target_id", "Eine Organisationseinheit kann nicht in sich selbst verschoben werden.")
                continue
        if kind == "computer" and s.num(msg, "userAccountControl") & UF_SERVER_TRUST:
            f.add(f"ids.{i}", "Domänencontroller bleiben in „Domain Controllers“.")
            continue
        if kind in ("user", "group"):
            sid = s.sid(msg)
            if (s.rid(sid) < 1000 or s.val(msg, "isCriticalSystemObject").upper() == "TRUE"
                    or "builtindomain" in s.classes(s.by_dn(msg.dn.parent(), ["objectClass"]) or msg)):
                f.add(f"ids.{i}", "Integrierte Objekte können nicht verschoben werden.")
                continue
        new_dn = s.child_dn(target, msg.dn.get_rdn_name(), msg.dn.get_rdn_value())
        if str(new_dn).lower() == str(msg.dn).lower():
            continue
        if s.exists(new_dn):
            f.add(f"ids.{i}", "Im Ziel gibt es schon ein Objekt mit diesem Namen.")
            continue
        moves.append((msg.dn, new_dn))
    f.raise_if_any()
    with s.transaction():
        for old, new in moves:
            s.db.rename(old, new)
    s._containers = None
    return {"moved": len(moves)}


# --- domain ------------------------------------------------------------------------------------------

def _fsmo_owner(s: Session, dn) -> str:
    msg = s.by_dn(dn, ["fSMORoleOwner"])
    if msg is None:
        return ""
    owner = s.val(msg, "fSMORoleOwner")
    if not owner:
        return ""
    try:
        return s.dn(owner).get_component_value(1).lower()
    except Exception:  # noqa: BLE001 - informational only
        return owner


def domain_info(s: Session) -> dict:
    import samba

    base_msg = s.search(base=s.base, scope="base", attrs=["msDS-Behavior-Version"])[0]
    config_dn = str(s.db.get_config_basedn())
    schema_dn = str(s.db.get_schema_basedn())
    forest_dn = str(s.db.get_root_basedn())
    partitions = s.by_dn(f"CN=Partitions,{config_dn}", ["msDS-Behavior-Version", "uPNSuffixes"])
    st = s.settings

    def count(expr):
        return len(s.search(expression=expr, attrs=["dn"]))

    return {
        "realm": s.realm,
        "kerberos_realm": s.realm.upper(),
        "netbios_domain": st.get("netbios_domain", ""),
        "base_dn": s.base_str,
        "sid": s.domain_sid,
        "dc": {"hostname": st.get("hostname", ""), "fqdn": f"{st.get('hostname', '')}.{s.realm}",
               "ip": st.get("host_ip", "")},
        "domain_level": LEVELS.get(s.num(base_msg, "msDS-Behavior-Version", -1), "?"),
        "forest_level": LEVELS.get(s.num(partitions, "msDS-Behavior-Version", -1), "?") if partitions else "?",
        "samba_version": samba.version,
        "fsmo": {
            "schema": _fsmo_owner(s, schema_dn),
            "naming": _fsmo_owner(s, f"CN=Partitions,{config_dn}"),
            "pdc": _fsmo_owner(s, s.base_str),
            "rid": _fsmo_owner(s, f"CN=RID Manager$,CN=System,{s.base_str}"),
            "infrastructure": _fsmo_owner(s, f"CN=Infrastructure,{s.base_str}"),
            "domain_dns": _fsmo_owner(s, f"CN=Infrastructure,DC=DomainDnsZones,{s.base_str}"),
            "forest_dns": _fsmo_owner(s, f"CN=Infrastructure,DC=ForestDnsZones,{forest_dn}"),
        },
        "upn_suffixes": upn_suffixes(s),
        "counts": {
            "users": count("(sAMAccountType=805306368)"),
            "groups": count("(objectClass=group)"),
            "computers": count("(objectClass=computer)"),
            "ous": count("(objectClass=organizationalUnit)"),
            "gpos": count("(objectClass=groupPolicyContainer)"),
        },
        "dns_forwarder": st.get("dns_forwarder", ""),
        "dns_port": s.cfg.dns_port,
    }


def upn_suffixes(s: Session) -> list[str]:
    out = [s.realm]
    partitions = s.by_dn(f"CN=Partitions,{s.db.get_config_basedn()}", ["uPNSuffixes"])
    if partitions is not None:
        for v in s.vals(partitions, "uPNSuffixes"):
            if v.lower() not in out:
                out.append(v.lower())
    return out


# --- password policy ---------------------------------------------------------------------------------

PP_ATTRS = ["minPwdLength", "pwdProperties", "pwdHistoryLength", "maxPwdAge", "minPwdAge",
            "lockoutThreshold", "lockoutDuration", "lockOutObservationWindow"]


def _ticks_to(value: int, unit: int) -> int:
    if value in (0, NEG_NEVER):
        return 0
    return round(abs(value) / unit)


def password_policy(s: Session) -> dict:
    m = s.search(base=s.base, scope="base", attrs=PP_ATTRS)[0]
    return {
        "min_length": s.num(m, "minPwdLength"),
        "complexity": bool(s.num(m, "pwdProperties") & 1),
        "history_length": s.num(m, "pwdHistoryLength"),
        "max_age_days": _ticks_to(s.num(m, "maxPwdAge"), TICKS_DAY),
        "min_age_days": _ticks_to(s.num(m, "minPwdAge"), TICKS_DAY),
        "lockout_threshold": s.num(m, "lockoutThreshold"),
        "lockout_duration_minutes": _ticks_to(s.num(m, "lockoutDuration"), TICKS_MIN),
        "lockout_window_minutes": _ticks_to(s.num(m, "lockOutObservationWindow"), TICKS_MIN),
    }


PP_RULES = {
    "min_length": (0, 255),
    "history_length": (0, 24),
    "max_age_days": (0, 999),
    "min_age_days": (0, 998),
    "lockout_threshold": (0, 999),
    "lockout_duration_minutes": (0, 99999),
    "lockout_window_minutes": (1, 99999),
}


def set_password_policy(s: Session, body: dict) -> dict:
    cur = password_policy(s)
    f = Fields()
    for key in body:
        if key not in cur:
            f.add(key, "Unbekannte Einstellung.")
    new = dict(cur)
    for key, (lo, hi) in PP_RULES.items():
        if key in body:
            v, err = validate.integer(body[key], lo, hi)
            f.add(key, err)
            new[key] = v
    if "complexity" in body:
        v, err = validate.boolean(body["complexity"])
        f.add("complexity", err)
        new["complexity"] = v
    f.raise_if_any()
    if new["max_age_days"] and new["min_age_days"] >= new["max_age_days"]:
        f.add("min_age_days", "Muss kleiner als das maximale Kennwortalter sein.")
    if new["lockout_duration_minutes"] and new["lockout_window_minutes"] > new["lockout_duration_minutes"]:
        f.add("lockout_window_minutes", "Darf nicht länger als die Sperrdauer sein.")
    f.raise_if_any()

    m = s.search(base=s.base, scope="base", attrs=["pwdProperties"])[0]
    props = s.num(m, "pwdProperties")
    props = (props | 1) if new["complexity"] else (props & ~1)
    s.replace(s.base, {
        "minPwdLength": str(new["min_length"]),
        "pwdProperties": str(props),
        "pwdHistoryLength": str(new["history_length"]),
        "maxPwdAge": str(-new["max_age_days"] * TICKS_DAY if new["max_age_days"] else NEG_NEVER),
        "minPwdAge": str(-new["min_age_days"] * TICKS_DAY),
        "lockoutThreshold": str(new["lockout_threshold"]),
        "lockoutDuration": str(-new["lockout_duration_minutes"] * TICKS_MIN),
        "lockOutObservationWindow": str(-new["lockout_window_minutes"] * TICKS_MIN),
    })
    return password_policy(s)
