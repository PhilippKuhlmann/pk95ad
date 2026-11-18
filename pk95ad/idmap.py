"""Unix ID ranges for the unprivileged LXC (docs/design.md → Unix IDs).

The LXC maps only the IDs 0-65535 (uid_map "0 100000 65536"): a chown to a higher ID fails, and Samba
panics while setting NT ACLs. Samba's default idmap range starts at 3000000, so the image patches
/usr/share/samba/setup/idmap_init.ldif to XID_LOW..XID_HIGH before any domain is provisioned.
"""

from __future__ import annotations

import os
import re

MAX_ID = 65535                          # highest ID that exists in the LXC
RFC2307_LOW, RFC2307_HIGH = 10000, 19999  # uidNumber/gidNumber set by hand (NIS attributes); the app sets none
XID_LOW, XID_HIGH = 20000, 59999         # Samba's automatic xidNumbers (idmap.ldb)
# 0-9999: system and well-known mappings (root 0, users 100); 60000-65535: Debian reserve, nobody 65534.

LDIF = "/usr/share/samba/setup/idmap_init.ldif"


def ldif_bounds(text: str) -> tuple[int | None, int | None]:
    def num(name):
        m = re.search(rf"^{name}:\s*(\d+)\s*$", text, re.M)
        return int(m.group(1)) if m else None
    return num("lowerBound"), num("upperBound")


def check_ldif(path: str = LDIF) -> str | None:
    """German error when the image would provision with IDs the LXC does not have."""
    try:
        with open(path, encoding="utf-8") as fh:
            lower, upper = ldif_bounds(fh.read())
    except OSError as exc:
        return f"{path} fehlt: {exc.strerror}."
    if (lower, upper) != (XID_LOW, XID_HIGH):
        return (f"Das Image vergibt Unix-IDs von {lower} bis {upper}; im unprivilegierten LXC gibt es nur IDs bis "
                f"{MAX_ID}. Erwartet {XID_LOW}–{XID_HIGH} (Image zu alt?).")
    return None


def evaluate(lower: int, upper: int, hwm: int | None, xids: list[int], rfc2307: list[tuple[str, int]]) -> dict:
    """Status of the ID ranges of a provisioned domain (pure, for /api/domain)."""
    problems = []
    if lower < XID_LOW or upper > XID_HIGH or lower > upper:
        problems.append(f"Samba vergibt Unix-IDs von {lower} bis {upper}; im unprivilegierten LXC gehen nur "
                        f"{XID_LOW}–{XID_HIGH}. Diese Domäne wurde mit einem älteren Image eingerichtet und muss neu "
                        "eingerichtet werden.")
    too_high = [x for x in xids if x > MAX_ID]
    if too_high:
        problems.append(f"{len(too_high)} vergebene Unix-IDs liegen über {MAX_ID} (z. B. {min(too_high)}).")
    outside = [name for name, v in rfc2307 if not RFC2307_LOW <= v <= RFC2307_HIGH]
    if outside:
        problems.append(f"uidNumber/gidNumber außerhalb {RFC2307_LOW}–{RFC2307_HIGH}: "
                        + ", ".join(sorted(outside)[:5]) + (" …" if len(outside) > 5 else "") + ".")
    next_xid = hwm if hwm is not None else lower
    if not problems and next_xid > upper - (upper - lower) // 10:
        problems.append(f"Der Bereich für Unix-IDs ist fast aufgebraucht (nächste ID {next_xid}, Ende {upper}).")
    return {
        "xid_range": [lower, upper],
        "rfc2307_range": [RFC2307_LOW, RFC2307_HIGH],
        "next_xid": next_xid,
        "allocated": len(xids),
        "ok": not problems,
        "message": " ".join(problems),
    }


def read(cfg) -> tuple[int, int, int | None, list[int]]:
    """(lowerBound, upperBound, xidNumber high-water mark, allocated xidNumbers) from idmap.ldb."""
    import ldb

    path = os.path.join(cfg.samba_dir, "private", "idmap.ldb")
    db = ldb.Ldb(url=path, flags=getattr(ldb, "FLG_RDONLY", 0))
    conf = db.search(base="CN=CONFIG", scope=ldb.SCOPE_BASE, attrs=["lowerBound", "upperBound", "xidNumber"])[0]

    def num(msg, attr):
        el = msg.get(attr)
        return int(str(el[0])) if el is not None and len(el) else None

    xids = [num(m, "xidNumber") for m in db.search(expression="(&(objectSid=*)(xidNumber=*))", attrs=["xidNumber"])]
    return num(conf, "lowerBound"), num(conf, "upperBound"), num(conf, "xidNumber"), [x for x in xids if x is not None]


def rfc2307_values(s) -> list[tuple[str, int]]:
    """uidNumber/gidNumber set on directory objects (directory Session)."""
    out = []
    for m in s.search(expression="(|(uidNumber=*)(gidNumber=*))", attrs=["sAMAccountName", "cn", "uidNumber",
                                                                          "gidNumber"]):
        name = s.val(m, "sAMAccountName") or s.val(m, "cn")
        for attr in ("uidNumber", "gidNumber"):
            v = s.val(m, attr)
            if v.isdigit():
                out.append((name, int(v)))
    return out


def info(cfg, s) -> dict:
    lower, upper, hwm, xids = read(cfg)
    return evaluate(lower if lower is not None else 0, upper if upper is not None else 0, hwm, xids,
                    rfc2307_values(s))
