"""gPLink handling and the GPMC-style inheritance order (pure functions).

gPLink = "[LDAP://cn={GUID},cn=policies,cn=system,DC=…;opts][…]". opts bit 1: link disabled, bit 2: enforced.
The LAST entry in the string has link order 1 (highest precedence on that container); new links are
put at the front (lowest precedence), like the GPMC does.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

DISABLED = 1
ENFORCED = 2

_LINK = re.compile(r"\[LDAP://([^;\]]+);(\d+)\]", re.I)
_GUID = re.compile(r"cn=\{([0-9a-f-]{36})\}", re.I)


@dataclass
class Link:
    dn: str
    opts: int

    @property
    def guid(self) -> str:
        m = _GUID.search(self.dn)
        return m.group(1).lower() if m else ""

    @property
    def enabled(self) -> bool:
        return not self.opts & DISABLED

    @property
    def enforced(self) -> bool:
        return bool(self.opts & ENFORCED)


def parse(value: str | None) -> list[Link]:
    if not value:
        return []
    return [Link(m.group(1), int(m.group(2))) for m in _LINK.finditer(value)]


def format(links: list[Link]) -> str:  # noqa: A001 - mirrors parse()
    return "".join(f"[LDAP://{link.dn};{link.opts}]" for link in links)


def by_order(links: list[Link]) -> list[Link]:
    """Links in link order (index 0 = order 1)."""
    return list(reversed(links))


def order_of(links: list[Link], guid: str) -> int:
    for i, link in enumerate(by_order(links)):
        if link.guid == guid:
            return i + 1
    return 0


def opts(enabled: bool, enforced: bool) -> int:
    return (0 if enabled else DISABLED) | (ENFORCED if enforced else 0)


def add(links: list[Link], dn: str, options: int) -> list[Link]:
    """New link with the lowest precedence."""
    return [Link(dn, options)] + list(links)


def remove(links: list[Link], guid: str) -> list[Link]:
    return [link for link in links if link.guid != guid]


def set_opts(links: list[Link], guid: str, options: int) -> list[Link]:
    return [Link(link.dn, options) if link.guid == guid else link for link in links]


def move(links: list[Link], guid: str, order: int) -> list[Link]:
    ordered = by_order(links)
    item = next((link for link in ordered if link.guid == guid), None)
    if item is None:
        return list(links)
    ordered = [link for link in ordered if link.guid != guid]
    order = max(1, min(order, len(ordered) + 1))
    ordered.insert(order - 1, item)
    return list(reversed(ordered))


def inheritance(chain: list[dict], gpos: dict[str, dict]) -> list[dict]:
    """Resulting GPO order for objects in the last container of chain.

    chain: containers from the domain root down to the target, each
           {"id", "name", "links": [Link], "block": bool}.
    gpos:  guid -> {"name", "enabled": bool} (enabled = GPO not completely disabled).
    Enforced links first (domain before OUs), then the others from the target up to the domain;
    a container with blocked inheritance stops the non-enforced links of its parents.
    """
    def usable(link: Link) -> bool:
        info = gpos.get(link.guid)
        return link.enabled and info is not None and info.get("enabled", True)

    items: list[tuple[dict, Link]] = []
    for c in chain:
        for link in by_order(c["links"]):
            if link.enforced and usable(link):
                items.append((c, link))
    for c in reversed(chain):
        for link in by_order(c["links"]):
            if not link.enforced and usable(link):
                items.append((c, link))
        if c.get("block"):
            break
    out = []
    for i, (c, link) in enumerate(items):
        out.append({
            "precedence": i + 1,
            "gpo_id": link.guid,
            "name": gpos[link.guid]["name"],
            "from_id": c["id"],
            "from_name": c["name"],
            "enforced": link.enforced,
            "enabled": link.enabled,
        })
    return out
