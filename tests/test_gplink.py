import unittest

from pk95ad import gplink

A = "aaaaaaaa-0000-0000-0000-000000000001"
B = "bbbbbbbb-0000-0000-0000-000000000002"
C = "cccccccc-0000-0000-0000-000000000003"
BASE = "DC=ad,DC=example,DC=com"


def dn(g):
    return f"cn={{{g.upper()}}},cn=policies,cn=system,{BASE}"


class GPLinkTest(unittest.TestCase):
    def test_parse_and_format(self):
        value = f"[LDAP://{dn(A)};0][LDAP://{dn(B)};2]"
        links = gplink.parse(value)
        self.assertEqual([link.guid for link in links], [A, B])
        self.assertTrue(links[1].enforced)
        self.assertEqual(gplink.format(links), value)
        self.assertEqual(gplink.parse(""), [])
        self.assertEqual(gplink.parse(" "), [])

    def test_last_entry_is_order_one_and_new_links_go_last(self):
        links = gplink.add([], dn(A), 0)
        links = gplink.add(links, dn(B), 0)
        self.assertEqual(gplink.order_of(links, A), 1)
        self.assertEqual(gplink.order_of(links, B), 2)
        self.assertTrue(gplink.format(links).startswith(f"[LDAP://{dn(B)}"))

    def test_move_and_opts(self):
        links = gplink.add(gplink.add(gplink.add([], dn(A), 0), dn(B), 0), dn(C), 0)
        links = gplink.move(links, C, 1)
        self.assertEqual([link.guid for link in gplink.by_order(links)], [C, A, B])
        links = gplink.set_opts(links, A, gplink.opts(enabled=False, enforced=True))
        a = next(link for link in links if link.guid == A)
        self.assertFalse(a.enabled)
        self.assertTrue(a.enforced)
        self.assertEqual([link.guid for link in gplink.remove(links, A)], [B, C])

    def test_inheritance(self):
        gpos = {A: {"name": "Domain", "enabled": True}, B: {"name": "OU", "enabled": True},
                C: {"name": "Enforced", "enabled": True}}
        chain = [
            {"id": "root", "name": "ad.example.com", "links": gplink.parse(f"[LDAP://{dn(A)};0][LDAP://{dn(C)};2]"),
             "block": False},
            {"id": "ou", "name": "Vertrieb", "links": gplink.parse(f"[LDAP://{dn(B)};0]"), "block": False},
        ]
        names = [i["name"] for i in gplink.inheritance(chain, gpos)]
        self.assertEqual(names, ["Enforced", "OU", "Domain"])
        chain[1]["block"] = True
        names = [i["name"] for i in gplink.inheritance(chain, gpos)]
        self.assertEqual(names, ["Enforced", "OU"])  # enforced links pass a block
        gpos[B]["enabled"] = False
        self.assertEqual([i["name"] for i in gplink.inheritance(chain, gpos)], ["Enforced"])

    def test_disabled_link_is_skipped(self):
        gpos = {A: {"name": "A", "enabled": True}}
        chain = [{"id": "root", "name": "d", "links": gplink.parse(f"[LDAP://{dn(A)};1]"), "block": False}]
        self.assertEqual(gplink.inheritance(chain, gpos), [])


if __name__ == "__main__":
    unittest.main()
