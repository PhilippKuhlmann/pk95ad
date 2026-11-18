"""Group Policy Preferences lists (local groups, printers, shortcuts) against GPMC-style XML (MS-GPPREF)."""

import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from pk95ad import gpp
from pk95ad.errors import ApiError

DOM = "S-1-5-21-1111111111-2222222222-3333333333"
ACCOUNTS = {
    "id-da": {"name": "PK95\\Domain Admins", "sid": DOM + "-512", "kind": "group"},
    "id-help": {"name": "PK95\\Helpdesk", "sid": DOM + "-1110", "kind": "group"},
    "id-max": {"name": "PK95\\max", "sid": DOM + "-1105", "kind": "user"},
}
BY_SID = {a["sid"]: {"id": i, "name": a["name"], "kind": a["kind"]} for i, a in ACCOUNTS.items()}
NOW = datetime(2026, 11, 18, 12, 0, 0, tzinfo=timezone.utc)


def ctx():
    return gpp.Context(
        group_by_sid=lambda sid: ({"id": BY_SID[sid]["id"], "name": BY_SID[sid]["name"].split("\\")[1]}
                                  if sid in BY_SID and BY_SID[sid]["kind"] == "group" else None),
        group_by_id=lambda i: ({"name": ACCOUNTS[i]["name"], "sid": ACCOUNTS[i]["sid"]}
                               if i in ACCOUNTS and ACCOUNTS[i]["kind"] == "group" else "Gruppe nicht gefunden."),
        account_by_id=lambda i: ACCOUNTS.get(i, "Konto nicht gefunden."),
        account_by_sid=lambda sid: BY_SID.get(sid),
        domain_admins_sid=DOM + "-512", domain_admins_id="id-da", domain_admins_name="PK95\\Domain Admins")


def apply(kind, data, body):
    return gpp.apply(kind, gpp.parse(kind, data), body, ctx(), NOW)


def read(kind, data):
    return [gpp.to_json(kind, e, ctx()) for e in gpp.items(gpp.parse(kind, data))]


GROUPS_GPMC = (
    '<?xml version="1.0" encoding="utf-8"?>\r\n<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">'
    '<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Remote Desktop Users (built-in)" image="2" '
    'changed="2026-11-10 08:00:00" uid="{AAAAAAAA-1111-2222-3333-444444444444}">'
    '<Properties action="U" newName="" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0" '
    'groupSid="S-1-5-32-555" groupName="Remote Desktop Users (built-in)"><Members>'
    f'<Member name="PK95\\Helpdesk" action="ADD" sid="{DOM}-1110"/></Members></Properties></Group>'
    '<Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Guests (built-in)" image="2" '
    'changed="2026-11-10 08:00:00" uid="{BBBBBBBB-1111-2222-3333-444444444444}">'
    '<Properties action="U" newName="" description="" deleteAllUsers="1" deleteAllGroups="1" removeAccounts="0" '
    'groupSid="S-1-5-32-546" groupName="Guests (built-in)"/></Group></Groups>'
).encode()


class LocalGroupsTest(unittest.TestCase):
    K = gpp.LOCAL_GROUPS

    def test_constants_from_ms_gppref(self):
        self.assertEqual((self.K.root_clsid, self.K.item_clsid, self.K.cse, self.K.tool),
                         ("{3125E937-EB16-4b4c-9934-544FC6D24D26}", "{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}",
                          "{17D89FEC-5C44-4972-B12D-241CAEF74509}", "{79F92669-4224-476C-9C5C-6EFB4D87DF4A}"))
        self.assertEqual((self.K.scope, self.K.path[-1]), ("computer", "Groups.xml"))

    def test_reads_gpmc_file(self):
        rdp, guests = read(self.K, GROUPS_GPMC)
        self.assertEqual(rdp["group"], "remote_desktop_users")
        self.assertEqual(rdp["members"], [{"id": "id-help", "name": "PK95\\Helpdesk", "kind": "group", "action": "add"}])
        self.assertFalse(rdp["readonly"])
        self.assertTrue(guests["readonly"])  # Guests is not a managed group
        new, changed = apply(self.K, GROUPS_GPMC, read(self.K, GROUPS_GPMC))
        self.assertFalse(changed)

    def test_admins_with_remove_others_keep_domain_admins(self):
        new, changed = apply(self.K, b"", [{"group": "administrators", "remove_other_users": True,
                                            "members": [{"id": "id-help"}, {"id": "id-max", "action": "remove"}]}])
        self.assertTrue(changed)
        g = gpp.items(new)[0]
        self.assertEqual((g.get("clsid"), g.get("name"), g.get("image")),
                         ("{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}", "Administrators (built-in)", "2"))
        p = g.find("Properties")
        self.assertEqual({k: p.get(k) for k in ("action", "deleteAllUsers", "deleteAllGroups", "removeAccounts",
                                                "groupSid", "groupName", "newName")},
                         {"action": "U", "deleteAllUsers": "1", "deleteAllGroups": "0", "removeAccounts": "0",
                          "groupSid": "S-1-5-32-544", "groupName": "Administrators (built-in)", "newName": ""})
        members = [(m.get("name"), m.get("action"), m.get("sid")) for m in p.find("Members")]
        self.assertEqual(members[0], ("PK95\\Domain Admins", "ADD", DOM + "-512"))
        self.assertIn(("PK95\\max", "REMOVE", DOM + "-1105"), members)
        self.assertIsNone(g.get("bypassErrors"))

    def test_validation(self):
        cases = [
            ([{"group": "administrators", "members": [{"id": "id-da", "action": "remove"}]}], "items.0.members.0.action"),
            ([{"group": "guests"}], "items.0.group"),
            ([{"group": "users"}, {"group": "users"}], "items.1.group"),
            ([{"group": "users", "members": [{"id": "id-max"}, {"id": "id-max"}]}], "items.0.members.1.id"),
            ([{"group": "users", "members": [{"id": "nope"}]}], "items.0.members.0.id"),
            ([{"group": "users", "members": [{"id": "id-max", "action": "kick"}]}], "items.0.members.0.action"),
            ([{"group": "remote_desktop_users"}], "items.0.group"),  # the GPMC item for it is kept below
        ]
        for body, field in cases:
            with self.subTest(field=field):
                data = GROUPS_GPMC if field == "items.0.group" and body[0]["group"] == "remote_desktop_users" else b""
                if data:
                    body = read(self.K, data) + body
                    field = "items.2.group"
                with self.assertRaises(ApiError) as e:
                    apply(self.K, data, body)
                self.assertIn(field, e.exception.fields)

    def test_unknown_member_makes_item_readonly(self):
        data = GROUPS_GPMC.replace(f"{DOM}-1110".encode(), b"S-1-5-21-9-9-9-1234")
        self.assertTrue(read(self.K, data)[0]["readonly"])


PRINTERS_GPMC = (
    '<?xml version="1.0" encoding="utf-8"?>\r\n<Printers clsid="{1F577D12-3D1B-471e-A1B7-060317597B9C}">'
    '<SharedPrinter clsid="{9A5E9697-9095-436d-A0EE-4D128FDFBCE5}" name="Buero" status="Buero" image="2" '
    'changed="2026-11-10 08:00:00" uid="{CCCCCCCC-1111-2222-3333-444444444444}" bypassErrors="1">'
    '<Properties action="U" comment="" path="\\\\print\\Buero" location="" default="1" skipLocal="0" deleteAll="0" '
    'persistent="0" deleteMaps="0" port=""/></SharedPrinter>'
    '<PortPrinter clsid="{C3A739D2-4A37-4b0e-8C0F-5D3A16E0F3B1}" name="10.0.0.9" status="10.0.0.9" image="2" '
    'changed="2026-11-10 08:00:00" uid="{DDDDDDDD-1111-2222-3333-444444444444}"><Properties action="U" '
    'ipAddress="10.0.0.9"/></PortPrinter></Printers>'
).encode()


class PrintersTest(unittest.TestCase):
    K = gpp.PRINTERS

    def test_reads_and_keeps(self):
        shared, port = read(self.K, PRINTERS_GPMC)
        self.assertEqual((shared["path"], shared["action"], shared["default"], shared["readonly"]),
                         ("\\\\print\\Buero", "update", True, False))
        self.assertTrue(port["readonly"])  # TCP/IP printers only in the GPMC
        new, changed = apply(self.K, PRINTERS_GPMC, read(self.K, PRINTERS_GPMC))
        self.assertFalse(changed)

    def test_new_printer_like_the_gpmc(self):
        new, _ = apply(self.K, b"", [{"path": "\\\\print\\Farbe", "action": "create",
                                      gpp.TARGET: {"group_id": "id-help", "not": True}}])
        d = gpp.items(new)[0]
        self.assertEqual((d.tag, d.get("name"), d.get("image"), d.get("bypassErrors")), ("SharedPrinter", "Farbe", "0", "1"))
        p = d.find("Properties")
        self.assertEqual(list(p.attrib), ["action", "comment", "path", "location", "default", "skipLocal", "deleteAll",
                                          "persistent", "deleteMaps", "port"])
        self.assertEqual((p.get("action"), p.get("default"), p.get("port")), ("C", "0", ""))
        fg = d.find("Filters/FilterGroup")
        self.assertEqual((fg.get("not"), fg.get("sid")), ("1", DOM + "-1110"))

    def test_validation(self):
        for body, field in (([{"path": "\\\\print"}], "items.0.path"),
                            ([{"path": "\\\\print\\a\\b"}], "items.0.path"),
                            ([{"path": "\\\\p\\a"}, {"path": "\\\\P\\A"}], "items.1.path"),
                            ([{"path": "\\\\p\\a", "action": "x"}], "items.0.action"),
                            ([{"path": "\\\\p\\a", gpp.TARGET: {"group_id": "id-max"}}], f"items.0.{gpp.TARGET}.group_id")):
            with self.subTest(field=field):
                with self.assertRaises(ApiError) as e:
                    apply(self.K, b"", body)
                self.assertIn(field, e.exception.fields)


SHORTCUTS_GPMC = (
    '<?xml version="1.0" encoding="utf-8"?>\r\n<Shortcuts clsid="{872ECB34-B2EC-401b-A585-D32574AA90EE}">'
    '<Shortcut clsid="{4F2F7C55-2790-433e-8127-0739D1CFA327}" name="Intranet" status="Intranet" image="2" '
    'changed="2026-11-10 08:00:00" uid="{EEEEEEEE-1111-2222-3333-444444444444}" bypassErrors="1">'
    '<Properties pidl="" targetType="URL" action="U" comment="" shortcutKey="0" startIn="" arguments="" iconIndex="0" '
    'targetPath="https://intranet.example.com" iconPath="" window="" shortcutPath="%DesktopDir%\\Intranet"/></Shortcut>'
    '<Shortcut clsid="{4F2F7C55-2790-433e-8127-0739D1CFA327}" name="Drucker" status="Drucker" image="2" '
    'changed="2026-11-10 08:00:00" uid="{FFFFFFFF-1111-2222-3333-444444444444}"><Properties pidl="::{2227A280}" '
    'targetType="SHELL" action="U" targetPath="Drucker" shortcutPath="%DesktopDir%\\Drucker"/></Shortcut></Shortcuts>'
).encode()


class ShortcutsTest(unittest.TestCase):
    K = gpp.SHORTCUTS

    def test_reads_and_keeps(self):
        url, shell = read(self.K, SHORTCUTS_GPMC)
        self.assertEqual((url["name"], url["target_type"], url["target_path"], url["location"]),
                         ("Intranet", "url", "https://intranet.example.com", "desktop"))
        self.assertTrue(shell["readonly"])
        new, changed = apply(self.K, SHORTCUTS_GPMC, read(self.K, SHORTCUTS_GPMC))
        self.assertFalse(changed)

    def test_new_file_shortcut(self):
        new, _ = apply(self.K, b"", [{"name": "Vertrieb", "target_type": "file",
                                      "target_path": "\\\\nas\\vertrieb\\liste.xlsx", "location": "programs",
                                      "arguments": "/r", "icon_path": "%SystemRoot%\\System32\\shell32.dll",
                                      "icon_index": 4}])
        d = gpp.items(new)[0]
        p = d.find("Properties")
        self.assertEqual((d.get("clsid"), d.get("name")), ("{4F2F7C55-2790-433e-8127-0739D1CFA327}", "Vertrieb"))
        self.assertEqual((p.get("targetType"), p.get("shortcutPath"), p.get("arguments"), p.get("iconIndex"),
                          p.get("action")), ("FILESYSTEM", "%ProgramsDir%\\Vertrieb", "/r", "4", "U"))

    def test_validation(self):
        good = {"name": "A", "target_type": "url", "target_path": "https://a.example", "location": "desktop"}
        for change, field in (({"name": "a/b"}, "items.0.name"), ({"target_type": "shell"}, "items.0.target_type"),
                              ({"target_path": "intranet"}, "items.0.target_path"),
                              ({"arguments": "/x"}, "items.0.arguments"), ({"icon_index": 256}, "items.0.icon_index"),
                              ({"location": "startup"}, "items.0.location"),
                              ({"icon_path": "shell32.dll"}, "items.0.icon_path")):
            with self.subTest(field=field):
                with self.assertRaises(ApiError) as e:
                    apply(self.K, b"", [{**good, **change}])
                self.assertIn(field, e.exception.fields)
        with self.assertRaises(ApiError) as e:
            apply(self.K, b"", [good, {**good, "name": "a"}])
        self.assertIn("items.1.name", e.exception.fields)
        new, _ = apply(self.K, b"", [good, {**good, "location": "start_menu"}])  # same name elsewhere is fine
        self.assertEqual(len(gpp.items(new)), 2)


class CommonTest(unittest.TestCase):
    def test_bad_xml_and_limits(self):
        with self.assertRaises(gpp.PrefsError):
            gpp.parse(gpp.PRINTERS, b"<Drives/>")
        with self.assertRaises(ApiError):
            apply(gpp.PRINTERS, b"", [{"path": f"\\\\p\\{i}"} for i in range(51)])

    def test_uid_kept_and_changed_only_on_change(self):
        new, _ = apply(gpp.PRINTERS, PRINTERS_GPMC, [{**read(gpp.PRINTERS, PRINTERS_GPMC)[0], "default": False}])
        d = gpp.items(new)[0]
        self.assertEqual((d.get("uid"), d.get("changed")), ("{CCCCCCCC-1111-2222-3333-444444444444}", "2026-11-18 12:00:00"))
        self.assertEqual(len(gpp.items(new)), 1)  # the PortPrinter was left out → deleted
        ET.fromstring(gpp.serialize(new))


if __name__ == "__main__":
    unittest.main()
