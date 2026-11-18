"""Drives.xml against a file in the form the Windows GPMC writes (Drive Maps preference)."""

import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from pk95ad import drives
from pk95ad.errors import ApiError

SID_VERKAUF = "S-1-5-21-1111111111-2222222222-3333333333-1105"
GPMC_SAMPLE = (
    '<?xml version="1.0" encoding="utf-8"?>\r\n'
    '<Drives clsid="{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'
    '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="V:" status="V:" image="2" '
    'changed="2026-11-10 08:15:42" uid="{0E5A1B2C-3D4E-4F50-8172-93A4B5C6D7E8}" bypassErrors="1">'
    '<Properties action="U" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="" path="\\\\nas\\vertrieb" '
    'label="Vertrieb" persistent="1" useLetter="1" letter="V"/>'
    '<Filters><FilterGroup bool="AND" not="0" name="PK95\\Verkauf" sid="' + SID_VERKAUF + '" userContext="1" '
    'primaryGroup="0" localGroup="0"/></Filters></Drive>'
    '<Drive clsid="{935D1B74-9CB8-4e3c-9914-7DD559B7A417}" name="S:" status="S:" image="1" '
    'changed="2026-11-10 08:16:00" uid="{11111111-2222-3333-4444-555555555555}">'
    '<Properties action="R" thisDrive="NOCHANGE" allDrives="NOCHANGE" userName="svc" cpassword="AAAA" '
    'path="\\\\nas\\secret" label="" persistent="0" useLetter="1" letter="S"/></Drive>'
    '</Drives>'
).encode("utf-8")

GROUPS_BY_SID = {SID_VERKAUF: {"id": "aaaaaaaa-0000-0000-0000-000000000001", "name": "Verkauf"}}
GROUPS_BY_ID = {"aaaaaaaa-0000-0000-0000-000000000001": {"name": "PK95\\Verkauf", "sid": SID_VERKAUF},
                "bbbbbbbb-0000-0000-0000-000000000002": {"name": "PK95\\Technik", "sid": SID_VERKAUF[:-4] + "1106"}}
NOW = datetime(2026, 11, 18, 9, 30, 0, tzinfo=timezone.utc)


def by_id(gid):
    return GROUPS_BY_ID.get(gid, "Gruppe nicht gefunden.")


def read(data):
    return [drives.to_json(e, GROUPS_BY_SID.get) for e in drives.items(drives.parse(data))]


class DrivesTest(unittest.TestCase):
    def test_reads_gpmc_file(self):
        v, s = read(GPMC_SAMPLE)
        self.assertEqual(v["uid"], "{0E5A1B2C-3D4E-4F50-8172-93A4B5C6D7E8}")
        self.assertEqual((v["letter"], v["path"], v["label"], v["action"]), ("V", "\\\\nas\\vertrieb", "Vertrieb",
                                                                             "update"))
        self.assertTrue(v["reconnect"])
        self.assertFalse(v["first_available"])
        self.assertEqual(v["target"], {"group_id": "aaaaaaaa-0000-0000-0000-000000000001", "group_name": "Verkauf",
                                       "not": False})
        self.assertFalse(v["readonly"])
        self.assertEqual(v["changed_at"], int(datetime(2026, 11, 10, 8, 15, 42, tzinfo=timezone.utc).timestamp() * 1000))
        self.assertTrue(s["readonly"])
        self.assertEqual(s["warning"], drives.PASSWORD_WARNING)

    def test_sending_items_back_changes_nothing(self):
        root = drives.parse(GPMC_SAMPLE)
        body = read(GPMC_SAMPLE)
        new, changed = drives.apply(root, body, by_id, NOW)
        self.assertFalse(changed)
        self.assertEqual(drives.serialize(new), drives.serialize(root))

    def test_readonly_item_kept_verbatim_and_never_gets_a_password_from_us(self):
        root = drives.parse(GPMC_SAMPLE)
        body = read(GPMC_SAMPLE)
        body[1]["path"] = "\\\\evil\\x"  # ignored: the item is read-only
        new, _ = drives.apply(root, body, by_id, NOW)
        s = drives.items(new)[1]
        self.assertEqual(s.find("Properties").get("path"), "\\\\nas\\secret")
        # Leaving it out deletes it.
        new, changed = drives.apply(root, body[:1], by_id, NOW)
        self.assertTrue(changed)
        self.assertEqual(len(drives.items(new)), 1)
        self.assertNotIn(b"cpassword", drives.serialize(new))

    def test_new_item_like_the_gpmc(self):
        root = drives.parse(b"")
        new, changed = drives.apply(root, [{
            "letter": "h", "path": "\\\\nas\\home", "label": "Home", "action": "create", "reconnect": False,
            "visibility": "hide", "target": {"group_id": "bbbbbbbb-0000-0000-0000-000000000002", "not": True}}],
            by_id, NOW)
        self.assertTrue(changed)
        data = drives.serialize(new)
        self.assertTrue(data.startswith(b'<?xml version="1.0" encoding="utf-8"?>\r\n<Drives clsid="'
                                        b'{8FDDCC1A-0C3C-43cd-A6B4-71A6DF20DA8C}">'))
        d = drives.items(ET.fromstring(data))[0]
        self.assertEqual(d.get("clsid"), "{935D1B74-9CB8-4e3c-9914-7DD559B7A417}")
        self.assertEqual((d.get("name"), d.get("status"), d.get("image"), d.get("changed"), d.get("bypassErrors")),
                         ("H:", "H:", "0", "2026-11-18 09:30:00", "1"))
        self.assertRegex(d.get("uid"), r"^\{[0-9A-F-]{36}\}$")
        p = d.find("Properties")
        self.assertEqual({k: p.get(k) for k in ("action", "thisDrive", "allDrives", "userName", "path", "label",
                                                "persistent", "useLetter", "letter")},
                         {"action": "C", "thisDrive": "HIDE", "allDrives": "NOCHANGE", "userName": "",
                          "path": "\\\\nas\\home", "label": "Home", "persistent": "0", "useLetter": "1",
                          "letter": "H"})
        self.assertIsNone(p.get("cpassword"))
        fg = d.find("Filters/FilterGroup")
        self.assertEqual((fg.get("bool"), fg.get("not"), fg.get("name"), fg.get("userContext")),
                         ("AND", "1", "PK95\\Technik", "1"))

    def test_first_available(self):
        new, _ = drives.apply(drives.parse(b""), [
            {"letter": "E", "first_available": True, "path": "\\\\nas\\a"},
            {"letter": "E", "first_available": True, "path": "\\\\nas\\b"}], by_id, NOW)
        a = drives.items(new)[0]
        self.assertEqual((a.get("name"), a.find("Properties").get("useLetter")), ("\\\\nas\\a", "0"))

    def test_edit_updates_changed_only_for_that_item(self):
        root = drives.parse(GPMC_SAMPLE)
        body = read(GPMC_SAMPLE)
        body[0]["label"] = "Vertrieb neu"
        new, changed = drives.apply(root, body, by_id, NOW)
        self.assertTrue(changed)
        v, s = drives.items(new)
        self.assertEqual(v.get("changed"), "2026-11-18 09:30:00")
        self.assertEqual(v.get("uid"), "{0E5A1B2C-3D4E-4F50-8172-93A4B5C6D7E8}")
        self.assertEqual(s.get("changed"), "2026-11-10 08:16:00")

    def test_validation(self):
        cases = [
            ([{"letter": "V", "path": "\\\\nas\\a"}, {"letter": "v", "path": "\\\\nas\\b"}], "items.1.letter"),
            ([{"letter": "S", "path": "\\\\nas\\b"}] + read(GPMC_SAMPLE)[1:], "items.0.letter"),
            ([{"letter": "1", "path": "\\\\nas\\a"}], "items.0.letter"),
            ([{"letter": "V", "path": "C:\\daten"}], "items.0.path"),
            ([{"letter": "V", "path": ""}], "items.0.path"),
            ([{"letter": "V", "path": "\\\\nas\\a", "action": "move"}], "items.0.action"),
            ([{"letter": "V", "path": "\\\\nas\\a", "visibility": "maybe"}], "items.0.visibility"),
            ([{"letter": "V", "path": "\\\\nas\\a", "target": {"group_id": "nope"}}], "items.0.target.group_id"),
            ([{"letter": "V", "path": "\\\\nas\\a", "label": "x" * 129}], "items.0.label"),
            ([{"letter": "V", "path": "\\\\nas\\a"}] * 51, "items"),
        ]
        for body, field in cases:
            with self.subTest(field=field):
                with self.assertRaises(ApiError) as ctx:
                    drives.apply(drives.parse(GPMC_SAMPLE), body, by_id, NOW)
                self.assertIn(field, ctx.exception.fields)

    def test_bad_xml(self):
        with self.assertRaises(drives.DrivesError):
            drives.parse(b"<Drives><Drive>")
        with self.assertRaises(drives.DrivesError):
            drives.parse(b"<Printers/>")

    def test_missing_group_marks_readonly(self):
        data = GPMC_SAMPLE.replace(SID_VERKAUF.encode(), b"S-1-5-21-9-9-9-9999")
        v = read(data)[0]
        self.assertTrue(v["readonly"])
        self.assertIn("gibt es nicht mehr", v["warning"])


if __name__ == "__main__":
    unittest.main()
