import unittest

from pk95ad import gpsettings as gs
from pk95ad import regpol
from pk95ad.errors import ApiError

REALM = "ad.example.com"


def empty():
    return {"computer": [], "user": []}, {}


class DecodeApplyTest(unittest.TestCase):
    def test_empty_policy_has_every_key_unset(self):
        settings = gs.decode(*empty())
        self.assertEqual(set(settings), {c["key"] for c in gs.CATALOG})
        self.assertTrue(all(v is None for v in settings.values()))

    def test_screen_lock_written_and_read(self):
        entries, scripts, settings, changed = gs.apply(*empty(), {"screen_lock_minutes": 10}, REALM)
        self.assertEqual(changed, {"user"})
        self.assertEqual(settings["screen_lock_minutes"], 10)
        values = {e.value: regpol.entry_value(e) for e in entries["user"]}
        self.assertEqual(values, {"ScreenSaveActive": "1", "ScreenSaverIsSecure": "1", "ScreenSaveTimeOut": "600",
                                  "SCRNSAVE.EXE": "scrnsave.scr"})
        self.assertTrue(all(e.key == gs.K_DESKTOP for e in entries["user"]))

    def test_unset_removes_only_own_values_and_keeps_foreign_entries(self):
        foreign = regpol.dword(r"Software\Policies\Other", "Thing", 5)
        entries, scripts, settings, _ = gs.apply({"computer": [], "user": [foreign]}, {},
                                                 {"screen_lock_minutes": 5, "deny_cmd": True}, REALM)
        entries, scripts, settings, changed = gs.apply(entries, scripts, {"screen_lock_minutes": None}, REALM)
        self.assertEqual(changed, {"user"})
        self.assertIn(foreign, entries["user"])
        self.assertIsNone(settings["screen_lock_minutes"])
        self.assertTrue(settings["deny_cmd"])
        self.assertEqual(gs.unmanaged_count(entries), {"computer": 0, "user": 1})

    def test_bool_false_writes_disabled_value(self):
        entries, _, settings, _ = gs.apply(*empty(), {"removable_storage_deny": False}, REALM)
        self.assertEqual(regpol.entry_value(entries["computer"][0]), 0)
        self.assertIs(settings["removable_storage_deny"], False)

    def test_deny_cmd_keeps_scripts_running(self):
        entries, _, _, _ = gs.apply(*empty(), {"deny_cmd": True}, REALM)
        self.assertEqual(regpol.entry_value(entries["user"][0]), 2)

    def test_windows_update_auto_with_schedule(self):
        body = {"windows_update_mode": "auto", "windows_update_day": 3, "windows_update_hour": 22}
        entries, _, settings, changed = gs.apply(*empty(), body, REALM)
        self.assertEqual(changed, {"computer"})
        values = {e.value: regpol.entry_value(e) for e in entries["computer"]}
        self.assertEqual(values, {"NoAutoUpdate": 0, "AUOptions": 4, "ScheduledInstallDay": 3,
                                  "ScheduledInstallTime": 22})
        for k, v in body.items():
            self.assertEqual(settings[k], v)
        # Switching to "off" clears the schedule.
        entries, _, settings, _ = gs.apply(entries, {}, {"windows_update_mode": "off"}, REALM)
        self.assertEqual({e.value: regpol.entry_value(e) for e in entries["computer"]}, {"NoAutoUpdate": 1})
        self.assertIsNone(settings["windows_update_day"])

    def test_schedule_without_auto_is_invalid(self):
        with self.assertRaises(ApiError) as ctx:
            gs.apply(*empty(), {"windows_update_mode": "notify", "windows_update_hour": 3}, REALM)
        self.assertIn("settings.windows_update_hour", ctx.exception.fields)

    def test_wallpaper_style_needs_path(self):
        with self.assertRaises(ApiError) as ctx:
            gs.apply(*empty(), {"wallpaper_style": "fit"}, REALM)
        self.assertIn("settings.wallpaper_style", ctx.exception.fields)
        entries, _, settings, _ = gs.apply(*empty(), {"wallpaper_path": r"\\ad\NETLOGON\bg.jpg"}, REALM)
        self.assertEqual(settings["wallpaper_style"], "fill")
        self.assertEqual({e.value: regpol.entry_value(e) for e in entries["user"]},
                         {"Wallpaper": r"\\ad\NETLOGON\bg.jpg", "WallpaperStyle": "4"})

    def test_validation_errors(self):
        cases = [
            ({"screen_lock_minutes": 0}, "settings.screen_lock_minutes"),
            ({"screen_lock_minutes": True}, "settings.screen_lock_minutes"),
            ({"deny_cmd": "yes"}, "settings.deny_cmd"),
            ({"windows_update_mode": "sometimes"}, "settings.windows_update_mode"),
            ({"logon_banner_title": "x" * 201}, "settings.logon_banner_title"),
            ({"unknown": 1}, "settings.unknown"),
            ({"logon_scripts": [{"path": "../evil.bat"}]}, "settings.logon_scripts.0.path"),
        ]
        for body, field in cases:
            with self.subTest(body=body):
                with self.assertRaises(ApiError) as ctx:
                    gs.apply(*empty(), body, REALM)
                self.assertIn(field, ctx.exception.fields)

    def test_empty_string_is_not_configured(self):
        _, _, settings, changed = gs.apply(*empty(), {"logon_banner_title": "   "}, REALM)
        self.assertIsNone(settings["logon_banner_title"])
        self.assertEqual(changed, set())

    def test_banner_text_uses_crlf(self):
        entries, _, settings, _ = gs.apply(*empty(), {"logon_banner_text": "Zeile 1\nZeile 2"}, REALM)
        self.assertEqual(regpol.entry_value(entries["computer"][0]), "Zeile 1\r\nZeile 2")

    def test_scripts_split_between_ini_files(self):
        body = {"logon_scripts": [{"path": "logon.bat", "parameters": "/q"},
                                  {"path": r"\\srv\share\setup.ps1", "parameters": ""}]}
        entries, scripts, settings, changed = gs.apply(*empty(), body, REALM)
        self.assertEqual(changed, {"user"})
        self.assertEqual(scripts["user"]["scripts"].get("Logon"), [(r"\\ad.example.com\NETLOGON\logon.bat", "/q")])
        self.assertEqual(scripts["user"]["psscripts"].get("Logon"), [(r"\\srv\share\setup.ps1", "")])
        self.assertEqual(len(settings["logon_scripts"]), 2)
        self.assertEqual(entries, {"computer": [], "user": []})
        # Clearing removes both.
        _, scripts, settings, changed = gs.apply(entries, scripts, {"logon_scripts": []}, REALM)
        self.assertTrue(scripts["user"]["scripts"].empty() and scripts["user"]["psscripts"].empty())
        self.assertIsNone(settings["logon_scripts"])

    def test_untouched_keys_are_not_rewritten(self):
        # AUOptions=5 is unknown to the catalog: it stays as long as windows_update_* is not in the body.
        foreign_au = [regpol.dword(gs.K_AU, "NoAutoUpdate", 0), regpol.dword(gs.K_AU, "AUOptions", 5)]
        entries, _, settings, changed = gs.apply({"computer": foreign_au, "user": []}, {},
                                                 {"hide_last_username": True}, REALM)
        self.assertIsNone(settings["windows_update_mode"])
        self.assertTrue(all(e in entries["computer"] for e in foreign_au))
        self.assertEqual(changed, {"computer"})

    def test_no_change_reports_nothing(self):
        entries, scripts, _, _ = gs.apply(*empty(), {"deny_cmd": True}, REALM)
        _, _, _, changed = gs.apply(entries, scripts, {"deny_cmd": True}, REALM)
        self.assertEqual(changed, set())


class ScriptsIniTest(unittest.TestCase):
    def test_roundtrip_utf16_with_bom(self):
        ini = gs.ScriptsIni()
        ini.set("Logon", [("a.bat", ""), ("b.cmd", "-x")])
        data = gs.serialize_scripts_ini(ini)
        self.assertTrue(data.startswith(b"\xff\xfe"))
        self.assertIn("[Logon]\r\n0CmdLine=a.bat\r\n0Parameters=\r\n1CmdLine=b.cmd".encode("utf-16-le"), data)
        back = gs.parse_scripts_ini(data)
        self.assertEqual(back.get("logon"), [("a.bat", ""), ("b.cmd", "-x")])

    def test_unknown_sections_are_kept(self):
        raw = "[ScriptsConfig]\r\nStartExecutePSFirst=true\r\n[Logon]\r\n0CmdLine=x.ps1\r\n0Parameters=\r\n"
        ini = gs.parse_scripts_ini(raw.encode("utf-8"))
        self.assertEqual(ini.get("Logon"), [("x.ps1", "")])
        ini.set("Logon", [])
        out = gs.parse_scripts_ini(gs.serialize_scripts_ini(ini))
        self.assertEqual(out.other, ["[ScriptsConfig]", "StartExecutePSFirst=true"])
        self.assertFalse(out.empty())


if __name__ == "__main__":
    unittest.main()
