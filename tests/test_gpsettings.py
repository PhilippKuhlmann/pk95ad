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


class Package1Test(unittest.TestCase):
    """1.2.0: Grundschutz und Komfort (computer configuration)."""

    def values(self, entries):
        return {(e.key, e.value): regpol.entry_value(e) for e in entries}

    def test_catalog_groups_and_bool_help(self):
        groups = {c["group"] for c in gs.CATALOG}
        self.assertTrue({"Sicherheit", "Remotedesktop", "Datenschutz", "Energie", "Microsoft Edge",
                         "OneDrive"} <= groups)
        for c in gs.CATALOG:
            if c["type"] == "bool":
                self.assertTrue(c["help"].startswith("Aktiviert:") and "Deaktiviert:" in c["help"], c["key"])
        self.assertEqual(len({c["key"] for c in gs.CATALOG}), len(gs.CATALOG))
        editions = {"home", "pro", "enterprise", "education"}
        for c in gs.CATALOG:
            for item in [c] + c.get("options", []):
                self.assertTrue(set(item.get("editions", [])) <= editions, c["key"])
        by_key = gs.CATALOG_BY_KEY
        self.assertEqual(by_key["store_off"]["editions"], ["enterprise", "education"])
        self.assertNotIn("editions", by_key["firewall_enabled"])

    def test_firewall_all_profiles(self):
        entries, _, settings, changed = gs.apply(*empty(), {"firewall_enabled": True}, REALM)
        self.assertEqual(changed, {"computer"})
        self.assertEqual(self.values(entries["computer"]), {
            (gs.K_FW + r"\DomainProfile", "EnableFirewall"): 1, (gs.K_FW + r"\PrivateProfile", "EnableFirewall"): 1,
            (gs.K_FW + r"\PublicProfile", "EnableFirewall"): 1})
        self.assertIs(settings["firewall_enabled"], True)
        entries, _, settings, _ = gs.apply(entries, {}, {"firewall_enabled": False}, REALM)
        self.assertIs(settings["firewall_enabled"], False)
        self.assertEqual(set(self.values(entries["computer"]).values()), {0})

    def test_autorun_disabled_writes_del_like_the_gpmc(self):
        entries, _, settings, _ = gs.apply(*empty(), {"autorun_off": True}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v[(gs.K_EXPLORER_M, "NoDriveTypeAutoRun")], 255)
        self.assertEqual(v[(gs.K_EXPLORER_M, "NoAutorun")], 1)
        self.assertEqual(v[(gs.K_WINEXPLORER, "NoAutoplayfornonVolume")], 1)
        entries, _, settings, _ = gs.apply(entries, {}, {"autorun_off": False}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v, {(gs.K_EXPLORER_M, "**del.NoDriveTypeAutoRun"): " ", (gs.K_EXPLORER_M, "**del.NoAutorun"): " ",
                             (gs.K_WINEXPLORER, "NoAutoplayfornonVolume"): 0})
        self.assertIs(settings["autorun_off"], False)
        entries, _, settings, _ = gs.apply(entries, {}, {"autorun_off": None}, REALM)
        self.assertEqual(entries["computer"], [])
        self.assertIsNone(settings["autorun_off"])

    def test_rdp_opens_firewall_and_closing_removes_the_rules(self):
        entries, _, settings, _ = gs.apply(*empty(), {"rdp_allow": True, "rdp_require_nla": True}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v[(gs.K_TS, "fDenyTSConnections")], 0)
        self.assertEqual(v[(gs.K_TS, "UserAuthentication")], 1)
        rules = [x for (k, _), x in v.items() if k == gs.K_FW_RULES]
        self.assertEqual(len(rules), 2)
        self.assertTrue(all(r.startswith("v2.10|Action=Allow|Active=TRUE|Dir=In|") and "LPort=3389|" in r
                            for r in rules))
        self.assertTrue(settings["rdp_allow"])
        entries, _, settings, _ = gs.apply(entries, {}, {"rdp_allow": False}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v[(gs.K_TS, "fDenyTSConnections")], 1)
        self.assertFalse(any(k == gs.K_FW_RULES for k, _ in v))
        self.assertIs(settings["rdp_allow"], False)
        self.assertTrue(settings["rdp_require_nla"])

    def test_inverted_bools(self):
        entries, _, settings, _ = gs.apply(*empty(), {"defender_realtime": True, "llmnr_off": True,
                                                       "edge_password_manager_off": True, "onedrive_off": True}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v[(gs.K_DEFENDER_RTP, "DisableRealtimeMonitoring")], 0)
        self.assertEqual(v[(gs.K_DNSCLIENT, "EnableMulticast")], 0)
        self.assertEqual(v[(gs.K_EDGE, "PasswordManagerEnabled")], 0)
        self.assertEqual(v[(gs.K_ONEDRIVE, "DisableFileSyncNGSC")], 1)
        for k in ("defender_realtime", "llmnr_off", "edge_password_manager_off", "onedrive_off"):
            self.assertIs(settings[k], True)

    def test_power_minutes_as_seconds(self):
        entries, _, settings, _ = gs.apply(*empty(), {"display_off_ac_minutes": 10, "sleep_dc_minutes": 0}, REALM)
        v = self.values(entries["computer"])
        self.assertEqual(v[(f"{gs.K_POWER}\\{gs.POWER_DISPLAY}", "ACSettingIndex")], 600)
        self.assertEqual(v[(f"{gs.K_POWER}\\{gs.POWER_SLEEP}", "DCSettingIndex")], 0)
        self.assertEqual((settings["display_off_ac_minutes"], settings["sleep_dc_minutes"]), (10, 0))
        with self.assertRaises(ApiError):
            gs.apply(*empty(), {"sleep_ac_minutes": 601}, REALM)

    def test_telemetry_enum(self):
        entries, _, settings, _ = gs.apply(*empty(), {"telemetry_level": 1}, REALM)
        self.assertEqual(self.values(entries["computer"]), {(gs.K_DATACOLL, "AllowTelemetry"): 1})
        self.assertEqual(settings["telemetry_level"], 1)
        with self.assertRaises(ApiError):
            gs.apply(*empty(), {"telemetry_level": 2}, REALM)

    def test_edge_start_pages_as_list_key(self):
        body = {"edge_startup_urls": "https://intranet.example.com\n\nhttps://example.org/x ",
                "edge_homepage": "https://intranet.example.com"}
        entries, _, settings, _ = gs.apply(*empty(), body, REALM)
        e = entries["computer"]
        self.assertIn(regpol.delete_values(gs.K_EDGE_URLS), e)
        v = self.values(e)
        self.assertEqual(v[(gs.K_EDGE, "RestoreOnStartup")], 4)
        self.assertEqual(v[(gs.K_EDGE_URLS, "1")], "https://intranet.example.com")
        self.assertEqual(v[(gs.K_EDGE_URLS, "2")], "https://example.org/x")
        self.assertEqual(v[(gs.K_EDGE, "HomepageIsNewTabPage")], 0)
        self.assertEqual(settings["edge_startup_urls"], "https://intranet.example.com\nhttps://example.org/x")
        # Shorter list: old numbered values go away.
        entries, _, settings, _ = gs.apply(entries, {}, {"edge_startup_urls": "https://a.example"}, REALM)
        self.assertNotIn((gs.K_EDGE_URLS, "2"), self.values(entries["computer"]))
        self.assertEqual(gs.unmanaged_count(entries), {"computer": 0, "user": 0})
        for bad in ({"edge_startup_urls": "ftp://x"}, {"edge_homepage": "intranet"},
                    {"edge_startup_urls": "\n".join(f"https://h{i}.example" for i in range(21))}):
            with self.subTest(bad=bad):
                with self.assertRaises(ApiError):
                    gs.apply(*empty(), bad, REALM)

    def test_gpmc_disabled_entries_count_as_managed(self):
        e = [regpol.delete_value(gs.K_EXPLORER_M, "NoAutorun")]
        self.assertEqual(gs.unmanaged_count({"computer": e, "user": []}), {"computer": 0, "user": 0})


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
