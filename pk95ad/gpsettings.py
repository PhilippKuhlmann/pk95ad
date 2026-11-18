"""The curated Group Policy settings (docs/api.md → Curated settings).

Pure functions: they map between the settings JSON and Registry.pol entries / scripts.ini sections,
so they can be tested without Samba. Entries PK95 AD does not manage stay untouched.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from . import regpol
from .errors import Fields
from .regpol import Entry

K_DESKTOP = r"Software\Policies\Microsoft\Windows\Control Panel\Desktop"
K_SYSTEM = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
K_EXPLORER = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
K_WINSYSTEM = r"Software\Policies\Microsoft\Windows\System"
K_REMOVABLE = r"Software\Policies\Microsoft\Windows\RemovableStorageDevices"
K_AU = r"Software\Policies\Microsoft\Windows\WindowsUpdate\AU"
# Paket 1 (1.2.0), all machine (HKLM) policies
K_FW = r"Software\Policies\Microsoft\WindowsFirewall"
K_FW_RULES = K_FW + r"\FirewallRules"
K_DEFENDER = r"Software\Policies\Microsoft\Windows Defender"
K_DEFENDER_RTP = K_DEFENDER + r"\Real-Time Protection"
K_EXPLORER_M = r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
K_WINEXPLORER = r"Software\Policies\Microsoft\Windows\Explorer"
K_DNSCLIENT = r"Software\Policies\Microsoft\Windows NT\DNSClient"
K_TS = r"Software\Policies\Microsoft\Windows NT\Terminal Services"
K_CLOUD = r"Software\Policies\Microsoft\Windows\CloudContent"
K_DATACOLL = r"Software\Policies\Microsoft\Windows\DataCollection"
K_STORE = r"Software\Policies\Microsoft\WindowsStore"
K_POWER = r"Software\Policies\Microsoft\Power\PowerSettings"
POWER_DISPLAY = "3C0BC021-C8A8-4E07-A973-6B14CBCB2B7E"  # Turn off the display
POWER_SLEEP = "29F6C1DB-86DA-48C5-9FDB-F2B67B1F44DA"    # System sleep timeout
K_EDGE = r"Software\Policies\Microsoft\Edge"
K_EDGE_URLS = K_EDGE + r"\RestoreOnStartupURLs"
K_ONEDRIVE = r"Software\Policies\Microsoft\Windows\OneDrive"
TELEMETRY = [0, 1, 3]
MAX_EDGE_URLS = 20
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]{0,1990}$", re.I)

# WallpaperStyle of the "Desktop Wallpaper" administrative template.
WALLPAPER_STYLES = {"center": "0", "tile": "1", "stretch": "2", "fit": "3", "fill": "4", "span": "5"}
UPDATE_MODES = {"notify": 2, "download": 3, "auto": 4}
WEEKDAYS = ["Täglich", "Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"]

SCOPES = ("computer", "user")
MAX_SCRIPTS = 20

CATALOG: list[dict] = [
    {"key": "screen_lock_minutes", "scope": "user", "group": "Desktop",
     "label": "Bildschirmsperre nach Inaktivität", "type": "int", "min": 1, "max": 600, "unit": "Minuten",
     "help": "Startet nach dieser Zeit den Bildschirmschoner mit Kennwortschutz."},
    {"key": "wallpaper_path", "scope": "user", "group": "Desktop",
     "label": "Hintergrundbild", "type": "string", "max": 260,
     "help": "Pfad zum Bild, am besten eine Freigabe, z. B. \\\\ad.example.com\\NETLOGON\\hintergrund.jpg."},
    {"key": "wallpaper_style", "scope": "user", "group": "Desktop",
     "label": "Bildanpassung", "type": "enum",
     "options": [{"value": "fill", "label": "Füllen"}, {"value": "fit", "label": "Anpassen"},
                 {"value": "stretch", "label": "Strecken"}, {"value": "center", "label": "Zentrieren"},
                 {"value": "tile", "label": "Kacheln"}, {"value": "span", "label": "Über alle Bildschirme"}],
     "help": "Nur zusammen mit einem Hintergrundbild."},
    {"key": "deny_control_panel", "scope": "user", "group": "Einschränkungen",
     "label": "Systemsteuerung und Einstellungen sperren", "type": "bool",
     "help": "Aktiviert: Systemsteuerung und Einstellungen-App sind gesperrt. "
             "Deaktiviert: ausdrücklich erlaubt, auch wenn eine andere Richtlinie sie sperrt."},
    {"key": "deny_cmd", "scope": "user", "group": "Einschränkungen",
     "label": "Eingabeaufforderung sperren", "type": "bool",
     "help": "Aktiviert: cmd.exe ist gesperrt, Anmeldeskripte laufen weiter. "
             "Deaktiviert: ausdrücklich erlaubt, auch wenn eine andere Richtlinie sie sperrt."},
    {"key": "deny_registry_tools", "scope": "user", "group": "Einschränkungen",
     "label": "Registrierungs-Editor sperren", "type": "bool",
     "help": "Aktiviert: regedit ist gesperrt. "
             "Deaktiviert: ausdrücklich erlaubt, auch wenn eine andere Richtlinie ihn sperrt."},
    {"key": "logon_scripts", "scope": "user", "group": "Skripte",
     "label": "Anmeldeskripte", "type": "scripts", "max": MAX_SCRIPTS,
     "help": "Dateiname in NETLOGON (z. B. logon.bat) oder UNC-Pfad. .ps1 läuft als PowerShell-Skript."},
    {"key": "logoff_scripts", "scope": "user", "group": "Skripte",
     "label": "Abmeldeskripte", "type": "scripts", "max": MAX_SCRIPTS, "help": ""},
    {"key": "removable_storage_deny", "scope": "computer", "group": "Geräte",
     "label": "Wechseldatenträger sperren (USB-Speicher)", "type": "bool",
     "help": "Aktiviert: Lesen und Schreiben auf allen Wechselspeichern (USB-Sticks, externe Platten, SD-Karten) "
             "ist gesperrt. Deaktiviert: ausdrücklich erlaubt, auch wenn eine andere Richtlinie sie sperrt."},
    {"key": "windows_update_mode", "scope": "computer", "group": "Windows Update",
     "label": "Automatische Updates", "type": "enum",
     "options": [{"value": "off", "label": "Aus"},
                 {"value": "notify", "label": "Vor dem Herunterladen benachrichtigen"},
                 {"value": "download", "label": "Herunterladen, vor der Installation benachrichtigen"},
                 {"value": "auto", "label": "Automatisch installieren"}],
     "help": ""},
    {"key": "windows_update_day", "scope": "computer", "group": "Windows Update",
     "label": "Installationstag", "type": "enum",
     "options": [{"value": i, "label": name} for i, name in enumerate(WEEKDAYS)],
     "help": "Nur mit „Automatisch installieren“."},
    {"key": "windows_update_hour", "scope": "computer", "group": "Windows Update",
     "label": "Installationszeit", "type": "int", "min": 0, "max": 23, "unit": "Uhr",
     "help": "Nur mit „Automatisch installieren“."},
    {"key": "hide_last_username", "scope": "computer", "group": "Anmeldung",
     "label": "Letzten Benutzernamen nicht anzeigen", "type": "bool",
     "help": "Aktiviert: Der Anmeldebildschirm zeigt den zuletzt angemeldeten Benutzer nicht an. "
             "Deaktiviert: Er wird angezeigt."},
    {"key": "logon_banner_title", "scope": "computer", "group": "Anmeldung",
     "label": "Hinweis vor der Anmeldung: Titel", "type": "string", "max": 200, "help": ""},
    {"key": "logon_banner_text", "scope": "computer", "group": "Anmeldung",
     "label": "Hinweis vor der Anmeldung: Text", "type": "text", "max": 2000, "help": ""},
    {"key": "startup_scripts", "scope": "computer", "group": "Skripte",
     "label": "Startskripte", "type": "scripts", "max": MAX_SCRIPTS, "help": ""},
    # Paket 1 (1.2.0): all computer configuration
    {"key": "firewall_enabled", "scope": "computer", "group": "Sicherheit",
     "label": "Windows-Firewall einschalten (alle Profile)", "type": "bool",
     "help": "Aktiviert: Die Firewall ist im Domänen-, privaten und öffentlichen Profil an und lässt sich lokal "
             "nicht abschalten. Deaktiviert: Die Firewall ist in allen Profilen aus (nicht empfohlen)."},
    {"key": "defender_realtime", "scope": "computer", "group": "Sicherheit",
     "label": "Microsoft Defender: Echtzeitschutz erzwingen", "type": "bool",
     "help": "Aktiviert: Der Echtzeitschutz ist immer an. Deaktiviert: Der Echtzeitschutz wird abgeschaltet "
             "(nicht empfohlen). Wirkt nur, wenn Microsoft Defender der aktive Virenschutz ist; bei eingeschaltetem "
             "Manipulationsschutz ignoriert Windows das Abschalten."},
    {"key": "defender_pua", "scope": "computer", "group": "Sicherheit",
     "label": "Microsoft Defender: potenziell unerwünschte Apps blockieren", "type": "bool",
     "help": "Aktiviert: Adware, Bundler und ähnliche Programme werden blockiert. Deaktiviert: kein PUA-Schutz. "
             "Nur mit Microsoft Defender als Virenschutz."},
    {"key": "autorun_off", "scope": "computer", "group": "Sicherheit",
     "label": "AutoRun und automatische Wiedergabe abschalten", "type": "bool",
     "help": "Aktiviert: Kein AutoRun und keine automatische Wiedergabe für alle Laufwerke und Geräte (USB-Sticks, "
             "DVDs, Kameras). Deaktiviert: Windows-Standardverhalten."},
    {"key": "llmnr_off", "scope": "computer", "group": "Sicherheit",
     "label": "Multicast-Namensauflösung (LLMNR) abschalten", "type": "bool",
     "help": "Aktiviert: kein LLMNR, das schützt vor dem Abgreifen von Anmeldedaten per Namens-Spoofing. "
             "Deaktiviert: LLMNR bleibt an. Namen löst dann nur noch DNS auf."},
    {"key": "netbios_off", "scope": "computer", "group": "Sicherheit",
     "label": "NetBIOS-Namensauflösung abschalten", "type": "bool",
     "help": "Aktiviert: keine NetBIOS-Namensauflösung. Deaktiviert: erlaubt. Wirkt erst ab Windows 11 22H2; "
             "ältere Windows-Versionen ignorieren die Einstellung."},
    {"key": "rdp_allow", "scope": "computer", "group": "Remotedesktop",
     "label": "Remotedesktop-Verbindungen erlauben", "type": "bool",
     "help": "Aktiviert: Remotedesktop ist an, und die Windows-Firewall lässt TCP/UDP 3389 eingehend zu. Wer sich "
             "anmelden darf, regelt die lokale Gruppe Remotedesktopbenutzer. Deaktiviert: Remotedesktop ist gesperrt. "
             "Nur Windows Pro, Enterprise und Education; Home kann keine Verbindungen annehmen."},
    {"key": "rdp_require_nla", "scope": "computer", "group": "Remotedesktop",
     "label": "Authentifizierung auf Netzwerkebene (NLA) verlangen", "type": "bool",
     "help": "Aktiviert: Die Anmeldung wird geprüft, bevor eine Sitzung startet (empfohlen). "
             "Deaktiviert: Verbindungen ohne NLA sind erlaubt."},
    {"key": "consumer_features_off", "scope": "computer", "group": "Datenschutz",
     "label": "Microsoft-Verbraucherfeatures abschalten", "type": "bool",
     "help": "Aktiviert: keine automatisch installierten Vorschlags-Apps und Werbung im Startmenü. Deaktiviert: "
             "erlaubt. Wirkt nur unter Windows Enterprise und Education; Pro ignoriert die Einstellung."},
    {"key": "telemetry_level", "scope": "computer", "group": "Datenschutz",
     "label": "Diagnosedaten (Telemetrie)", "type": "enum",
     "options": [{"value": 0, "label": "Sicherheit (nur Enterprise/Education)"},
                 {"value": 1, "label": "Erforderliche Diagnosedaten"},
                 {"value": 3, "label": "Optionale Diagnosedaten"}],
     "help": "Höchste Stufe, die Windows senden darf. Unter Pro und Home wirkt „Sicherheit“ wie „Erforderlich“."},
    {"key": "store_off", "scope": "computer", "group": "Datenschutz",
     "label": "Microsoft Store sperren", "type": "bool",
     "help": "Aktiviert: Die Store-App ist gesperrt; installierte Apps bekommen weiter Updates. Deaktiviert: "
             "erlaubt. Wirkt nur unter Windows Enterprise und Education; Pro ignoriert die Einstellung."},
    {"key": "display_off_ac_minutes", "scope": "computer", "group": "Energie",
     "label": "Bildschirm aus nach (Netzbetrieb)", "type": "int", "min": 0, "max": 600, "unit": "Minuten",
     "help": "0 = nie."},
    {"key": "display_off_dc_minutes", "scope": "computer", "group": "Energie",
     "label": "Bildschirm aus nach (Akku)", "type": "int", "min": 0, "max": 600, "unit": "Minuten",
     "help": "0 = nie. Nur bei Geräten mit Akku."},
    {"key": "sleep_ac_minutes", "scope": "computer", "group": "Energie",
     "label": "Energiesparmodus nach (Netzbetrieb)", "type": "int", "min": 0, "max": 600, "unit": "Minuten",
     "help": "0 = nie."},
    {"key": "sleep_dc_minutes", "scope": "computer", "group": "Energie",
     "label": "Energiesparmodus nach (Akku)", "type": "int", "min": 0, "max": 600, "unit": "Minuten",
     "help": "0 = nie. Nur bei Geräten mit Akku."},
    {"key": "edge_startup_urls", "scope": "computer", "group": "Microsoft Edge",
     "label": "Beim Start öffnen", "type": "text", "max": 4000,
     "help": f"Eine Adresse pro Zeile (https://…), höchstens {MAX_EDGE_URLS}. Edge öffnet beim Start genau diese "
             "Seiten."},
    {"key": "edge_homepage", "scope": "computer", "group": "Microsoft Edge",
     "label": "Startseite (Home-Schaltfläche)", "type": "string", "max": 2000,
     "help": "Adresse, z. B. https://intranet.example.com."},
    {"key": "edge_password_manager_off", "scope": "computer", "group": "Microsoft Edge",
     "label": "Passwort-Manager von Edge abschalten", "type": "bool",
     "help": "Aktiviert: Edge bietet nicht an, Kennwörter zu speichern. Deaktiviert: erlaubt."},
    {"key": "onedrive_off", "scope": "computer", "group": "OneDrive",
     "label": "OneDrive abschalten", "type": "bool",
     "help": "Aktiviert: OneDrive kann nicht für die Dateisynchronisierung genutzt werden. Deaktiviert: erlaubt."},
]

CATALOG_BY_KEY = {c["key"]: c for c in CATALOG}

# Script settings: key -> (scope, scripts.ini section)
SCRIPT_KEYS = {
    "logon_scripts": ("user", "Logon"),
    "logoff_scripts": ("user", "Logoff"),
    "startup_scripts": ("computer", "Startup"),
}


# --- Registry groups --------------------------------------------------------------------------------

@dataclass
class Group:
    """A set of settings keys written together into a set of registry values."""
    name: str
    scope: str
    keys: list[str]
    values: list[tuple[str, str]]
    decode: object  # (lookup) -> dict key -> value
    encode: object  # (settings) -> list[Entry]
    prefix_keys: list[str] = field(default_factory=list)  # keys whose values all belong to the group

    def owns(self, e: Entry) -> bool:
        """The entry is one of the group's values, its '**del.' form, or a value of one of its list keys."""
        k, v = e.ident()
        for key, val in self.values:
            if k == key.lower() and v in (val.lower(), "**del." + val.lower()):
                return True
        return any(k == p.lower() for p in self.prefix_keys)


def _str(lookup, key, value):
    e = lookup(key, value)
    if e is None:
        return None
    v = regpol.entry_value(e)
    if isinstance(v, int):
        return str(v)
    return v if isinstance(v, str) else None


def _int(lookup, key, value):
    e = lookup(key, value)
    if e is None:
        return None
    v = regpol.entry_value(e)
    if isinstance(v, int):
        return v
    if isinstance(v, str) and v.strip().isdigit():
        return int(v.strip())
    return None


def _bool_group(name, scope, key, value, on, off=0):
    def decode(lookup):
        v = _int(lookup, key, value)
        return {name: None if v is None else v == on}

    def encode(s):
        v = s.get(name)
        if v is None:
            return []
        return [regpol.dword(key, value, on if v else off)]

    return Group(name, scope, [name], [(key, value)], decode, encode)


def _string_group(name, scope, key, value):
    def decode(lookup):
        v = _str(lookup, key, value)
        return {name: v if v else None}

    def encode(s):
        v = s.get(name)
        return [regpol.sz(key, value, v)] if v else []

    return Group(name, scope, [name], [(key, value)], decode, encode)


def _same(lookup, e: Entry) -> bool:
    cur = lookup(e.key, e.value)
    return cur is not None and cur.type == e.type and regpol.entry_value(cur) == regpol.entry_value(e)


def _set_group(name, scope, on: list[Entry], off: list[Entry]):
    """A bool written as a set of entries: True = all of on, False = all of off and none of the other on values.

    off may hold '**del.' entries (what the GPMC writes for "Deaktiviert" when the ADMX deletes the value).
    """
    values: list[tuple[str, str]] = []
    for e in on + off:
        v = e.value[len("**del."):] if e.value.lower().startswith("**del.") else e.value
        if (e.key, v) not in values:
            values.append((e.key, v))
    off_idents = {e.ident() for e in off}

    def decode(lookup):
        if all(_same(lookup, e) for e in on):
            return {name: True}
        if all(_same(lookup, e) for e in off) and not any(
                lookup(e.key, e.value) is not None for e in on if e.ident() not in off_idents):
            return {name: False}
        return {name: None}

    def encode(s):
        v = s.get(name)
        return [] if v is None else list(on if v else off)

    return Group(name, scope, [name], values, decode, encode)


def _int_group(name, scope, key, value, factor=1):
    """DWORD = setting × factor (e.g. minutes stored as seconds)."""
    def decode(lookup):
        v = _int(lookup, key, value)
        return {name: None if v is None else (v + factor - 1) // factor}

    def encode(s):
        v = s.get(name)
        return [] if v is None else [regpol.dword(key, value, v * factor)]

    return Group(name, scope, [name], [(key, value)], decode, encode)


def _enum_group(name, scope, key, value, allowed):
    def decode(lookup):
        v = _int(lookup, key, value)
        return {name: v if v in allowed else None}

    def encode(s):
        v = s.get(name)
        return [] if v is None else [regpol.dword(key, value, v)]

    return Group(name, scope, [name], [(key, value)], decode, encode)


def _edge_urls_group():
    def decode(lookup):
        if _int(lookup, K_EDGE, "RestoreOnStartup") != 4:
            return {"edge_startup_urls": None}
        urls = sorted(((int(e.value), regpol.entry_value(e)) for e in lookup.entries
                       if e.key.lower() == K_EDGE_URLS.lower() and e.value.isdigit()), key=lambda x: x[0])
        text = "\n".join(u for _, u in urls if isinstance(u, str) and u)
        return {"edge_startup_urls": text or None}

    def encode(s):
        v = s.get("edge_startup_urls")
        if not v:
            return []
        urls = [u.strip() for u in v.splitlines() if u.strip()]
        return ([regpol.dword(K_EDGE, "RestoreOnStartup", 4), regpol.delete_values(K_EDGE_URLS)]
                + [regpol.sz(K_EDGE_URLS, str(i + 1), u) for i, u in enumerate(urls)])

    return Group("edge_startup", "computer", ["edge_startup_urls"], [(K_EDGE, "RestoreOnStartup")], decode,
                 encode, prefix_keys=[K_EDGE_URLS])


def _edge_home_group():
    def decode(lookup):
        return {"edge_homepage": _str(lookup, K_EDGE, "HomepageLocation") or None}

    def encode(s):
        v = s.get("edge_homepage")
        return [regpol.sz(K_EDGE, "HomepageLocation", v), regpol.dword(K_EDGE, "HomepageIsNewTabPage", 0)] if v else []

    return Group("edge_homepage", "computer", ["edge_homepage"],
                 [(K_EDGE, "HomepageLocation"), (K_EDGE, "HomepageIsNewTabPage")], decode, encode)


def _rdp_rule(proto: int, label: str) -> Entry:
    rule = (f"v2.10|Action=Allow|Active=TRUE|Dir=In|Protocol={proto}|LPort=3389|"
            f"Name=PK95 AD: Remotedesktop ({label} eingehend)|")
    return regpol.sz(K_FW_RULES, f"PK95AD-RDP-{label}-In", rule)


def _screen_decode(lookup):
    active = _str(lookup, K_DESKTOP, "ScreenSaveActive")
    timeout = _int(lookup, K_DESKTOP, "ScreenSaveTimeOut")
    if active == "1" and timeout:
        return {"screen_lock_minutes": max(1, min(600, (timeout + 59) // 60))}
    return {"screen_lock_minutes": None}


def _screen_encode(s):
    m = s.get("screen_lock_minutes")
    if m is None:
        return []
    return [
        regpol.sz(K_DESKTOP, "ScreenSaveActive", "1"),
        regpol.sz(K_DESKTOP, "ScreenSaverIsSecure", "1"),
        regpol.sz(K_DESKTOP, "ScreenSaveTimeOut", str(m * 60)),
        regpol.sz(K_DESKTOP, "SCRNSAVE.EXE", "scrnsave.scr"),
    ]


def _wallpaper_decode(lookup):
    path = _str(lookup, K_SYSTEM, "Wallpaper")
    style = _str(lookup, K_SYSTEM, "WallpaperStyle")
    style_key = next((k for k, v in WALLPAPER_STYLES.items() if v == (style or "").strip()), None)
    if not path:
        return {"wallpaper_path": None, "wallpaper_style": None}
    return {"wallpaper_path": path, "wallpaper_style": style_key}


def _wallpaper_encode(s):
    path = s.get("wallpaper_path")
    if not path:
        return []
    style = s.get("wallpaper_style") or "fill"
    return [regpol.sz(K_SYSTEM, "Wallpaper", path),
            regpol.sz(K_SYSTEM, "WallpaperStyle", WALLPAPER_STYLES[style])]


def _update_decode(lookup):
    no_auto = _int(lookup, K_AU, "NoAutoUpdate")
    opt = _int(lookup, K_AU, "AUOptions")
    mode = None
    if no_auto == 1:
        mode = "off"
    elif opt in UPDATE_MODES.values():
        mode = next(k for k, v in UPDATE_MODES.items() if v == opt)
    day = hour = None
    if mode == "auto":
        day = _int(lookup, K_AU, "ScheduledInstallDay")
        hour = _int(lookup, K_AU, "ScheduledInstallTime")
        day = day if day is not None and 0 <= day <= 7 else None
        hour = hour if hour is not None and 0 <= hour <= 23 else None
    return {"windows_update_mode": mode, "windows_update_day": day, "windows_update_hour": hour}


def _update_encode(s):
    mode = s.get("windows_update_mode")
    if mode is None:
        return []
    if mode == "off":
        return [regpol.dword(K_AU, "NoAutoUpdate", 1)]
    out = [regpol.dword(K_AU, "NoAutoUpdate", 0), regpol.dword(K_AU, "AUOptions", UPDATE_MODES[mode])]
    if mode == "auto":
        day = s.get("windows_update_day")
        hour = s.get("windows_update_hour")
        out.append(regpol.dword(K_AU, "ScheduledInstallDay", 0 if day is None else day))
        out.append(regpol.dword(K_AU, "ScheduledInstallTime", 3 if hour is None else hour))
    return out


GROUPS: list[Group] = [
    Group("screen_lock", "user", ["screen_lock_minutes"],
          [(K_DESKTOP, "ScreenSaveActive"), (K_DESKTOP, "ScreenSaverIsSecure"),
           (K_DESKTOP, "ScreenSaveTimeOut"), (K_DESKTOP, "SCRNSAVE.EXE")],
          _screen_decode, _screen_encode),
    Group("wallpaper", "user", ["wallpaper_path", "wallpaper_style"],
          [(K_SYSTEM, "Wallpaper"), (K_SYSTEM, "WallpaperStyle")],
          _wallpaper_decode, _wallpaper_encode),
    _bool_group("deny_control_panel", "user", K_EXPLORER, "NoControlPanel", 1),
    _bool_group("deny_cmd", "user", K_WINSYSTEM, "DisableCMD", 2),
    _bool_group("deny_registry_tools", "user", K_SYSTEM, "DisableRegistryTools", 1),
    _bool_group("removable_storage_deny", "computer", K_REMOVABLE, "Deny_All", 1),
    Group("windows_update", "computer", ["windows_update_mode", "windows_update_day", "windows_update_hour"],
          [(K_AU, "NoAutoUpdate"), (K_AU, "AUOptions"), (K_AU, "ScheduledInstallDay"),
           (K_AU, "ScheduledInstallTime")],
          _update_decode, _update_encode),
    _bool_group("hide_last_username", "computer", K_SYSTEM, "DontDisplayLastUserName", 1),
    _string_group("logon_banner_title", "computer", K_SYSTEM, "LegalNoticeCaption"),
    _string_group("logon_banner_text", "computer", K_SYSTEM, "LegalNoticeText"),
    # Paket 1 (1.2.0)
    _set_group("firewall_enabled", "computer",
               [regpol.dword(f"{K_FW}\\{p}Profile", "EnableFirewall", 1) for p in ("Domain", "Private", "Public")],
               [regpol.dword(f"{K_FW}\\{p}Profile", "EnableFirewall", 0) for p in ("Domain", "Private", "Public")]),
    _bool_group("defender_realtime", "computer", K_DEFENDER_RTP, "DisableRealtimeMonitoring", 0, 1),
    _bool_group("defender_pua", "computer", K_DEFENDER, "PUAProtection", 1, 0),
    _set_group("autorun_off", "computer",
               [regpol.dword(K_EXPLORER_M, "NoDriveTypeAutoRun", 255), regpol.dword(K_EXPLORER_M, "NoAutorun", 1),
                regpol.dword(K_WINEXPLORER, "NoAutoplayfornonVolume", 1)],
               [regpol.delete_value(K_EXPLORER_M, "NoDriveTypeAutoRun"), regpol.delete_value(K_EXPLORER_M, "NoAutorun"),
                regpol.dword(K_WINEXPLORER, "NoAutoplayfornonVolume", 0)]),
    _bool_group("llmnr_off", "computer", K_DNSCLIENT, "EnableMulticast", 0, 1),
    _bool_group("netbios_off", "computer", K_DNSCLIENT, "EnableNetbios", 0, 1),
    _set_group("rdp_allow", "computer",
               [regpol.dword(K_TS, "fDenyTSConnections", 0), _rdp_rule(6, "TCP"), _rdp_rule(17, "UDP")],
               [regpol.dword(K_TS, "fDenyTSConnections", 1)]),
    _bool_group("rdp_require_nla", "computer", K_TS, "UserAuthentication", 1, 0),
    _bool_group("consumer_features_off", "computer", K_CLOUD, "DisableWindowsConsumerFeatures", 1, 0),
    _enum_group("telemetry_level", "computer", K_DATACOLL, "AllowTelemetry", TELEMETRY),
    _bool_group("store_off", "computer", K_STORE, "RemoveWindowsStore", 1, 0),
    _int_group("display_off_ac_minutes", "computer", f"{K_POWER}\\{POWER_DISPLAY}", "ACSettingIndex", 60),
    _int_group("display_off_dc_minutes", "computer", f"{K_POWER}\\{POWER_DISPLAY}", "DCSettingIndex", 60),
    _int_group("sleep_ac_minutes", "computer", f"{K_POWER}\\{POWER_SLEEP}", "ACSettingIndex", 60),
    _int_group("sleep_dc_minutes", "computer", f"{K_POWER}\\{POWER_SLEEP}", "DCSettingIndex", 60),
    _edge_urls_group(),
    _edge_home_group(),
    _bool_group("edge_password_manager_off", "computer", K_EDGE, "PasswordManagerEnabled", 0, 1),
    _bool_group("onedrive_off", "computer", K_ONEDRIVE, "DisableFileSyncNGSC", 1, 0),
]

GROUP_OF_KEY = {k: g for g in GROUPS for k in g.keys}


def owned(scope: str, e: Entry) -> bool:
    return any(g.scope == scope and g.owns(e) for g in GROUPS)


def _lookup(entries: list[Entry]):
    table = {}
    for e in entries:
        table[e.ident()] = e  # last one wins, like the client

    def lookup(key, value):
        return table.get((key.lower(), value.lower()))

    lookup.entries = list(entries)  # for groups with list keys (Edge start pages)
    return lookup


# --- scripts.ini -------------------------------------------------------------------------------------

@dataclass
class ScriptsIni:
    """scripts.ini / psscripts.ini: ordered sections of (CmdLine, Parameters); other keys kept."""
    sections: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # section name -> scripts
    other: list[str] = field(default_factory=list)  # raw lines of unknown sections

    def get(self, section: str) -> list[tuple[str, str]]:
        for name, items in self.sections.items():
            if name.lower() == section.lower():
                return items
        return []

    def set(self, section: str, items: list[tuple[str, str]]) -> None:
        for name in list(self.sections):
            if name.lower() == section.lower():
                del self.sections[name]
        if items:
            self.sections[section] = items

    def empty(self) -> bool:
        return not any(self.sections.values()) and not any(line.strip() for line in self.other)


_KNOWN_SECTIONS = {"logon", "logoff", "startup", "shutdown"}


def decode_ini_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe"):
        return data[2:].decode("utf-16-le", errors="replace")
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8", errors="replace")
    if b"\x00" in data:
        return data.decode("utf-16-le", errors="replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp1252", errors="replace")


def parse_scripts_ini(data: bytes) -> ScriptsIni:
    ini = ScriptsIni()
    if not data:
        return ini
    section = None
    raw: dict[str, dict[int, dict[str, str]]] = {}
    for line in decode_ini_bytes(data).splitlines():
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^\[(.+)\]$", s)
        if m:
            section = m.group(1).strip()
            if section.lower() in _KNOWN_SECTIONS:
                raw.setdefault(section, {})
            else:
                ini.other.append(s)
            continue
        if section is None:
            continue
        if section.lower() not in _KNOWN_SECTIONS:
            ini.other.append(s)
            continue
        m = re.match(r"^(\d+)(CmdLine|Parameters)\s*=(.*)$", s, re.I)
        if m:
            idx = int(m.group(1))
            raw[section].setdefault(idx, {})[m.group(2).lower()] = m.group(3)
    for name, items in raw.items():
        scripts = [(v.get("cmdline", ""), v.get("parameters", "")) for _, v in sorted(items.items())]
        ini.sections[name] = [s for s in scripts if s[0]]
    return ini


def serialize_scripts_ini(ini: ScriptsIni) -> bytes:
    lines: list[str] = []
    for name, items in ini.sections.items():
        if not items:
            continue
        lines.append(f"[{name}]")
        for i, (cmd, params) in enumerate(items):
            lines.append(f"{i}CmdLine={cmd}")
            lines.append(f"{i}Parameters={params}")
    lines.extend(ini.other)
    text = "\r\n".join(lines) + "\r\n"
    return b"\xff\xfe" + text.encode("utf-16-le")


def _is_ps(path: str) -> bool:
    return path.lower().endswith(".ps1")


def _decode_scripts(scripts: dict, scope: str, section: str):
    pair = scripts.get(scope) or {}
    items = pair.get("scripts", ScriptsIni()).get(section) + pair.get("psscripts", ScriptsIni()).get(section)
    if not items:
        return None
    return [{"path": cmd, "parameters": params} for cmd, params in items]


# --- decode / apply ----------------------------------------------------------------------------------

def decode(entries: dict[str, list[Entry]], scripts: dict) -> dict:
    """Settings for every catalog key (None = not configured).

    entries: {"computer": [...], "user": [...]}; scripts: {scope: {"scripts": ScriptsIni, "psscripts": ScriptsIni}}.
    """
    out = {c["key"]: None for c in CATALOG}
    lookups = {scope: _lookup(entries.get(scope, [])) for scope in SCOPES}
    for g in GROUPS:
        out.update(g.decode(lookups[g.scope]))
    for key, (scope, section) in SCRIPT_KEYS.items():
        out[key] = _decode_scripts(scripts, scope, section)
    return out


def unmanaged_count(entries: dict[str, list[Entry]]) -> dict[str, int]:
    return {scope: sum(1 for e in entries.get(scope, []) if not owned(scope, e)) for scope in SCOPES}


def normalise_script_path(path: str, realm: str) -> str:
    p = path.strip()
    if p.startswith("\\\\"):
        return p
    return f"\\\\{realm}\\NETLOGON\\{p}"


def _check_value(key: str, value, f: Fields, realm: str):
    """Validated value for one catalog key (None = not configured)."""
    spec = CATALOG_BY_KEY[key]
    name = f"settings.{key}"
    if value is None:
        return None
    t = spec["type"]
    if t == "bool":
        if not isinstance(value, bool):
            f.add(name, "Bitte true, false oder null angeben.")
        return value
    if t == "int":
        if isinstance(value, bool) or not isinstance(value, int) or not spec["min"] <= value <= spec["max"]:
            f.add(name, f"Bitte eine Zahl von {spec['min']} bis {spec['max']} angeben.")
        return value
    if t == "enum":
        allowed = [o["value"] for o in spec["options"]]
        if isinstance(value, bool) or value not in allowed:
            f.add(name, "Ungültiger Wert.")
        return value
    if t in ("string", "text"):
        if not isinstance(value, str):
            f.add(name, "Bitte Text angeben.")
            return value
        v = value if t == "text" else value.strip()
        if not v.strip():
            return None
        if len(v) > spec["max"]:
            f.add(name, f"Höchstens {spec['max']} Zeichen.")
        bad = r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]" if t == "text" else r"[\x00-\x1f\x7f]"
        if re.search(bad, v):
            f.add(name, "Keine Steuerzeichen.")
        return v.replace("\r\n", "\n").replace("\n", "\r\n") if t == "text" else v
    if t == "scripts":
        if not isinstance(value, list):
            f.add(name, "Bitte eine Liste von Skripten angeben.")
            return value
        if len(value) > spec["max"]:
            f.add(name, f"Höchstens {spec['max']} Skripte.")
        out = []
        for i, item in enumerate(value):
            if not isinstance(item, dict):
                f.add(f"{name}.{i}", "Bitte {\"path\", \"parameters\"} angeben.")
                continue
            path = item.get("path")
            params = item.get("parameters") or ""
            if not isinstance(path, str) or not path.strip():
                f.add(f"{name}.{i}.path", "Bitte einen Pfad angeben.")
                continue
            p = path.strip()
            if len(p) > 260 or re.search(r"[\x00-\x1f\x7f]", p):
                f.add(f"{name}.{i}.path", "Ungültiger Pfad (höchstens 260 Zeichen).")
            elif not p.startswith("\\\\") and not re.match(r"^[A-Za-z0-9._-]+(\\[A-Za-z0-9._-]+)*$", p):
                f.add(f"{name}.{i}.path", "Dateiname in NETLOGON (z. B. logon.bat) oder UNC-Pfad.")
            if not isinstance(params, str) or len(params) > 260 or re.search(r"[\x00-\x1f\x7f]", params):
                f.add(f"{name}.{i}.parameters", "Höchstens 260 Zeichen ohne Steuerzeichen.")
                params = ""
            out.append({"path": normalise_script_path(p, realm), "parameters": params})
        return out or None
    return value


def apply(entries: dict[str, list[Entry]], scripts: dict, body: dict, realm: str):
    """Apply a settings body.

    Returns (new_entries, new_scripts, settings, changed_scopes). Raises ApiError 422 on invalid input.
    Only the groups whose keys are in the body are rewritten; everything else stays as it is.
    """
    f = Fields()
    if not isinstance(body, dict):
        f.add("settings", "Bitte ein Objekt mit Einstellungen angeben.")
        f.raise_if_any()
    for key in body:
        if key not in CATALOG_BY_KEY:
            f.add(f"settings.{key}", "Unbekannte Einstellung.")
    f.raise_if_any()

    current = decode(entries, scripts)
    merged = dict(current)
    for key, value in body.items():
        merged[key] = _check_value(key, value, f, realm)
    f.raise_if_any()

    # Coupled keys.
    if merged.get("windows_update_mode") != "auto":
        for k in ("windows_update_day", "windows_update_hour"):
            if k in body and body[k] is not None:
                f.add(f"settings.{k}", "Nur mit „Automatisch installieren“.")
            merged[k] = None
    if not merged.get("wallpaper_path"):
        if body.get("wallpaper_style") is not None:
            f.add("settings.wallpaper_style", "Nur zusammen mit einem Hintergrundbild.")
        merged["wallpaper_style"] = None
    if body.get("edge_startup_urls") and merged.get("edge_startup_urls"):
        urls = [u.strip() for u in merged["edge_startup_urls"].splitlines() if u.strip()]
        if len(urls) > MAX_EDGE_URLS:
            f.add("settings.edge_startup_urls", f"Höchstens {MAX_EDGE_URLS} Adressen.")
        bad = [u for u in urls if not _URL.match(u)]
        if bad:
            f.add("settings.edge_startup_urls", f"Keine gültige Adresse: {bad[0][:80]} (erwartet https://…).")
        merged["edge_startup_urls"] = "\n".join(urls) or None
    if body.get("edge_homepage") and merged.get("edge_homepage") and not _URL.match(merged["edge_homepage"]):
        f.add("settings.edge_homepage", "Bitte eine Adresse angeben, z. B. https://intranet.example.com.")
    f.raise_if_any()

    touched_groups = {GROUP_OF_KEY[k].name for k in body if k in GROUP_OF_KEY}
    new_entries = {scope: list(entries.get(scope, [])) for scope in SCOPES}
    for g in GROUPS:
        if g.name not in touched_groups:
            continue
        kept = [e for e in new_entries[g.scope] if not g.owns(e)]
        new_entries[g.scope] = kept + g.encode(merged)

    new_scripts = {scope: {"scripts": _copy_ini((scripts.get(scope) or {}).get("scripts")),
                           "psscripts": _copy_ini((scripts.get(scope) or {}).get("psscripts"))}
                   for scope in SCOPES}
    for key, (scope, section) in SCRIPT_KEYS.items():
        if key not in body:
            continue
        items = merged.get(key) or []
        new_scripts[scope]["scripts"].set(section, [(i["path"], i["parameters"]) for i in items
                                                     if not _is_ps(i["path"])])
        new_scripts[scope]["psscripts"].set(section, [(i["path"], i["parameters"]) for i in items
                                                       if _is_ps(i["path"])])

    changed = set()
    for scope in SCOPES:
        if regpol.serialize(new_entries[scope]) != regpol.serialize(entries.get(scope, [])):
            changed.add(scope)
        old = scripts.get(scope) or {}
        for kind in ("scripts", "psscripts"):
            before = old.get(kind) or ScriptsIni()
            if serialize_scripts_ini(new_scripts[scope][kind]) != serialize_scripts_ini(before):
                changed.add(scope)
    return new_entries, new_scripts, decode(new_entries, new_scripts), changed


def _copy_ini(ini: ScriptsIni | None) -> ScriptsIni:
    if ini is None:
        return ScriptsIni()
    return ScriptsIni({k: list(v) for k, v in ini.sections.items()}, list(ini.other))
