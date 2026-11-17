"""Input validation (pure functions, German messages). Each check returns (value, error or None)."""

from __future__ import annotations

import ipaddress
import re

_DNS_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_DC_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,13}[a-z0-9])?$")
_NETBIOS = re.compile(r"^[A-Z0-9][A-Z0-9-]{0,14}$")
_SAM_BAD = re.compile(r'["/\\\[\]:;|=,+*?<>@]')
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_UNC = re.compile(r"^\\\\[^\\/\s]+\\[^\\/]+(\\.*)?$")
_SCRIPT_PATH = re.compile(r"^[A-Za-z0-9._\- ]+([\\/][A-Za-z0-9._\- ]+)*$")
_HOST_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


def text(value) -> str:
    return value.strip() if isinstance(value, str) else ""


def realm(value):
    v = text(value).lower().rstrip(".")
    if not v:
        return v, "Bitte den Domänennamen angeben, z. B. ad.example.com."
    labels = v.split(".")
    if (len(labels) < 2 or len(labels) > 5 or len(v) > 200
            or not all(_DNS_LABEL.match(label) for label in labels) or labels[-1].isdigit()):
        return v, ("Ungültiger Domänenname: 2–5 Teile aus Buchstaben, Ziffern und Bindestrichen, "
                   "z. B. ad.example.com.")
    if labels[-1] == "local":
        return v, (".local ist für mDNS reserviert. Bitte eine Subdomain einer eigenen Domain wählen, "
                   "z. B. ad.example.com.")
    return v, None


def netbios_domain(value):
    v = text(value).upper()
    if not v:
        return v, "Bitte den NetBIOS-Namen der Domäne angeben, z. B. EXAMPLE."
    if not _NETBIOS.match(v) or v.isdigit():
        return v, "1–15 Zeichen: Buchstaben, Ziffern und Bindestriche (nicht nur Ziffern)."
    return v, None


def dc_hostname(value):
    v = text(value).lower()
    if not v:
        return v, "Bitte den Namen des Domänencontrollers angeben, z. B. dc1."
    if not _DC_NAME.match(v) or v.isdigit():
        return v, ("1–15 Zeichen: Buchstaben, Ziffern und Bindestriche, nicht am Anfang oder Ende, "
                   "nicht nur Ziffern.")
    return v, None


def ipv4(value):
    v = text(value)
    try:
        addr = ipaddress.IPv4Address(v)
    except ValueError:
        return v, "Bitte eine IPv4-Adresse angeben, z. B. 192.168.1.10."
    return str(addr), None


def forwarder(value):
    """IP, IP:port, [v6]:port or bare IPv6. Normalised string."""
    v = text(value)
    if not v:
        return v, "Bitte eine Adresse angeben, z. B. 127.0.0.1."
    host, port = v, None
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", v)
    if m:
        host, port = m.group(1), m.group(2)
    elif v.count(":") == 1:
        host, port = v.split(":")
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return v, "Ungültige Adresse. Erlaubt: IP-Adresse, optional mit Port (192.168.1.1:53, [fd00::1]:53)."
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            return v, "Ungültiger Port (1–65535)."
        if addr.version == 6:
            return f"[{addr}]:{int(port)}", None
        return f"{addr}:{int(port)}", None
    return str(addr), None


def password(value, username: str = ""):
    """Samba's default complexity: 3 of 4 character classes, not containing the account name."""
    if not isinstance(value, str) or not value:
        return "", "Bitte ein Kennwort angeben."
    if len(value) < 8:
        return value, "Das Kennwort braucht mindestens 8 Zeichen."
    if len(value) > 127:
        return value, "Das Kennwort darf höchstens 127 Zeichen haben."
    classes = sum([
        any(c.isupper() for c in value),
        any(c.islower() for c in value),
        any(c.isdigit() for c in value),
        any(not c.isalnum() for c in value),
    ])
    if classes < 3:
        return value, ("Das Kennwort braucht drei von vier Zeichenarten: Großbuchstaben, Kleinbuchstaben, "
                       "Ziffern, Sonderzeichen.")
    if username and len(username) >= 3 and username.lower() in value.lower():
        return value, "Das Kennwort darf den Benutzernamen nicht enthalten."
    return value, None


def sam_account_name(value, max_len: int = 20):
    v = text(value)
    if not v:
        return v, "Bitte einen Anmeldenamen angeben."
    if len(v) > max_len:
        return v, f"Höchstens {max_len} Zeichen."
    if _SAM_BAD.search(v) or _CONTROL.search(v) or v.endswith("."):
        return v, 'Nicht erlaubt sind " / \\ [ ] : ; | = , + * ? < > @ und ein Punkt am Ende.'
    return v, None


def object_name(value, max_len: int = 64, what: str = "Namen"):
    """CN/OU value. DN escaping is done by ldb; "/" is kept out because paths use it."""
    if not isinstance(value, str) or not value.strip():
        return "", f"Bitte einen {what} angeben."
    if value != value.strip():
        return value, "Keine Leerzeichen am Anfang oder Ende."
    if len(value) > max_len:
        return value, f"Höchstens {max_len} Zeichen."
    if _CONTROL.search(value) or "/" in value or "\\" in value or value.startswith("#"):
        return value, "Nicht erlaubt sind / und \\, Steuerzeichen und # am Anfang."
    return value, None


def optional_text(value, max_len: int, multiline: bool = False):
    if value is None:
        return "", None
    if not isinstance(value, str):
        return "", "Bitte Text angeben."
    v = value if multiline else value.strip()
    if len(v) > max_len:
        return v, f"Höchstens {max_len} Zeichen."
    bad = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]") if multiline else _CONTROL
    if bad.search(v):
        return v, "Keine Steuerzeichen."
    return v, None


def email(value):
    v = text(value)
    if not v:
        return "", None
    if len(v) > 256 or not _EMAIL.match(v):
        return v, "Ungültige E-Mail-Adresse."
    return v, None


def unc_path(value):
    v = text(value)
    if not v:
        return "", None
    if len(v) > 260 or not _UNC.match(v):
        return v, "Bitte einen UNC-Pfad angeben, z. B. \\\\server\\freigabe\\ordner."
    return v, None


def home_drive(value):
    v = text(value).upper()
    if not v:
        return "", None
    if not re.match(r"^[A-Z]:$", v):
        return v, "Bitte einen Laufwerksbuchstaben angeben, z. B. H:."
    return v, None


def script_path(value):
    v = text(value).replace("/", "\\")
    if not v:
        return "", None
    parts = v.split("\\")
    if len(v) > 260 or not _SCRIPT_PATH.match(v) or any(p in ("", ".", "..") for p in parts):
        return v, "Pfad relativ zur NETLOGON-Freigabe, z. B. logon.bat oder vertrieb\\logon.cmd."
    return v, None


def boolean(value):
    if isinstance(value, bool):
        return value, None
    return value, "Bitte true oder false angeben."


def integer(value, lo: int, hi: int):
    if isinstance(value, bool) or not isinstance(value, int):
        return value, f"Bitte eine ganze Zahl von {lo} bis {hi} angeben."
    if not lo <= value <= hi:
        return value, f"Erlaubt sind {lo} bis {hi}."
    return value, None


def guid(value) -> str | None:
    """Normalised GUID (lowercase, no braces) or None."""
    if not isinstance(value, str):
        return None
    v = value.strip().strip("{}").lower()
    if re.match(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", v):
        return v
    return None


def dns_name(value):
    """Host name for DNS records: lowercase, labels with letters, digits, '-', '_', '*' as first label."""
    v = text(value).lower().rstrip(".")
    if not v or len(v) > 253:
        return v, "Bitte einen gültigen Namen angeben."
    labels = v.split(".")
    for i, label in enumerate(labels):
        if label == "*" and i == 0:
            continue
        if not _HOST_LABEL.match(label):
            return v, "Ungültiger Name: Buchstaben, Ziffern, Bindestriche und Unterstriche je Teil."
    return v, None


def host_target(value):
    v, err = dns_name(value)
    if err:
        return v, "Bitte einen Hostnamen angeben (keine IP-Adresse)."
    try:
        ipaddress.ip_address(v)
        return v, "Bitte einen Hostnamen angeben (keine IP-Adresse)."
    except ValueError:
        pass
    if v.startswith("*"):
        return v, "Bitte einen Hostnamen angeben."
    return v, None
