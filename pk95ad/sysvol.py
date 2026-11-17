"""SYSVOL files: case-insensitive paths, GPT.INI, NT ACL reset and the NETLOGON scripts API."""

from __future__ import annotations

import logging
import os
import re
import subprocess

from .errors import ApiError, Fields, not_found

log = logging.getLogger("pk95ad.sysvol")

SCRIPT_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SCRIPT_EXT = (".bat", ".cmd", ".ps1", ".vbs", ".kix")
MAX_SCRIPT = 256 * 1024


def domain_dir(cfg, realm: str) -> str:
    return os.path.join(cfg.samba_dir, "sysvol", realm.lower())


def ci_join(base: str, *parts: str, create: bool = False) -> str:
    """Join path parts, matching existing names case-insensitively (Windows tools write MACHINE, Machine, …).

    With create=True missing directories (all parts but the last) are created with the given case.
    """
    path = base
    for i, part in enumerate(parts):
        match = None
        try:
            for entry in os.listdir(path):
                if entry.lower() == part.lower():
                    match = entry
                    break
        except FileNotFoundError:
            pass
        path = os.path.join(path, match or part)
        if create and i < len(parts) - 1 and not os.path.isdir(path):
            os.makedirs(path, exist_ok=True)
    return path


def read_bytes(path: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return b""


def write_bytes(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".pk95tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def remove(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


# --- GPT.INI -----------------------------------------------------------------------------------------

def gpt_version(text: str) -> int:
    m = re.search(r"^\s*Version\s*=\s*(\d+)\s*$", text, re.I | re.M)
    return int(m.group(1)) if m else 0


def gpt_set_version(text: str, version: int) -> str:
    lines = text.replace("\r\n", "\n").split("\n") if text.strip() else []
    out, done, in_general = [], False, False
    for line in lines:
        s = line.strip()
        if s.startswith("["):
            if in_general and not done:
                out.append(f"Version={version}")
                done = True
            in_general = s.lower() == "[general]"
        if in_general and re.match(r"^\s*Version\s*=", line, re.I):
            if not done:
                out.append(f"Version={version}")
                done = True
            continue
        if line or out:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    if not done:
        if not any(x.strip().lower() == "[general]" for x in out):
            out.insert(0, "[General]")
            out.insert(1, f"Version={version}")
        else:
            idx = next(i for i, x in enumerate(out) if x.strip().lower() == "[general]")
            out.insert(idx + 1, f"Version={version}")
    return "\r\n".join(out) + "\r\n"


# --- NT ACLs -----------------------------------------------------------------------------------------

def reset_acls(cfg) -> None:
    """samba-tool ntacl sysvolreset: gives new SYSVOL files and GPO folders the NT ACL derived from the
    directory (GPO ACLs) - written to user.NTACL per smb.conf."""
    try:
        res = subprocess.run(["samba-tool", "ntacl", "sysvolreset", "-s", cfg.smb_conf],
                             capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ApiError(500, f"SYSVOL-Berechtigungen konnten nicht gesetzt werden: {exc}") from exc
    if res.returncode != 0:
        out = (res.stderr or res.stdout or "").strip()
        log.error("sysvolreset failed: %s", out)
        last = out.splitlines()[-1] if out else ""
        raise ApiError(500, "SYSVOL-Berechtigungen konnten nicht gesetzt werden." + (f" {last}" if last else ""))


# --- NETLOGON scripts --------------------------------------------------------------------------------

def scripts_dir(cfg, realm: str) -> str:
    return os.path.join(domain_dir(cfg, realm), "scripts")


def _script_path(cfg, realm: str, name: str) -> str:
    if not SCRIPT_NAME.match(name or "") or not name.lower().endswith(SCRIPT_EXT) or name.startswith("."):
        raise not_found("Skript nicht gefunden.")
    return os.path.join(scripts_dir(cfg, realm), name)


def scripts_list(cfg, realm: str) -> list[dict]:
    d = scripts_dir(cfg, realm)
    out = []
    try:
        names = os.listdir(d)
    except FileNotFoundError:
        return out
    for name in names:
        p = os.path.join(d, name)
        if not os.path.isfile(p) or not name.lower().endswith(SCRIPT_EXT):
            continue
        st = os.stat(p)
        out.append({"name": name, "size": st.st_size, "changed_at": int(st.st_mtime * 1000)})
    out.sort(key=lambda x: x["name"].casefold())
    return out


def script_get(cfg, realm: str, name: str) -> dict:
    p = _script_path(cfg, realm, name)
    data = read_bytes(p)
    if not data and not os.path.isfile(p):
        raise not_found("Skript nicht gefunden.")
    if data.startswith(b"\xef\xbb\xbf"):
        text = data[3:].decode("utf-8", errors="replace")
    elif data.startswith(b"\xff\xfe"):
        text = data[2:].decode("utf-16-le", errors="replace")
    else:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("cp1252", errors="replace")
    st = os.stat(p)
    return {"name": os.path.basename(p), "content": text.replace("\r\n", "\n"), "size": st.st_size,
            "changed_at": int(st.st_mtime * 1000)}


def script_put(cfg, realm: str, name: str, body: dict) -> dict:
    f = Fields()
    if not SCRIPT_NAME.match(name or "") or name.startswith(".") or not name.lower().endswith(SCRIPT_EXT):
        f.add("name", "1–64 Zeichen A–Z, 0–9, . _ - mit der Endung .bat, .cmd, .ps1, .vbs oder .kix.")
    content = body.get("content")
    if not isinstance(content, str):
        f.add("content", "Bitte den Inhalt angeben.")
    elif len(content.encode("utf-8")) > MAX_SCRIPT:
        f.add("content", "Höchstens 256 KiB.")
    elif "\x00" in content:
        f.add("content", "Keine Nullzeichen.")
    f.raise_if_any()
    text = content.replace("\r\n", "\n").replace("\n", "\r\n")
    data = text.encode("utf-8")
    if name.lower().endswith(".ps1"):
        data = b"\xef\xbb\xbf" + data
    p = os.path.join(scripts_dir(cfg, realm), name)
    write_bytes(p, data)
    os.chmod(p, 0o644)
    reset_acls(cfg)
    return script_get(cfg, realm, name)


def script_delete(cfg, realm: str, name: str) -> None:
    p = _script_path(cfg, realm, name)
    if not os.path.isfile(p):
        raise not_found("Skript nicht gefunden.")
    os.unlink(p)
