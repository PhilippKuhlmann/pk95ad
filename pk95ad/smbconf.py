"""smb.conf, krb5 and chrony configuration rendered from the app settings (docs/design.md)."""

from __future__ import annotations

import os

HEADER = (
    "# Written by PK95 AD on every start from its settings - manual changes are overwritten.\n"
    "# Change the settings in PK95 Core (AD -> Domäne).\n"
)


def provision_options(s: dict, cfg) -> list[str]:
    """--option values for samba-tool domain provision (same as the [global] section below)."""
    return [
        f"netbios name={s['hostname'].upper()}",
        f"dns forwarder={s['dns_forwarder']}",
        f"dns port={cfg.dns_port}",
        f"interfaces={interfaces(s)}",
        "bind interfaces only=yes",
        f"rpc server dynamic port range={cfg.rpc_ports}",
        "acl_xattr:security_acl_name=user.NTACL",
    ]


def interfaces(s: dict) -> str:
    return f"lo {s['host_ip']}" if s.get("host_ip") else "lo"


def render(s: dict, cfg) -> str:
    realm = s["realm"].lower()
    sysvol = os.path.join(cfg.samba_dir, "sysvol")
    lines = [
        HEADER,
        "[global]",
        f"    netbios name = {s['hostname'].upper()}",
        f"    realm = {realm.upper()}",
        f"    workgroup = {s['netbios_domain'].upper()}",
        "    server role = active directory domain controller",
        f"    dns forwarder = {s['dns_forwarder']}",
        f"    dns port = {cfg.dns_port}",
        f"    interfaces = {interfaces(s)}",
        "    bind interfaces only = yes",
        f"    rpc server dynamic port range = {cfg.rpc_ports}",
        "    idmap_ldb:use rfc2307 = yes",
        "    acl_xattr:security_acl_name = user.NTACL",
        "    dns update command = /usr/sbin/samba_dnsupdate --use-samba-tool",
        f"    ntp signd socket directory = {os.path.join(cfg.samba_dir, 'ntp_signd')}",
        "    template shell = /bin/false",
        "    template homedir = /nonexistent",
        "    log level = 1",
        "",
        "[sysvol]",
        f"    path = {sysvol}",
        "    read only = No",
        "",
        "[netlogon]",
        f"    path = {os.path.join(sysvol, realm, 'scripts')}",
        "    read only = No",
        "",
    ]
    return "\n".join(lines)


def chrony(cfg) -> str:
    """chronyd serves the (host-synchronised) local clock and signs replies for domain members."""
    return "\n".join([
        "# Written by PK95 AD on every start.",
        "local stratum 10",
        "allow all",
        f"ntpsigndsocket {os.path.join(cfg.samba_dir, 'ntp_signd')}",
        "",
    ])
