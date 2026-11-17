"""Configuration from environment variables."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass


@dataclass
class Config:
    listen_host: str = "0.0.0.0"
    listen_port: int = 8389
    data_dir: str = "/var/lib/pk95ad"
    samba_dir: str = "/var/lib/samba"
    cache_dir: str = "/var/cache/samba"
    smb_conf: str = "/etc/samba/smb.conf"
    krb5_conf: str = "/etc/krb5.conf"
    chrony_conf: str = "/etc/chrony/pk95ad.conf"
    dns_port: int = 5300
    rpc_ports: str = "49152-49200"
    core_mode: bool = False
    core_url: str = ""
    token: str = ""
    ntp: bool = True
    manage_processes: bool = True  # False in tests: never start samba/chronyd

    def path(self, name: str) -> str:
        return os.path.join(self.data_dir, name)


def _flag(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def load(env=None) -> Config:
    env = os.environ if env is None else env
    cfg = Config()
    listen = env.get("PK95AD_LISTEN", "0.0.0.0:8389")
    host, _, port = listen.rpartition(":")
    cfg.listen_host = host.strip("[]") or "0.0.0.0"
    cfg.listen_port = int(port)
    cfg.data_dir = env.get("PK95AD_DATA_DIR", cfg.data_dir)
    cfg.samba_dir = env.get("PK95AD_SAMBA_DIR", cfg.samba_dir)
    cfg.dns_port = int(env.get("PK95AD_DNS_PORT", cfg.dns_port))
    rpc = env.get("PK95AD_RPC_PORTS", cfg.rpc_ports).strip()
    if not re.match(r"^\d{4,5}-\d{4,5}$", rpc):
        raise ValueError(f"PK95AD_RPC_PORTS must look like 49152-49200, got {rpc!r}")
    cfg.rpc_ports = rpc
    cfg.core_mode = _flag(env.get("PK95_CORE_MODE"), False)
    cfg.core_url = env.get("PK95_CORE_URL", "").rstrip("/")
    cfg.token = env.get("PK95_CORE_TOKEN", "") if cfg.core_mode else env.get("PK95AD_TOKEN", "")
    cfg.ntp = _flag(env.get("PK95AD_NTP"), True)
    return cfg
