# PK95 AD – Design

## Goal

A Windows-style Active Directory for the PK95 LXC: one Samba AD DC (Samba 4.22, Debian trixie) in a Docker
container that PK95 Core starts with `network_mode: host` in an unprivileged Proxmox LXC (Docker with
nesting). Everything is managed through the Core module `ad` over the JSON API in `docs/api.md`.

v1 scope: one DC that provisions a new domain. Not in v1: joining an existing domain as an additional DC,
creating DNS zones, fine-grained password policies, GPO security filtering/WMI filters, an own web UI.

## Language: Python with the Samba bindings

The admin API is a small Python 3 program (stdlib only: `http.server`, `threading`, `json`) that uses the
Python bindings Samba ships (`python3-samba`):

- `samba.samdb.SamDB` opens `sam.ldb` directly as system, the way `samba-tool -H …/sam.ldb` does. No LDAP
  bind, no stored administrator password, no `ldapi` privilege question, and password resets work without
  an encrypted LDAP connection.
- Samba's own NDR types are available: `security.descriptor`, `dnsp.DnssrvRpcRecord` for DNS records,
  `samba.ntacls` for SYSVOL ACLs. `samba-tool` itself is Python on top of the same modules.
- The Go alternative (like pk95dns) would talk LDAP over `ldapi` and shell out to `samba-tool` for passwords,
  DNS, GPOs and ACLs – every call starts a Python interpreter (~1 s) and its text output would have to be
  parsed. That is slower and more fragile than calling the same functions in-process.

`ldb` handles are not thread-safe: all directory access goes through one `SamDB` connection behind a lock.
That is fine for an admin API. `ldb` locks per operation, so the running `samba` daemon and the API share
the database safely (exactly like `samba-tool` while Samba runs).

Processes in the container: `tini` (PID 1) → `python3 -m pk95ad` → children `samba --foreground` and
`chronyd` (signed NTP for Windows time sync). The API supervises both.

## Network (host network in the LXC)

| Port | Service | Note |
|---|---|---|
| 8389/tcp | Admin API | free next to Core 8080, DNS 8053, Proxy 8090, Uptime 3001 |
| 5300/udp+tcp | Samba DNS | `dns port = 5300`, because PK95 DNS owns 53 |
| 88/udp+tcp | Kerberos | |
| 123/udp | NTP (chrony) | signed NTP via `ntp_signd` for domain members |
| 135/tcp | RPC endpoint mapper | |
| 137–138/udp, 139/tcp | NetBIOS | |
| 389/udp+tcp, 636/tcp | LDAP, LDAPS | |
| 445/tcp | SMB (SYSVOL, NETLOGON) | |
| 464/udp+tcp | kpasswd | |
| 3268–3269/tcp | Global Catalog | |
| 49152–49200/tcp | RPC dynamic range | `rpc server dynamic port range` (default would be 49152–65535) |

`interfaces = lo <host_ip>` with `bind interfaces only = yes`: with host network Samba would otherwise also
bind to (and register in DNS!) the Docker bridge addresses (`172.17.0.1`, …), and clients would get
unreachable DC addresses.

### DNS

Samba's internal DNS (`--dns-backend=SAMBA_INTERNAL`) serves the zones `<realm>` (DomainDnsZones) and
`_msdcs.<realm>` (ForestDnsZones) on port 5300 (`dns port`, a Samba option since 4.x that exists to put
another DNS server in front of Samba; 4.22 has it). Clients keep using PK95 DNS on port 53. PK95 DNS needs one
conditional forwarding rule:

```json
{ "domain": "ad.example.com", "upstream": "127.0.0.1:5300" }
```

That covers `_msdcs.ad.example.com` too, because PK95 DNS uses the longest matching suffix. `127.0.0.1` is a
private address, so the rule is allowed with `encrypted_only`. The Core module should add the rule after
setup (Core manages both apps); the API answers `dns_port` in `/api/domain` for that.

Samba's `dns forwarder` points to `127.0.0.1` (PK95 DNS) by default. No loop: Samba answers its own zones
itself and only forwards other names; PK95 DNS only forwards the realm to Samba.

The DC's own name: on every start the app writes `<host_ip> <hostname>.<realm> <hostname>` into the container's
`/etc/hosts` (one line marked `# pk95ad`), so Samba's tools on the DC resolve it without DNS on port 53. Tools
that look up a DC through SRV records (`samba-tool gpo …` without `-H`) still need the realm forwarded by
PK95 DNS; the app itself never calls them (GPOs are written in-process), manual calls should pass
`-H ldap://127.0.0.1`.

Known limit: Windows clients send dynamic DNS updates to port 53 of the SOA server (the DC), i.e. to PK95 DNS,
which does not forward `UPDATE`. Client A/PTR records therefore do not register themselves; add them with
`/api/dns/…` when needed (AD logon does not need them). The DC's own records are created by the provisioning;
`dns update command = samba_dnsupdate --use-samba-tool` refreshes them over RPC instead of `nsupdate` to port 53.

## Unprivileged LXC and NT ACLs

Samba stores Windows ACLs (SYSVOL, NETLOGON, GPO folders) in an extended attribute, by default
`security.NTACL`. Writing `security.*` attributes needs `CAP_SYS_ADMIN` in the initial user namespace, which an
unprivileged LXC never has (and Docker containers do not have by default either). PK95 AD therefore sets

```ini
acl_xattr:security_acl_name = user.NTACL
```

in `[global]` – also during `samba-tool domain provision` (`--option`), so the SYSVOL ACLs that provisioning
sets already go to `user.NTACL`. `samba-tool ntacl sysvolreset/sysvolcheck` read the same option from `smb.conf`.

Assumptions (checked by provisioning; a failure ends in `state: failed` with a German message):

1. The filesystem under the `samba` volume supports `user.*` xattrs and POSIX ACLs. True for ext4 and for
   ZFS datasets with `acltype=posixacl` (Proxmox creates container subvolumes with it) and for the Docker
   volumes inside them (plain directories, not overlayfs).
2. `user.NTACL` is readable and writable by the file owner and root inside the container. The
   `vfs_acl_xattr` module hides the attribute from SMB clients (Samba ≥ 4.15), so Windows clients cannot
   overwrite it through the share; only local access in the container can. Nobody but the app has that.
3. Samba runs as root inside the container (no file capabilities in an unprivileged LXC).

CI provisions a domain inside a plain Docker container (no `CAP_SYS_ADMIN`, so `security.*` fails there as
well) and checks `getfattr -n user.NTACL` on SYSVOL and `samba-tool ntacl sysvolcheck`. A real domain join
needs the LXC and a Windows client.

## Files and volumes

| Volume | Path | Content |
|---|---|---|
| `samba` | `/var/lib/samba` | `private/` (sam.ldb, secrets, krb5.conf), `sysvol/` (GPOs, NETLOGON), `ntp_signd/` |
| `config` | `/etc/samba` | `smb.conf`, generated by the app from its settings |
| `data` | `/var/lib/pk95ad` | `settings.json` (realm, names, IP, forwarder), `setup.log`, `dbcheck.json`, `state.json` (lockout dedupe) |

`smb.conf` is written by the app on every start from `settings.json` (manual edits are overwritten; the
file says so in its header). `/etc/krb5.conf` is copied from `private/krb5.conf` on every start.

```ini
[global]
    netbios name = DC1
    realm = AD.EXAMPLE.COM
    workgroup = EXAMPLE
    server role = active directory domain controller
    dns forwarder = 127.0.0.1
    dns port = 5300
    interfaces = lo 192.168.1.10
    bind interfaces only = yes
    rpc server dynamic port range = 49152-49200
    idmap_ldb:use rfc2307 = yes
    acl_xattr:security_acl_name = user.NTACL
    dns update command = /usr/sbin/samba_dnsupdate --use-samba-tool
    ntp signd socket directory = /var/lib/samba/ntp_signd
    template shell = /bin/false
    template homedir = /nonexistent

[sysvol]
    path = /var/lib/samba/sysvol
    read only = No

[netlogon]
    path = /var/lib/samba/sysvol/ad.example.com/scripts
    read only = No
```

## Backup

`POST /core/backup/prepare` stops Samba (SIGTERM, wait up to 30 s, then SIGKILL) and keeps it stopped
(`samba.state: backup`), so no `ldb` transaction is open while Core copies the volumes. Core stops the container
right after; on the next start Samba runs again. If the container keeps running for 10 minutes (Core failed),
Samba is started again. Restore = Core restores the three volumes; nothing else is needed for a single DC
(no other DC has newer data – with more DCs a restored DC would need an authoritative restore, not v1).

## Group Policy

GPOs are created like `samba-tool gpo create` does, but locally: `groupPolicyContainer` with `CN=User` and
`CN=Machine` below `CN=Policies,CN=System`, then the folder `sysvol/<realm>/Policies/{GUID}` with `GPT.INI`,
`Machine/`, `User/`, then `samba-tool ntacl sysvolreset` so the folder gets the ACL derived from the GPO's
directory ACL. Links are the `gPLink` attribute (`[LDAP://cn={GUID},cn=policies,cn=system,DC=…;<opts>]`,
opts bit 1 = disabled, bit 2 = enforced; the last entry is link order 1), blocked inheritance is `gPOptions = 1`.

Settings: see `docs/api.md` → Curated settings. `Registry.pol` is read and written by `pk95ad/regpol.py`
(PReg v1: `PReg` + version 1, then `[key;value;type;size;data]` with UTF-16 LE strings). Version bump: the
changed half's counter + 1 in both `GPT.INI` and `versionNumber`, extension names updated – otherwise
Windows clients ignore the change.

## Monitoring and events

- Samba process: restart with backoff after an unexpected exit; `ad.samba.down` after an exit or 60 s without
  LDAP/Kerberos answering, `ad.samba.up` on recovery.
- Lockouts: every 30 s the users with `lockoutTime > 0` are compared with the last seen value
  (`state.json`); a new lockout sends `ad.user.locked_out` once.
- dbcheck: daily at 03:30 local time (`TZ`) without fix; errors → `ad.dbcheck.failed`.
