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

### DNS of the DC itself (1.1.1)

With host network the container gets a copy of the LXC's `/etc/resolv.conf` – usually the router, which does not
know the AD zone. `samba_dnsupdate` (run by Samba every few minutes) looks up each record the DC needs through that
resolver (`/etc/resolv.conf`, always port 53), gets NXDOMAIN, and calls `samba-tool dns add` for every record,
which fails with `WERR_DNS_ERROR_RECORD_ALREADY_EXISTS` because the records are there. Its exit code is the number
of failed records (`sys.exit(error_count)`), hence `Failed DNS update with exit code 29` / `110` in Samba's log –
the same cause, counted per run.

The app therefore points the container's resolver at PK95 DNS, the same way a Windows DC uses itself as DNS
server: on every start and every 30 s it sends an SOA query for the realm to `127.0.0.1:53`; once PK95 DNS answers
it (the conditional forwarding rule exists), `/etc/resolv.conf` becomes `nameserver 127.0.0.1`, then up to two of
the LXC's nameservers as fallback, `search <realm> <old search domains>`, `options timeout:2 attempts:2`. The
original lines are kept as `# pk95ad-original:` comments, so rewriting never loses them (Docker gives the
container its own copy, written in place). As long as nothing on `127.0.0.1:53` answers the zone the file stays
untouched and `GET /api/domain` → `resolver` explains why.

Why not only `samba_dnsupdate`: it can be pointed at another resolv.conf (`RESOLV_CONF`), but a resolv.conf has no
port, so it could not ask Samba on 5300 directly either – it would need PK95 DNS on 53 as well. Kerberos and
Samba's own tools on the DC also resolve through `/etc/resolv.conf`, so one system-wide answer is simpler.

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
sets already go to `user.NTACL`. `samba-tool ntacl sysvolreset` and `ntacl get` read the same option from `smb.conf`
(they go through the VFS). **Not usable:** `samba-tool ntacl sysvolcheck` reads `security.NTACL` directly and ignores
the option; it always fails with `No data available` (ENODATA). To check the ACLs use `samba-tool gpo aclcheck -H
ldap://127.0.0.1 -U Administrator` or `samba-tool ntacl get --as-sddl <path>`.

Assumptions (checked by provisioning; a failure ends in `state: failed` with a German message):

1. The filesystem under the `samba` volume supports `user.*` xattrs and POSIX ACLs. True for ext4 and for
   ZFS datasets with `acltype=posixacl` (Proxmox creates container subvolumes with it) and for the Docker
   volumes inside them (plain directories, not overlayfs).
2. `user.NTACL` is readable and writable by the file owner and root inside the container. The
   `vfs_acl_xattr` module hides the attribute from SMB clients (Samba ≥ 4.15), so Windows clients cannot
   overwrite it through the share; only local access in the container can. Nobody but the app has that.
3. Samba runs as root inside the container (no file capabilities in an unprivileged LXC).

CI provisions a domain inside a Docker container with `userns-remap` (no `CAP_SYS_ADMIN` and only 65536 IDs, like
the LXC; `security.*` fails there as
well) and checks `getfattr -n user.NTACL` on SYSVOL, `samba-tool ntacl get`, `samba-tool gpo aclcheck` and SMB access
to SYSVOL/NETLOGON. A real domain join
needs the LXC and a Windows client.

## Time (1.4.0)

The DC's clock is the Proxmox host's clock: `chronyd -x` in the unprivileged LXC can never set it. The NTP servers
in the settings (`ntp_servers`, default `de.pool.ntp.org`) are only a reference: chrony measures the host clock
against them, `GET /api/time` reports the offset, and the dashboard warns from 1 s on (error from 120 s; Kerberos
tolerates 5 minutes). Domain members keep getting signed NTP from chronyd – with `-x` chrony serves its estimate of
true time (host clock plus measured correction) while a source is selected, otherwise the host clock at stratum 10.
Samba's Kerberos uses the uncorrected host clock, which is why a wrong host clock must be fixed on the host.
Changing the servers rewrites `/etc/chrony/pk95ad.conf` and restarts only chronyd.

## Unix IDs (unprivileged LXC)

The LXC maps only 65536 IDs (`/proc/self/uid_map`: `0 100000 65536`), so inside it only the IDs 0–65535
exist and a `chown` to a higher ID fails with `EINVAL`. Samba gives every SID that touches the file system
(well-known groups such as SYSTEM or Authenticated Users, users opening SMB shares, …) a Unix ID from the
range in `idmap.ldb` (`CN=CONFIG`: `lowerBound`/`upperBound`), by default 3000000–4000000, and chowns SYSVOL
files to it. In the LXC that made provisioning abort with `PANIC: Security context active token stack
underflow` (in `set_nt_acl → chown_if_needed`).

| Range | Used for |
|---|---|
| 0–9999 | system accounts and Samba's fixed mappings (Administrator → root 0, Domain Users → users 100) |
| 10000–19999 | RFC2307 `uidNumber`/`gidNumber` set by hand (NIS attributes; `msSFU30MaxUidNumber` starts at 10000). PK95 AD sets none. |
| 20000–59999 | Samba's automatic IDs (`idmap.ldb`) |
| 60000–65535 | left free (Debian reserve, `nobody` = 65534, the fixed mapping of Guest) |

The image patches `/usr/share/samba/setup/idmap_init.ldif` (from which provisioning creates `idmap.ldb`) to
20000–59999; the build fails if the patch does not apply. Setup refuses to run with an unpatched file and checks
`idmap.ldb` after provisioning. `GET /api/domain` → `idmap` reports the range, the next ID and problems (a domain
provisioned with 1.0.0 outside the LXC, `uidNumber`s outside 10000–19999, range nearly used up). Samba's C
allocator reads only these bounds (`source4/winbind/idmap.c`), so `sysvolreset`, new GPOs and scripts and smbd
mapping a user without `uidNumber` all stay in the range; CI checks that under `userns-remap` (65536 IDs like
the LXC). A new setup after a failed one removes `idmap.ldb` with everything else under `/var/lib/samba`.

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
