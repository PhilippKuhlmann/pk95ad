# PK95 AD – HTTP API

PK95 AD runs a Samba Active Directory domain controller and exposes one JSON admin API for the
PK95 Core module (app protocol v1, see `PK95Core/docs/app-protocol.md`). There is no own web UI in
v1. Default listen address `0.0.0.0:8389` (`PK95AD_LISTEN`).

Implementation: Python 3 (Debian trixie, Samba 4.22) with the Samba Python bindings. Directory
operations run in-process against `sam.ldb` as system (like `samba-tool -H /var/lib/samba/private/sam.ldb`),
so the API needs no LDAP bind and no stored administrator password. Why Python and not Go:
see `docs/design.md`.

## Conventions

- Request and response bodies are JSON (`Content-Type: application/json`).
- Timestamps are Unix **milliseconds** (integers). `0` means "never/none".
- Directory objects (users, groups, computers, OUs) are identified by their `objectGUID` in lowercase
  without braces (`"5f0e1a6c-…"`). Group Policy objects by their GUID in the same form; `guid` carries the
  braced uppercase form Windows shows (`"{31B2F340-016D-11D2-945F-00C04FB984F9}"`).
- Errors: `{"error": "German message"}` with a fitting status. Validation errors are
  `422 {"error": "Bitte Eingaben prüfen.", "fields": {"<field>": "German message"}}`. Field names are
  the JSON keys of the request body, for array items `member_ids.2`, for nested objects `settings.screen_lock_minutes`.
- `401` without valid token, `404` unknown id, `413` body over 2 MiB, `415` writing request without
  `Content-Type: application/json` (Core sends it, also on DELETE).
- `409 {"error": "Die Domäne ist noch nicht eingerichtet."}` for every directory, DNS and GPO route while
  `state` is not `ready`. `409` also for state conflicts (non-empty OU, setup already running, …).
- `403 {"error": "…"}` when an action on a protected built-in object is refused (e.g. deleting
  `Domain Admins`, disabling `Administrator`, anything on `krbtgt`).
- Directory errors from Samba that have no German mapping become `422 {"error": "Samba: <english text>"}`.

## Authentication

**Core mode** (`PK95_CORE_MODE=1`): every `/api/*` and `/core/*` route except `GET /core/health` requires
`Authorization: Bearer <PK95_CORE_TOKEN>` (constant-time comparison via `hmac.compare_digest`, tokens shorter
than 32 chars never match). `/` serves a short HTML note.

**Standalone** (no `PK95_CORE_MODE`): v1 has no own UI or login. The API then requires
`Authorization: Bearer <PK95AD_TOKEN>` (also at least 32 chars); without `PK95AD_TOKEN` only `/core/health`
answers (everything else `401`). Useful for scripts and tests.

## Core protocol routes

- `GET /core/health` → `200 {"ok": true, "version": "1.0.0", "state": "ready"}` as soon as the API serves
  requests – also before setup (`state: "unconfigured"`) and while Samba is down (that shows up in
  `/api/status` and as event `ad.samba.down`).
- `GET /core/manifest` → see below.
- `POST /core/backup/prepare` → `204`. Stops Samba cleanly (all `sam.ldb` partitions, `secrets.ldb`,
  `idmap.ldb` closed, no open transaction) so the volumes Core copies next are consistent. Core stops
  the container right after; if it does not within 10 minutes, Samba is started again. Before setup the
  route only answers `204`.

### Manifest

```json
{
  "id": "ad",
  "name": "PK95 AD",
  "version": "1.0.0",
  "protocol": 1,
  "icon": "key",
  "menu": [
    { "key": "domain", "label": "Domäne", "icon": "server" },
    { "key": "users", "label": "Benutzer", "icon": "user" },
    { "key": "groups", "label": "Gruppen", "icon": "apps" },
    { "key": "computers", "label": "Computer", "icon": "cpu" },
    { "key": "ous", "label": "Organisationseinheiten", "icon": "box" },
    { "key": "gpo", "label": "Gruppenrichtlinien", "icon": "lock" },
    { "key": "dns", "label": "DNS", "icon": "globe" },
    { "key": "scripts", "label": "Anmeldeskripte", "icon": "terminal" }
  ],
  "capabilities": ["events", "backup"],
  "events": ["ad.setup.done", "ad.setup.failed", "ad.samba.down", "ad.samba.up",
             "ad.user.locked_out", "ad.dbcheck.failed"]
}
```

The setup wizard belongs to the `domain` page: while `GET /api/setup` says `state != "ready"` the module
shows the wizard there (and the other pages can show a hint pointing to it).

### Events

| type | severity | when | `data` |
|---|---|---|---|
| `ad.setup.done` | info | provisioning finished, Samba started | `realm`, `netbios_domain`, `dc` |
| `ad.setup.failed` | critical | provisioning failed | `error` |
| `ad.samba.down` | critical | the `samba` process exited unexpectedly or LDAP/Kerberos on the DC IP stopped answering for 60 s (not during backup) | `exit_code`, `error` |
| `ad.samba.up` | info | Samba answers again after `ad.samba.down` | `down_seconds` |
| `ad.user.locked_out` | warning | an account was locked by the lockout policy (checked every 30 s, once per lockout) | `user_id`, `username`, `locked_at` |
| `ad.dbcheck.failed` | warning | a database check (manual or the daily one at 03:30 local time) found errors | `errors`, `fixed` |

Buffered and retried for up to one hour like the other apps.

## Setup (first start)

Without a provisioned domain the app reports `state: "unconfigured"`.

### `GET /api/setup`

```json
{
  "state": "unconfigured",
  "error": "",
  "started_at": 0,
  "finished_at": 0,
  "log": [],
  "defaults": {
    "hostname": "dc1",
    "host_ips": ["192.168.1.10"],
    "dns_forwarder": "127.0.0.1"
  },
  "domain": null
}
```

- `state`: `unconfigured` | `provisioning` | `ready` | `failed`.
- `log`: the last 200 lines of the provisioning output (`samba-tool domain provision`, …), newest last.
- `error`: German message when `failed` (the wizard shows it and offers to try again).
- `defaults`: suggestions for the wizard. `host_ips` are the global IPv4 addresses of the host network
  (Docker bridges, loopback and link-local are left out); `hostname` is the short host name of the LXC
  when it is a valid DC name, else `dc1`.
- `domain`: when `ready`, `{"realm", "netbios_domain", "hostname", "host_ip"}`.

### `POST /api/setup`

```json
{
  "realm": "ad.example.com",
  "netbios_domain": "EXAMPLE",
  "hostname": "dc1",
  "host_ip": "192.168.1.10",
  "dns_forwarder": "127.0.0.1",
  "admin_password": "…"
}
```

→ `202 {"state": "provisioning"}`. Runs in the background (about 30–90 s); poll `GET /api/setup`.
`409` while `provisioning` or when already `ready`. After `failed` a new `POST` starts over (the partial
provisioning is removed first).

| field | rule |
|---|---|
| `realm` | DNS domain of the AD, 2–5 labels, lowercase letters, digits, hyphens, max 63 chars per label, at least two labels; not `.local` („.local ist für mDNS reserviert. Bitte eine Subdomain einer eigenen Domain wählen, z. B. ad.example.com.“). Stored lowercase; the Kerberos realm is the uppercase form. |
| `netbios_domain` | 1–15 chars `A-Z0-9-`, not only digits, uppercase (normalised); default in the wizard: first label of `realm`. Must differ from `hostname`. |
| `hostname` | name of the DC, 1–15 chars `a-z0-9-`, no leading/trailing hyphen, not only digits, lowercase (normalised). The DC is `<hostname>.<realm>`. |
| `host_ip` | IPv4 address the DC registers in DNS and binds to; must be one of `defaults.host_ips` („Diese Adresse gehört nicht zu diesem Host.“). |
| `dns_forwarder` | IPv4 or IPv6 address (optionally `:port` / `[v6]:port`) where Samba's DNS sends names outside the AD zones. Default `127.0.0.1` (PK95 DNS on the same LXC). |
| `admin_password` | password of `Administrator`: 8–127 chars and at least 3 of: uppercase, lowercase, digit, other character (Samba's default complexity), must not contain `Administrator`. Not stored by PK95 AD. |

Steps (each one appears in `log`): write a minimal `smb.conf` with the PK95 options (see `docs/design.md`),
`samba-tool domain provision --use-rfc2307 --dns-backend=SAMBA_INTERNAL …`, write the final `smb.conf`,
copy `krb5.conf`, start Samba, wait until LDAP answers, `samba-tool ntacl sysvolcheck`, send `ad.setup.done`.

## Status

### `GET /api/status`

```json
{
  "version": "1.0.0",
  "core_mode": true,
  "state": "ready",
  "started_at": 1762700000000,
  "samba": {
    "state": "running",
    "pid": 41,
    "since": 1762700003000,
    "restarts": 0,
    "last_exit": "",
    "services": { "ldap": true, "kerberos": true, "smb": true, "dns": true }
  },
  "ntp": { "running": true, "available": true, "message": "" },
  "domain": { "realm": "ad.example.com", "netbios_domain": "EXAMPLE", "hostname": "dc1", "host_ip": "192.168.1.10" }
}
```

`ntp`: signed NTP for domain members (`chronyd -x`: serves the host-synchronised clock, never sets it).
It never blocks Samba. `available: false` with a German `message` when chronyd cannot run or port 123/udp is
taken („NTP nicht verfügbar: Port 123/udp ist im LXC belegt.“); `PK95AD_NTP=0` switches it off.

`samba.state`: `stopped` (not set up), `starting`, `running`, `restarting` (crashed, restarted with
backoff 5 s … 5 min), `backup` (stopped by `/core/backup/prepare`). `services`: TCP 389 / 88 / 445 on
`host_ip` and DNS on `127.0.0.1:5300` answer (checked every 30 s). `last_exit`: German text of the last
unexpected exit. `domain` is `null` before setup.

## Domain

### `GET /api/domain`

```json
{
  "realm": "ad.example.com",
  "kerberos_realm": "AD.EXAMPLE.COM",
  "netbios_domain": "EXAMPLE",
  "base_dn": "DC=ad,DC=example,DC=com",
  "sid": "S-1-5-21-…",
  "dc": { "hostname": "dc1", "fqdn": "dc1.ad.example.com", "ip": "192.168.1.10" },
  "domain_level": "2008_R2",
  "forest_level": "2008_R2",
  "samba_version": "4.22.3-Debian",
  "fsmo": {
    "schema": "dc1", "naming": "dc1", "pdc": "dc1", "rid": "dc1", "infrastructure": "dc1",
    "domain_dns": "dc1", "forest_dns": "dc1"
  },
  "upn_suffixes": ["ad.example.com"],
  "counts": { "users": 14, "groups": 52, "computers": 3, "ous": 4, "gpos": 3 },
  "dns_forwarder": "127.0.0.1",
  "dns_port": 5300,
  "ntp": { "running": true, "available": true, "message": "" }
}
```

FSMO values are the DC names (`hostname` of the owning server). With only one DC all are this DC.
`dns_port` is stable (the Core module uses it for the conditional forwarding rule in PK95 DNS).
`ntp`: same object as in `/api/status`.

### `PUT /api/domain/settings`

Body `{"dns_forwarder": "192.168.1.1"}` → `200` domain object. Rewrites `smb.conf` and restarts Samba
(a few seconds without LDAP/Kerberos).

### `GET /api/domain/password-policy` / `PUT /api/domain/password-policy`

```json
{
  "min_length": 7,
  "complexity": true,
  "history_length": 24,
  "max_age_days": 42,
  "min_age_days": 1,
  "lockout_threshold": 0,
  "lockout_duration_minutes": 30,
  "lockout_window_minutes": 30
}
```

`PUT` takes any subset and answers with the full object. Rules: `min_length` 0–255, `history_length` 0–24,
`max_age_days` 0–999 (0 = never expires), `min_age_days` 0–998 and `< max_age_days` unless that is 0,
`lockout_threshold` 0–999 (0 = no lockout), `lockout_duration_minutes` 0–99999 (0 = until an admin
unlocks), `lockout_window_minutes` 1–99999 and `≤ lockout_duration_minutes` unless that is 0.
Stored on the domain object (like `samba-tool domain passwordsettings`), which is what the DC enforces.

### `POST /api/domain/dbcheck` / `GET /api/domain/dbcheck`

`POST {"fix": false}` → `202 {"running": true}` (`409` when one is running). `fix: true` runs
`samba-tool dbcheck --cross-ncs --fix --yes`, otherwise without `--fix`.
`GET` →

```json
{
  "running": false,
  "fix": false,
  "started_at": 1762700000000,
  "finished_at": 1762700012000,
  "ok": true,
  "errors": 0,
  "output": "Checking 412 objects\nChecked 412 objects (0 errors)\n"
}
```

`output` is cut to the last 64 KiB. Before the first run all fields are zero/empty and `ok` is `null`.
The daily automatic check runs without `--fix`.

## Organizational units

Node object:

```json
{
  "id": "…", "name": "Vertrieb", "dn": "OU=Vertrieb,OU=Firma,DC=ad,DC=example,DC=com",
  "type": "ou", "description": "", "path": "Firma/Vertrieb", "parent_id": "…",
  "protected": false, "block_inheritance": false, "children": []
}
```

`type`: `domain` (the root), `ou`, `container` (`Users`, `Computers`) or `builtin` (`Builtin`).
`path` is the slash-separated path below the domain (`""` for the root). `protected`: cannot be renamed,
deleted or moved (root, `Users`, `Computers`, `Builtin`, `Domain Controllers`).

| Route | Body | Answer |
|---|---|---|
| `GET /api/ous` | – | `200` root node with nested `children` (OUs and the containers above, sorted by name) |
| `POST /api/ous` | `{"name", "parent_id", "description"}` | `201` node (no children) |
| `PUT /api/ous/{id}` | any of `{"name", "description", "block_inheritance"}` | `200` node. `block_inheritance` = GPO inheritance blocked (`gPOptions`), only for `type: ou` |
| `DELETE /api/ous/{id}?recursive=1` | – | `204`. Without `recursive=1` a non-empty OU answers `409 {"error": "Die Organisationseinheit ist nicht leer."}`. Never when a domain controller is inside. |
| `GET /api/ous/{id}/gpo-inheritance` | – | `200` resulting GPO order for objects in this container, see Group Policy |
| `POST /api/move` | `{"ids": ["…"], "target_id": "…"}` | `200 {"moved": 2}` – users, groups, computers and OUs; target is an OU, the root or a container (not `Builtin`). An OU cannot be moved into itself or below itself. |

`name`: 1–64 chars, no `,+"\<>;=/#` and no leading/trailing space; unique below the parent
(„Es gibt hier schon eine Organisationseinheit mit diesem Namen.“).

## Users

List item:

```json
{
  "id": "…", "username": "max", "upn": "max@ad.example.com",
  "display_name": "Max Muster", "given_name": "Max", "surname": "Muster",
  "email": "max@example.com", "description": "",
  "ou_id": "…", "ou_path": "Firma/Vertrieb",
  "enabled": true, "locked": false, "must_change_password": false,
  "password_never_expires": false, "expires_at": 0, "last_logon": 1762690000000,
  "builtin": false, "protected": false
}
```

Details (`GET /api/users/{id}` and answers of `POST`/`PUT`) add:

```json
{
  "dn": "CN=Max Muster,OU=Vertrieb,OU=Firma,DC=ad,DC=example,DC=com",
  "sid": "S-1-5-21-…-1104",
  "created_at": 1762600000000, "changed_at": 1762690000000,
  "password_last_set": 1762600000000, "bad_password_count": 0, "locked_at": 0,
  "profile_path": "\\\\dc1\\profiles\\max", "home_directory": "\\\\nas\\home\\max", "home_drive": "H:",
  "script_path": "logon.bat",
  "primary_group": { "id": "…", "name": "Domain Users" },
  "groups": [ { "id": "…", "name": "Vertrieb", "scope": "global", "type": "security", "builtin": false } ]
}
```

- `builtin`: well-known account (RID < 1000: `Administrator`, `Guest`, `krbtgt`). `protected`: cannot be
  deleted, renamed or moved; `Administrator` cannot be disabled either; `krbtgt` cannot be changed at all.
  The list hides `krbtgt` unless `?all=1`.
- `locked`: from `msDS-User-Account-Control-Computed` (lockout still active). `last_logon`: `lastLogonTimestamp`
  (replicated, up to 14 days behind; `0` = never).
- `expires_at`: account expiry (`accountExpires`), `0` = never.
- `groups`: direct memberships without the primary group.

| Route | Body | Answer |
|---|---|---|
| `GET /api/users?search=&ou_id=&recursive=1&all=0` | – | `200 {"items": [user…], "total": 14}` sorted by `display_name`. `search`: substring of username, display name, email or UPN (case-insensitive). `ou_id`: only this container (with `recursive=1` also below). At most 2000 items (`total` counts all). |
| `GET /api/users/{id}` | – | `200` details |
| `POST /api/users` | see below | `201` details |
| `PUT /api/users/{id}` | any subset of the editable fields | `200` details |
| `DELETE /api/users/{id}` | – | `204` |
| `POST /api/users/{id}/password` | `{"password", "must_change_password": false}` | `204` (does not change `enabled`) |
| `POST /api/users/{id}/unlock` | – | `204` |
| `PUT /api/users/{id}/groups` | `{"group_ids": ["…"]}` | `200 {"groups": […]}` – replaces the direct memberships (primary group stays) |

`POST /api/users` body:

```json
{
  "username": "max", "given_name": "Max", "surname": "Muster", "display_name": "Max Muster",
  "upn": "max@ad.example.com", "email": "max@example.com", "description": "",
  "ou_id": "…", "password": "…", "must_change_password": true, "enabled": true,
  "password_never_expires": false, "expires_at": 0,
  "profile_path": "", "home_directory": "", "home_drive": "", "script_path": "",
  "group_ids": []
}
```

Editable with `PUT`: all of these except `password`, `ou_id` (use `/api/move`) and `group_ids` (use
`/groups`). Fields missing in a `PUT` stay unchanged; `""` clears a text field.

| field | rule |
|---|---|
| `username` | `sAMAccountName`: 1–20 chars, no `"/\[]:;|=,+*?<>@` and no leading/trailing space or dot; unique in the domain (users, groups and computers) |
| `given_name`, `surname` | 0–64 chars; at least one of `given_name`, `surname`, `display_name` |
| `display_name` | 1–64 chars (the CN limit), no `/` or `\`, default `"<given_name> <surname>"`. It is also the object name (CN): unique within the OU, changing it renames the object |
| `upn` | `<name>@<suffix>`, suffix one of `upn_suffixes`; default `<username>@<realm>`; unique |
| `email` | empty or an e-mail address |
| `description` | 0–1024 chars |
| `ou_id` | default: the `Users` container |
| `password` | required on create; Samba checks the domain password policy → `422 fields.password` („Das Kennwort erfüllt die Kennwortrichtlinie nicht: mindestens 7 Zeichen, Komplexität …“) |
| `expires_at` | `0` or a future timestamp (end of the account's last day) |
| `profile_path`, `home_directory` | empty or a UNC path `\\server\share\…` (max 260 chars); `home_drive` empty or `A:`–`Z:` (needs `home_directory`) |
| `script_path` | empty or a path relative to the NETLOGON share (`logon.bat`, `scripts/vertrieb.cmd`) |

## Groups

```json
{
  "id": "…", "name": "Vertrieb", "description": "", "email": "",
  "type": "security", "scope": "global",
  "ou_id": "…", "ou_path": "Firma", "member_count": 4,
  "builtin": false, "protected": false
}
```

- `type`: `security` | `distribution`. `scope`: `global` | `domain_local` | `universal` | `builtin_local`
  (the groups in `Builtin`, read-only scope).
- `builtin`: well-known group (RID < 1000 or in `Builtin`, e.g. `Domain Admins`, `Domain Users`,
  `Administrators`). Built-in groups cannot be renamed, deleted, moved or changed in type/scope; their
  description and members can be changed (that is how someone becomes a domain admin). `protected` = `builtin`.

Details add `dn`, `sid`, `members` (direct: `[{"id", "name", "kind": "user"|"group"|"computer"|"foreign", "builtin"}]`,
for groups that are a primary group, such as `Domain Users`, including the accounts with that primary group),
`member_of` (`[{"id", "name"}]`) and `effective_users` (all users, also through nested groups,
`[{"id", "name", "username"}]`, max 2000).

| Route | Body | Answer |
|---|---|---|
| `GET /api/groups?search=&ou_id=&recursive=1&type=&scope=` | – | `200 {"items": [group…], "total": 52}` sorted by name |
| `GET /api/groups/{id}` | – | `200` details |
| `POST /api/groups` | `{"name", "description", "email", "type", "scope", "ou_id", "member_ids": []}` | `201` details |
| `PUT /api/groups/{id}` | any of `{"name", "description", "email", "type", "scope"}` | `200` details |
| `PUT /api/groups/{id}/members` | `{"member_ids": ["…"]}` | `200` details – replaces the direct members (users, groups, computers). Accounts that have this group as primary group (`members[].primary: true`) stay members; they are not in the list and cannot be removed here |
| `DELETE /api/groups/{id}` | – | `204` |

`name`: 1–64 chars, same characters as `username`; it is CN and `sAMAccountName`, unique in the domain.
Default `type: security`, `scope: global`, `ou_id`: `Users`. Scope changes follow the AD rules (global ↔
domain local only via universal, a global group with global members cannot become universal, …); Samba's
refusal becomes `422 fields.scope`. A group cannot be a member of itself (also not through nesting:
`422 member_ids.N`, „Das würde eine Schleife ergeben.“).

## Computers

```json
{
  "id": "…", "name": "PC-01", "dns_hostname": "pc-01.ad.example.com",
  "os": "Windows 11 Pro", "os_version": "10.0 (26100)",
  "description": "", "enabled": true, "is_dc": false,
  "ou_id": "…", "ou_path": "Computers", "last_logon": 1762690000000, "created_at": 1762000000000
}
```

Details add `dn`, `sid`, `groups` (`[{"id", "name"}]`).

| Route | Body | Answer |
|---|---|---|
| `GET /api/computers?search=&ou_id=&recursive=1` | – | `200 {"items": [computer…], "total": 3}` |
| `GET /api/computers/{id}` | – | `200` details |
| `PUT /api/computers/{id}` | any of `{"description", "enabled"}` | `200` details |
| `DELETE /api/computers/{id}` | – | `204` (the machine has to join again) |

Domain controllers (`is_dc`) cannot be disabled, deleted or moved out of `Domain Controllers` (`403`).
Joining a computer happens on the computer (with a domain account); no pre-staging in v1.

## DNS of the AD zones

Samba's internal DNS serves the AD zones on `127.0.0.1:5300` and `<host_ip>:5300`; PK95 DNS forwards
the realm to it (see `docs/design.md`). The API edits the zones directly in the directory (`dnsNode`
objects), which is what Samba's DNS serves.

```json
{ "name": "ad.example.com", "partition": "domain", "reverse": false, "record_count": 23, "system": false }
```

`partition`: `domain` (`DomainDnsZones`) or `forest` (`ForestDnsZones`, `_msdcs.<realm>`).
`system: true` for `_msdcs.<realm>`.

Record (same shape as PK95 DNS records):

```json
{ "id": "a1b2c3…", "zone": "ad.example.com", "name": "nas.ad.example.com", "type": "A",
  "value": "192.168.1.20", "ttl": 900, "priority": 0, "weight": 0, "port": 0,
  "dynamic": false, "system": false }
```

| Route | Body | Answer |
|---|---|---|
| `GET /api/dns/zones` | – | `200 [zone…]` |
| `GET /api/dns/zones/{zone}/records?type=&q=` | – | `200 [record…]` sorted by name, type, value |
| `POST /api/dns/zones/{zone}/records` | `{"name", "type", "value", "ttl", "priority", "weight", "port"}` | `201` record |
| `PUT /api/dns/zones/{zone}/records/{id}` | same | `200` record (the `id` changes with the content) |
| `DELETE /api/dns/zones/{zone}/records/{id}` | – | `204` |

- `id`: hex hash of name, type and data – stable as long as the record does not change.
- `name`: full host name inside the zone; the zone name itself is the apex. Types `A`, `AAAA`, `CNAME`,
  `MX`, `TXT`, `SRV`, `PTR` (only in reverse zones) can be written; `NS` and `SOA` are listed read-only.
- `ttl` 0–604800, default 900 (Samba's default). `value`/`priority`/`weight`/`port` like PK95 DNS.
- `dynamic: true`: registered by a client (aging timestamp set); editing makes it static.
- `system: true`: records the DC needs (`SOA`, `NS`, the DC's own A record, `_ldap`/`_kerberos`/`_gc`/`_kpasswd`
  SRV records, everything in `_msdcs`). Changing or deleting them answers `403`.
- Creating zones is not part of v1 (reverse lookups are answered by PK95 DNS' private PTR handling).

## Group Policy

GPO object:

```json
{
  "id": "31b2f340-016d-11d2-945f-00c04fb984f9",
  "guid": "{31B2F340-016D-11D2-945F-00C04FB984F9}",
  "name": "Default Domain Policy",
  "status": "enabled",
  "builtin": true,
  "created_at": 1762600000000, "changed_at": 1762690000000,
  "version": { "computer": 3, "user": 0 },
  "links": [ { "target_id": "…", "target_name": "ad.example.com", "target_type": "domain",
               "target_path": "", "enabled": true, "enforced": false, "order": 1 } ],
  "sysvol_ok": true
}
```

- `status`: `enabled` | `user_disabled` | `computer_disabled` | `disabled` (the GPO `flags`).
- `builtin`: `Default Domain Policy` and `Default Domain Controllers Policy` – cannot be deleted or renamed;
  their links and settings can be changed.
- `version`: version counters of the two halves. Each settings change raises the matching counter
  in `GPT.INI` and in `versionNumber` (computer in the low 16 bits, user in the high 16 bits) – that is
  how Windows clients notice changes.
- `links[].order`: link order on that container, `1` = highest precedence (Windows' "Verknüpfungsreihenfolge").
- `sysvol_ok`: the policy folder exists in SYSVOL and `GPT.INI` carries the same version as the directory.

| Route | Body | Answer |
|---|---|---|
| `GET /api/gpos` | – | `200 [gpo…]` sorted by name |
| `GET /api/gpos/{id}` | – | `200` gpo + `settings` + `other_settings` |
| `POST /api/gpos` | `{"name"}` | `201` gpo (empty, not linked) |
| `PUT /api/gpos/{id}` | any of `{"name", "status"}` | `200` gpo |
| `DELETE /api/gpos/{id}` | – | `204` – also removes all links and the SYSVOL folder |
| `GET /api/gpos/catalog` | – | `200` the curated settings (below) for building the form |
| `PUT /api/gpos/{id}/settings` | `{"settings": {…}}` | `200` gpo with `settings` – keys missing in the body stay unchanged, `null` = not configured |
| `POST /api/gpos/{id}/links` | `{"target_id", "enabled": true, "enforced": false}` | `201` gpo. New links get the lowest precedence (highest order) |
| `PUT /api/gpos/{id}/links/{target_id}` | any of `{"enabled", "enforced", "order"}` | `200` gpo. `order` moves the link on that container (1 … number of links there) |
| `DELETE /api/gpos/{id}/links/{target_id}` | – | `204` |
| `GET /api/ous/{id}/gpo-inheritance` | – | `200` see below |

`name`: 1–200 chars, unique. Link targets: the domain root or an OU (not containers like `Users`).

### Curated settings

`GET /api/gpos/catalog` →

```json
[
  { "key": "screen_lock_minutes", "scope": "user", "group": "Desktop",
    "label": "Bildschirmsperre nach Inaktivität", "type": "int", "min": 1, "max": 600, "unit": "Minuten",
    "help": "Startet nach der Zeit den Bildschirmschoner mit Kennwortschutz." }
]
```

`type`: `bool`, `int` (`min`, `max`, `unit`), `enum` (`options: [{"value", "label"}]`), `string` (`max`,
optional `pattern`), `text` (multi-line, `max`), `scripts` (list of `{"path", "parameters"}`). `GET /api/gpos/{id}`
answers `settings` with every catalog key, `null` when not configured.

| key | scope | type | written as |
|---|---|---|---|
| `screen_lock_minutes` | user | int 1–600 | `HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop`: `ScreenSaveActive=1`, `ScreenSaverIsSecure=1`, `ScreenSaveTimeOut=<sec>`, `SCRNSAVE.EXE=scrnsave.scr` (REG_SZ) |
| `wallpaper_path` | user | string (UNC or local path, max 260) | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`: `Wallpaper` (REG_SZ) |
| `wallpaper_style` | user | enum `fill`, `fit`, `stretch`, `center`, `tile`, `span` | same key: `WallpaperStyle` (REG_SZ `4`, `3`, `2`, `0`, `1`, `5` as in the "Desktop Wallpaper" template; only with `wallpaper_path`, default `fill`) |
| `deny_control_panel` | user | bool | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer`: `NoControlPanel=1` (DWORD) |
| `deny_cmd` | user | bool | `HKCU\Software\Policies\Microsoft\Windows\System`: `DisableCMD=2` (scripts keep working) |
| `deny_registry_tools` | user | bool | `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System`: `DisableRegistryTools=1` |
| `logon_scripts` | user | scripts (max 20) | `User\Scripts\scripts.ini` `[Logon]` (UTF-16 LE with BOM) |
| `logoff_scripts` | user | scripts (max 20) | same file, `[Logoff]` |
| `removable_storage_deny` | computer | bool | `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices`: `Deny_All=1` |
| `windows_update_mode` | computer | enum `off`, `notify`, `download`, `auto` | `HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU`: `NoAutoUpdate=1` (off) or `NoAutoUpdate=0` + `AUOptions=2/3/4` |
| `windows_update_day` | computer | enum `0` (täglich) … `7` (Samstag) | same key: `ScheduledInstallDay` (only with `auto`) |
| `windows_update_hour` | computer | int 0–23 | same key: `ScheduledInstallTime` (only with `auto`) |
| `hide_last_username` | computer | bool | `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System`: `DontDisplayLastUserName=1` |
| `logon_banner_title` | computer | string (max 200) | same key: `LegalNoticeCaption` (REG_SZ) |
| `logon_banner_text` | computer | text (max 2000) | same key: `LegalNoticeText` (REG_SZ) |
| `startup_scripts` | computer | scripts (max 20) | `Machine\Scripts\scripts.ini` `[Startup]` |

Script `path`: UNC path (`\\ad.example.com\NETLOGON\logon.bat`) or a file name in NETLOGON (then
written as the UNC path), `parameters` 0–260 chars.

How settings are stored: the registry values in `Machine\Registry.pol` / `User\Registry.pol` (PReg format,
UTF-16 LE). Entries PK95 AD does not manage (set with the Windows GPMC, for example) are kept unchanged and
counted in `other_settings`. After a change: counter of the changed half + 1 in `GPT.INI` and `versionNumber`,
and the client-side extension GUID pairs in `gPCMachineExtensionNames`/`gPCUserExtensionNames` are set
(Registry: `{35378EAC-683F-11D2-A89A-00C04FBBCFA2}` with tool `{D02B1F72-…}` computer / `{D02B1F73-…}` user;
Scripts: `{42B5FAAE-6536-11D2-AE5A-0000F87571E3}` with tool `{40B6664F-…}` computer / `{40B66650-…}` user),
or removed when the half has no such settings left. Other extensions stay.

`other_settings`: `{"computer": 2, "user": 0, "extensions": ["Sicherheit", "Software-Installation"]}` – entries
and client-side extensions that only the Windows tools can edit.

### Inheritance

`GET /api/ous/{id}/gpo-inheritance` →

```json
{
  "block_inheritance": false,
  "items": [
    { "precedence": 1, "gpo_id": "…", "name": "Bildschirmsperre", "from_id": "…", "from_name": "Vertrieb",
      "enforced": false, "enabled": true }
  ]
}
```

Order like the GPMC tab "Gruppenrichtlinienvererbung": enforced links first (domain before OUs), then the
other links from the nearest container up to the domain, within a container by link order. Disabled links
and links of disabled GPOs are left out. Blocked inheritance drops the non-enforced links of the parents.

## NETLOGON scripts

Text files in the NETLOGON share (`\\<realm>\NETLOGON`) for `script_path` and GPO scripts.

| Route | Body | Answer |
|---|---|---|
| `GET /api/scripts` | – | `200 [{"name": "logon.bat", "size": 120, "changed_at": …}]` |
| `GET /api/scripts/{name}` | – | `200 {"name", "content", "size", "changed_at"}` |
| `PUT /api/scripts/{name}` | `{"content"}` | `200` (creates or replaces) |
| `DELETE /api/scripts/{name}` | – | `204` |

`name`: 1–64 chars `A-Za-z0-9._-`, extension `.bat`, `.cmd`, `.ps1`, `.vbs` or `.kix`; `content` max 256 KiB.
Files are written with CRLF line ends as UTF-8 (`.ps1` with BOM, `.bat`/`.cmd` without) and get the
SYSVOL NT ACL (Domain Users read, Domain Admins full).
