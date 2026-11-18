"""Route table (docs/api.md)."""

from __future__ import annotations

from . import VERSION, accounts, directory, dnszone, gpo, gpp, gpsettings, idmap, sysvol
from .app import App, manifest
from .errors import invalid
from .httpapi import Response, Router

ID = "{id:[0-9a-fA-F-]{36}}"


def build(app: App) -> Router:
    r = Router()

    def ready(fn):
        """Handler that needs a provisioned domain and gets a directory session."""
        def handler(req):
            app.require_ready()
            with app.directory.session() as s:
                return fn(req, s)
        return handler

    def body_bool(req, name: str, default: bool = False) -> bool:
        v = req.json().get(name, default)
        if not isinstance(v, bool):
            raise invalid({name: "Bitte true oder false angeben."})
        return v

    # Core protocol
    r.add("GET", "/core/health", lambda req: {"ok": True, "version": VERSION, "state": app.state()}, auth=False)
    r.add("GET", "/core/manifest", lambda req: manifest())

    def backup_prepare(req):
        app.backup_prepare()
        return Response(204)
    r.add("POST", "/core/backup/prepare", backup_prepare)

    # Setup and status
    r.add("GET", "/api/setup", lambda req: app.setup.info())

    def setup_start(req):
        app.setup.start(req.json())
        return Response(202, {"state": "provisioning"})
    r.add("POST", "/api/setup", setup_start)
    r.add("GET", "/api/status", lambda req: app.status())

    # Domain
    def domain_info(s):
        try:
            ids = idmap.info(app.cfg, s)
        except Exception as exc:  # noqa: BLE001 - informational, must not break the domain page
            ids = {"xid_range": [0, 0], "rfc2307_range": [idmap.RFC2307_LOW, idmap.RFC2307_HIGH], "next_xid": 0,
                   "allocated": 0, "ok": False, "message": f"idmap.ldb nicht lesbar: {exc}"}
        return {**directory.domain_info(s), "ntp": app.ntp_info(), "idmap": ids,
                "resolver": dict(app.resolver_status)}
    r.add("GET", "/api/domain", ready(lambda req, s: domain_info(s)))

    def domain_settings(req):
        app.update_forwarder(req.json())
        with app.directory.session() as s:
            return domain_info(s)
    r.add("PUT", "/api/domain/settings", domain_settings)
    r.add("GET", "/api/domain/password-policy", ready(lambda req, s: directory.password_policy(s)))
    r.add("PUT", "/api/domain/password-policy",
          ready(lambda req, s: directory.set_password_policy(s, req.json())))

    def dbcheck_start(req):
        app.require_ready()
        app.dbcheck.start(body_bool(req, "fix"))
        return Response(202, {"running": True})
    r.add("GET", "/api/domain/dbcheck", lambda req: (app.require_ready(), app.dbcheck.info())[1])
    r.add("POST", "/api/domain/dbcheck", dbcheck_start)

    # OUs
    r.add("GET", "/api/ous", ready(lambda req, s: directory.ou_tree(s)))
    r.add("POST", "/api/ous", ready(lambda req, s: Response(201, directory.ou_create(s, req.json()))))
    r.add("PUT", f"/api/ous/{ID}", ready(lambda req, s: directory.ou_update(s, req.params["id"], req.json())))

    def ou_delete(req, s):
        directory.ou_delete(s, req.params["id"], req.flag("recursive"))
        return Response(204)
    r.add("DELETE", f"/api/ous/{ID}", ready(ou_delete))
    r.add("GET", f"/api/ous/{ID}/gpo-inheritance", ready(lambda req, s: gpo.inheritance(s, req.params["id"])))
    r.add("POST", "/api/move", ready(lambda req, s: directory.move(s, req.json())))

    # Users
    r.add("GET", "/api/users", ready(lambda req, s: accounts.users_list(s, req)))
    r.add("POST", "/api/users", ready(lambda req, s: Response(201, accounts.user_create(s, req.json()))))
    r.add("GET", f"/api/users/{ID}", ready(lambda req, s: accounts.user_get(s, req.params["id"])))
    r.add("PUT", f"/api/users/{ID}", ready(lambda req, s: accounts.user_update(s, req.params["id"], req.json())))

    def user_delete(req, s):
        accounts.user_delete(s, req.params["id"])
        return Response(204)
    r.add("DELETE", f"/api/users/{ID}", ready(user_delete))

    def user_password(req, s):
        accounts.user_password(s, req.params["id"], req.json())
        return Response(204)
    r.add("POST", f"/api/users/{ID}/password", ready(user_password))

    def user_unlock(req, s):
        accounts.user_unlock(s, req.params["id"])
        return Response(204)
    r.add("POST", f"/api/users/{ID}/unlock", ready(user_unlock))
    r.add("PUT", f"/api/users/{ID}/groups",
          ready(lambda req, s: accounts.user_set_groups(s, req.params["id"], req.json())))

    # Groups
    r.add("GET", "/api/groups", ready(lambda req, s: accounts.groups_list(s, req)))
    r.add("POST", "/api/groups", ready(lambda req, s: Response(201, accounts.group_create(s, req.json()))))
    r.add("GET", f"/api/groups/{ID}", ready(lambda req, s: accounts.group_get(s, req.params["id"])))
    r.add("PUT", f"/api/groups/{ID}", ready(lambda req, s: accounts.group_update(s, req.params["id"], req.json())))
    r.add("PUT", f"/api/groups/{ID}/members",
          ready(lambda req, s: accounts.group_set_members(s, req.params["id"], req.json())))

    def group_delete(req, s):
        accounts.group_delete(s, req.params["id"])
        return Response(204)
    r.add("DELETE", f"/api/groups/{ID}", ready(group_delete))

    # Computers
    r.add("GET", "/api/computers", ready(lambda req, s: accounts.computers_list(s, req)))
    r.add("GET", f"/api/computers/{ID}", ready(lambda req, s: accounts.computer_get(s, req.params["id"])))
    r.add("PUT", f"/api/computers/{ID}",
          ready(lambda req, s: accounts.computer_update(s, req.params["id"], req.json())))

    def computer_delete(req, s):
        accounts.computer_delete(s, req.params["id"])
        return Response(204)
    r.add("DELETE", f"/api/computers/{ID}", ready(computer_delete))

    # DNS
    zone = "{zone:[A-Za-z0-9._-]+}"
    rec = "{rid:[0-9a-f]{16}}"
    r.add("GET", "/api/dns/zones", ready(lambda req, s: dnszone.zones(s)))
    r.add("GET", f"/api/dns/zones/{zone}/records",
          ready(lambda req, s: dnszone.records(s, req.params["zone"], req)))
    r.add("POST", f"/api/dns/zones/{zone}/records",
          ready(lambda req, s: Response(201, dnszone.create(s, req.params["zone"], req.json()))))
    r.add("PUT", f"/api/dns/zones/{zone}/records/{rec}",
          ready(lambda req, s: dnszone.update(s, req.params["zone"], req.params["rid"], req.json())))

    def dns_delete(req, s):
        dnszone.delete(s, req.params["zone"], req.params["rid"])
        return Response(204)
    r.add("DELETE", f"/api/dns/zones/{zone}/records/{rec}", ready(dns_delete))

    # Group Policy
    r.add("GET", "/api/gpos", ready(lambda req, s: gpo.gpo_list(s)))
    r.add("GET", "/api/gpos/catalog", lambda req: gpsettings.CATALOG)
    r.add("GET", f"/api/gpos/{ID}", ready(lambda req, s: gpo.gpo_get(s, req.params["id"])))

    def gpo_create(req):
        app.require_ready()
        with app.directory.session() as s:
            gid = gpo.gpo_create(s, req.json())
        sysvol.reset_acls(app.cfg)  # outside the transaction: samba-tool reads the new GPO's ACL
        with app.directory.session() as s:
            return Response(201, gpo.gpo_get(s, gid))
    r.add("POST", "/api/gpos", gpo_create)

    def gpo_update(req, s):
        gpo.gpo_update(s, req.params["id"], req.json())
        return gpo.gpo_get(s, req.params["id"])
    r.add("PUT", f"/api/gpos/{ID}", ready(gpo_update))

    def gpo_delete(req, s):
        gpo.gpo_delete(s, req.params["id"])
        return Response(204)
    r.add("DELETE", f"/api/gpos/{ID}", ready(gpo_delete))

    def gpo_settings(req):
        app.require_ready()
        with app.directory.session() as s:
            changed = gpo.gpo_set_settings(s, req.params["id"], req.json())
        if changed:
            sysvol.reset_acls(app.cfg)
        with app.directory.session() as s:
            return gpo.gpo_get(s, req.params["id"])
    r.add("PUT", f"/api/gpos/{ID}/settings", gpo_settings)

    r.add("GET", f"/api/gpos/{ID}/drives", ready(lambda req, s: gpo.drives_get(s, req.params["id"])))

    def gpo_drives(req):
        app.require_ready()
        with app.directory.session() as s:
            changed = gpo.drives_put(s, req.params["id"], req.json())
        if changed:
            sysvol.reset_acls(app.cfg)  # new Preferences folders get the GPO's NT ACL
        with app.directory.session() as s:
            out = gpo.drives_get(s, req.params["id"])
            out["version"] = gpo.gpo_get(s, req.params["id"])["version"]
            return out
    r.add("PUT", f"/api/gpos/{ID}/drives", gpo_drives)

    # Other Group Policy Preferences lists (1.3.0): same shape as /drives.
    for kind in gpp.KINDS.values():
        def prefs_get(req, s, kind=kind):
            return gpo.prefs_get(s, req.params["id"], kind)

        def prefs_put(req, kind=kind):
            app.require_ready()
            with app.directory.session() as s:
                changed = gpo.prefs_put(s, req.params["id"], kind, req.json())
            if changed:
                sysvol.reset_acls(app.cfg)
            with app.directory.session() as s:
                out = gpo.prefs_get(s, req.params["id"], kind)
                out["version"] = gpo.gpo_get(s, req.params["id"])["version"]
                return out
        r.add("GET", f"/api/gpos/{ID}/{kind.route}", ready(prefs_get))
        r.add("PUT", f"/api/gpos/{ID}/{kind.route}", prefs_put)

    def link_add(req, s):
        gpo.link_add(s, req.params["id"], req.json())
        return Response(201, gpo.gpo_get(s, req.params["id"]))
    r.add("POST", f"/api/gpos/{ID}/links", ready(link_add))

    def link_update(req, s):
        gpo.link_update(s, req.params["id"], req.params["target"], req.json())
        return gpo.gpo_get(s, req.params["id"])
    r.add("PUT", f"/api/gpos/{ID}/links/{{target:[0-9a-fA-F-]{{36}}}}", ready(link_update))

    def link_delete(req, s):
        gpo.link_delete(s, req.params["id"], req.params["target"])
        return Response(204)
    r.add("DELETE", f"/api/gpos/{ID}/links/{{target:[0-9a-fA-F-]{{36}}}}", ready(link_delete))

    # NETLOGON scripts
    def realm():
        app.require_ready()
        return app.settings["realm"]

    name = "{name:[A-Za-z0-9._-]+}"
    r.add("GET", "/api/scripts", lambda req: sysvol.scripts_list(app.cfg, realm()))
    r.add("GET", f"/api/scripts/{name}", lambda req: sysvol.script_get(app.cfg, realm(), req.params["name"]))
    r.add("PUT", f"/api/scripts/{name}",
          lambda req: sysvol.script_put(app.cfg, realm(), req.params["name"], req.json()))

    def script_delete(req):
        sysvol.script_delete(app.cfg, realm(), req.params["name"])
        return Response(204)
    r.add("DELETE", f"/api/scripts/{name}", script_delete)
    return r
