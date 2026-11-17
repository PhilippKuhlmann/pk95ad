# PK95 AD

Active-Directory-Domänencontroller (Samba 4.22) als PK95-App. Benutzer, Gruppen, Organisationseinheiten,
Computer, DNS der AD-Zone und Gruppenrichtlinien werden in PK95 Core verwaltet. PK95 AD selbst bringt nur die
JSON-API mit (Core-Modus des App-Protokolls v1).

- API: [docs/api.md](docs/api.md)
- Aufbau, Netz, LXC-Annahmen, Backup: [docs/design.md](docs/design.md)
- Katalog-Eintrag für PK95 Core: [catalog/ad.yaml](catalog/ad.yaml)
- Image: `ghcr.io/philippkuhlmann/pk95-ad` (amd64, arm64)

## Betrieb unter PK95 Core

Core startet den Container mit `network_mode: host` im LXC. Beim ersten Start ist keine Domäne eingerichtet;
der Assistent auf der Core-Seite „Domäne“ fragt Realm, NetBIOS-Name, Name und IP des DCs, DNS-Weiterleitung und
das Administrator-Kennwort ab und provisioniert die Domäne (`POST /api/setup`).

Danach braucht PK95 DNS eine bedingte Weiterleitung `<realm>` → `127.0.0.1:5300`, damit die Clients (die
weiter PK95 DNS nutzen) die AD-Einträge finden. Windows-Clients treten der Domäne dann normal bei
(Einstellungen → Konto → Auf Arbeit oder Schule zugreifen bzw. `Add-Computer`).

Belegte Ports im LXC: 88, 123/udp, 135, 137–139, 389, 445, 464, 636, 3268, 3269, 5300 (Samba-DNS),
49152–49200 (RPC) und 8389 (API).

## Entwicklung

Die App ist reines Python 3 (nur Standardbibliothek) plus die Samba-Bindings aus Debian (`python3-samba`).

```bash
python3 -m unittest discover -s tests -t .
```

Die Unit-Tests laufen ohne Samba (Registry.pol, Einstellungen, gPLink, Validierung, HTTP-Schicht, Events).
Der Ende-zu-Ende-Test `tests/integration/run.py` läuft in GitHub Actions gegen das gebaute Image: Er
provisioniert eine Domäne, prüft alle API-Bereiche und die NT-ACLs in `user.NTACL`.

Eigenständig (ohne Core) zum Ausprobieren: `docker compose up -d` mit gesetztem `PK95AD_TOKEN`.
