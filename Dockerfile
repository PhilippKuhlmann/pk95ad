# PK95 AD als Container für PK95 Core (ghcr.io/philippkuhlmann/pk95-ad).
# Samba-AD-Domänencontroller (Debian trixie, Samba 4.22) plus die Admin-API (Python, Port 8389).
# Läuft mit network_mode host: Kerberos, LDAP, SMB usw. auf den Standardports des LXC, Samba-DNS auf 5300
# (Port 53 gehört PK95 DNS, das die AD-Zone an 5300 weiterleitet). Siehe docs/design.md.
# Läuft als root im Container (Samba braucht das; im unprivilegierten LXC gibt es keine Datei-Capabilities).

FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
		samba-ad-dc samba-ad-provision samba-dsdb-modules samba-vfs-modules python3-samba \
		winbind smbclient ldb-tools krb5-user \
		chrony tini iproute2 acl attr bind9-host tzdata ca-certificates \
	&& rm -rf /var/lib/apt/lists/* \
	# The image ships no domain: provisioning creates everything in the volumes.
	&& rm -f /etc/samba/smb.conf /etc/krb5.conf \
	&& rm -rf /var/lib/samba/* /var/cache/samba/* \
	# Unprivileged LXC: only the IDs 0-65535 exist. Samba's automatic Unix IDs start at 3000000 by default,
	# and a chown to such an ID makes provisioning panic. Use 20000-59999 instead (docs/design.md → Unix IDs).
	&& sed -i -E -e 's/^lowerBound: [0-9]+$/lowerBound: 20000/' -e 's/^upperBound: [0-9]+$/upperBound: 59999/' \
		/usr/share/samba/setup/idmap_init.ldif \
	&& grep -qx 'lowerBound: 20000' /usr/share/samba/setup/idmap_init.ldif \
	&& grep -qx 'upperBound: 59999' /usr/share/samba/setup/idmap_init.ldif \
	&& mkdir -p /var/lib/pk95ad /etc/chrony /run/chrony

COPY pk95ad /opt/pk95ad/pk95ad

ARG VERSION=1.1.2
ENV PYTHONPATH=/opt/pk95ad \
	PYTHONUNBUFFERED=1 \
	PYTHONDONTWRITEBYTECODE=1 \
	PK95AD_VERSION=${VERSION} \
	PK95AD_LISTEN=0.0.0.0:8389 \
	PK95AD_DATA_DIR=/var/lib/pk95ad \
	PK95AD_DNS_PORT=5300 \
	PK95AD_RPC_PORTS=49152-49200

# Domäne (sam.ldb, SYSVOL), generierte smb.conf und App-Daten überstehen ein neues Image.
VOLUME ["/var/lib/samba", "/etc/samba", "/var/lib/pk95ad"]
EXPOSE 8389 53/udp 88/tcp 88/udp 123/udp 135 137/udp 138/udp 139 389/tcp 389/udp 445 464/tcp 464/udp 636 3268 3269 5300/tcp 5300/udp
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/tini", "--", "python3", "-m", "pk95ad"]
