# Security and operational boundaries

Report issues privately to the repository owner after a publication destination
has been selected. Never include VPN client keys, credentials.json, complete
container configurations, panel passwords or private server backups in an issue.

Run privileged tests only on disposable machines. The package controls privileged
network rules through Docker and must be installed by the server owner. It does
not grant a regular SSH user membership in the Docker group or configure sudo.

Checksums verify a selected release's integrity, not the trustworthiness of a
compromised repository. Use a trusted release and compare its digest through a
trusted channel. Do not execute unreviewed shell content piped directly from curl.

This is a DNS access-control tool, not an anonymity system, traffic inspection
proxy, VPN detection prevention system or complete application firewall.
