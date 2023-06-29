# CVE dashboard

Uses data from EPSS and NIST's database to create a little dashboard.

Features:
- [x] Get all CVEs for the last 30 days.
- [x] Find overlap between NIST and EPSS data and enrich CVEs
- [x] Allow browsing enriched CVEs and link to MITRE database
- [x] Plot number of new CVEs per day
- [x] Plot min/mean/median/max impact score over days

It should be a stateful application, because querying the databases can take a while.
Probably TUI, with plotille plots?