# CVE dashboard

Uses data from EPSS and NIST's database to create a little dashboard.

Features:
- [x] Get all CVEs for the last 30 days.
- [ ] Find overlap between NIST and EPSS data and enrich CVEs
- [ ] Allow browsing enriched CVEs and link to MITRE database
- [ ] Plot number of new CVEs per day
- [ ] Plot min/mean/median/max impact score over days

It should be a stateful application, because querying the databases can take a while.
Probably TUI, with plotille plots?