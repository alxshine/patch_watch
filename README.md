# CVE dashboard

Uses data from EPSS and NIST's database to create a little dashboard.

Features:
- [x] Get all CVEs for the last 30 days.
- [x] Find overlap between NIST and EPSS data and enrich CVEs
- [x] Allow browsing enriched CVEs and link to MITRE database
- [x] Plot number of new CVEs per day
- [x] Plot min/mean/median/max impact score over days
- [x] Allow specifying desired output via command line parameters
- [x] Update cached data if from yesterday or older, allow force updating
- [x] Add pagination (depending on terminal size?)
- [x] Add setup script
- [ ] Create PyPI package?