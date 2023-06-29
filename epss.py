# %%
import requests
import datetime
import json

NUM_DAYS = 30
EPSS_PERCENTILE = 0.6

# get cves rated above the 80th percentile in the last 30 days
EPSS_PATH = ".cache/epss.json"
try:
    epss_cves = json.load(open(EPSS_PATH, "r"))
    print("Got EPSS data from cache")  # TODO: check if from today
except FileNotFoundError:
    print("Requesting EPSS data...")
    epss_cves = requests.get(
        "https://api.first.org/data/v1/epss",
        {"order": "!epss", "days": NUM_DAYS, "percentile-gt": EPSS_PERCENTILE},
    ).json()["data"]
    json.dump(epss_cves, open(EPSS_PATH, "w"))

print(
    f"Found {len(epss_cves)} EPSS CVEs rated above the {int(EPSS_PERCENTILE*100)}th percentile in the last {NUM_DAYS} days"
)

NIST_PATH = ".cache/nist.json"

try:
    nist_cves = json.load(open(NIST_PATH, "r"))  # TODO: check if from today
    print("Got NIST data from cache")
except FileNotFoundError:
    print("Requesting NIST data...")
    nist_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/"
    today = datetime.date.today()
    start_date = today - datetime.timedelta(days=30)
    end_date = today

    format_date = lambda date: date.strftime("%Y-%m-%dT%H:%M:%S.%f")
    nist_data = requests.get(
        nist_url,
        params={
            "pubStartDate": format_date(start_date),
            "pubEndDate": format_date(end_date),
        },
    ).json()
    nist_cves = [cve["cve"] for cve in nist_data["vulnerabilities"]]
    json.dump(nist_cves, open(NIST_PATH, "w"))

print(f"Found {len(nist_cves)} NIST CVEs published in the last {NUM_DAYS} days")

# %%

nist_ids = set([cve["id"] for cve in nist_cves])
epss_ids = set([cve["cve"] for cve in epss_cves])
common_ids = nist_ids.intersection(epss_ids)

print(f"Found {len(common_ids)} CVEs in both lists")
print(f"That's {len(common_ids)/len(nist_ids)*100:.2f}% of the NIST list")


def get_impact_score(cve):
    try:
        impact_score = cve["metrics"]["cvssMetricV31"][0]["impactScore"]
    except KeyError:
        impact_score = 0

    return impact_score


rich_cves = []
for cve_id in common_ids:
    nist_data = next(cve for cve in nist_cves if cve["id"] == cve_id)
    date = datetime.datetime.strptime(
        nist_data["published"], "%Y-%m-%dT%H:%M:%S.%f"
    ).date()
    impact_score = get_impact_score(nist_data)

    epss_data = next(cve for cve in epss_cves if cve["cve"] == cve_id)
    epss_score = epss_data["epss"]

    rich_cve = {
        "id": cve_id,
        "date": date,
        "impact_score": impact_score,
        "epss_score": epss_score,
    }
    rich_cves.append(rich_cve)

import pandas as pd

df = pd.DataFrame(
    rich_cves,
)
df.date = pd.to_datetime(df.date)
df.impact_score = pd.to_numeric(df.impact_score)
df.epss_score = pd.to_numeric(df.epss_score)
df.dtypes

df.describe()

# %%

import seaborn as sns
import matplotlib.pyplot as plt

plt.figure()
sns.boxplot(data=df, x="date", y="impact_score")
plt.title("Boxplot over NIST CVE impact scores by date")
