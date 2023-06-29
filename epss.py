# %%
import requests
import datetime
import json

NUM_DAYS = 30
EPSS_PERCENTILE = 0.6

today = datetime.date.today()
start_date = today - datetime.timedelta(days=NUM_DAYS)
end_date = today


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

    format_date = lambda date: date.strftime("%Y-%m-%dT%H:%M:%S.%f")
    nist_details = requests.get(
        nist_url,
        params={
            "pubStartDate": format_date(start_date),
            "pubEndDate": format_date(end_date),
        },
    ).json()
    nist_cves = [cve["cve"] for cve in nist_details["vulnerabilities"]]
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
    nist_details = next(cve for cve in nist_cves if cve["id"] == cve_id)
    date = datetime.datetime.strptime(
        nist_details["published"], "%Y-%m-%dT%H:%M:%S.%f"
    ).date()
    impact_score = get_impact_score(nist_details)

    epss_details = next(cve for cve in epss_cves if cve["cve"] == cve_id)
    epss_score = epss_details["epss"]

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


# %% Print top 5 CVEs with rich data

from termcolor import colored

NUM_CVES = 5
top_ids = df.sort_values(by="epss_score", ascending=False).head(NUM_CVES).id.to_list()

print(f"Top {NUM_CVES} CVEs:")
from pprint import pprint

for cve_id in top_ids:
    nist_details = next(cve for cve in nist_cves if cve["id"] == cve_id)
    epss_details = next(cve for cve in epss_cves if cve["cve"] == cve_id)

    # construct cve.org url
    cve_url = f"https://www.cve.org/CVERecord?id={nist_details['id']}"

    print(colored(f"{nist_details['id']}", "red", attrs=["bold"]), end="")
    try:
        print(
            colored(f": {nist_details['cisaVulnerabilityName']}", attrs=["bold"]),
            end="",
        )  # TODO: highlight text in red or something
    except KeyError:
        pass
    print()

    print(cve_url)

    # print impact and epss scores
    print(colored("Impact score: ", attrs=["bold"]), end="")
    print(get_impact_score(nist_details), end="\t")
    print(colored("EPSS score: ", attrs=["bold"]), end="")
    print(f"{float(epss_details['epss']):.3f}", end="\t")
    print(colored("EPSS percentile: ", attrs=["bold"]), end="")
    print(f"{float(epss_details['percentile'])*100:.2f}%")

    # print(colored(cve_url, "blue"))

    print(f"{colored('Date', 'blue', attrs=['bold'])}: {df[df.id==cve_id].date.dt.date.values[0]}")
    pprint(nist_details["descriptions"][0]["value"])

    # pprint(cve)
    print()

# %%
# find all mondays in the last 30 days to use as xticks
mondays = pd.date_range(start=start_date, end=today, freq="W-MON")

count_per_day = df.groupby("date").count().id

# plt.plot(count_per_day.index, count_per_day, label="Count per day")
# plt.xlabel("Date (Labels are Mondays)")
# plt.ylabel("Count")
# plt.xticks(mondays, rotation=45)
# # plt.legend()
# plt.title(
#     f"NIST CVEs with EPSS score above {EPSS_PERCENTILE*100:.0f}th percentile per day"
# )
# plt.show()

import plotille

count_chart = plotille.Figure()
count_chart.width = 60
count_chart.height = 15
# chart.set_x_limits(min_=start_date, max_=end_date)
count_chart.set_y_limits(min_=0, max_=max(count_per_day))
count_chart.color_mode = "byte"
counts = count_per_day.values
count_chart.plot(count_per_day.index, count_per_day.values, lc=1, label="Count per day")
print("Number of common CVEs per day:")
print(count_chart.show(legend=True))
print()


severity_chart = plotille.Figure()
severity_chart.width = 60
severity_chart.height = 15

cve_by_day = df.groupby("date")[["impact_score","epss_score"]]
impact_min = cve_by_day.min().impact_score
impact_mean = cve_by_day.mean().impact_score
impact_median = cve_by_day.median().impact_score
impact_max = cve_by_day.max().impact_score

severity_chart.set_y_limits(min_=0, max_=10)
severity_chart.color_mode = "byte"
severity_chart.plot(impact_min.index, impact_min.values, lc=1, label="Min impact score")
severity_chart.plot(impact_mean.index, impact_mean.values, lc=2, label="Mean impact score")
severity_chart.plot(impact_median.index, impact_median.values, lc=3, label="Median impact score")
severity_chart.plot(impact_max.index, impact_max.values, lc=4, label="Max impact score")

print("CVSS severity statistics per day:")
print(severity_chart.show(legend=True))
print()

epss_min = cve_by_day.min().epss_score
epss_mean = cve_by_day.mean().epss_score
epss_median = cve_by_day.median().epss_score
epss_max = cve_by_day.max().epss_score

epss_chart = plotille.Figure()
epss_chart.width = 60
epss_chart.height = 15
epss_chart.set_y_limits(min_=0, max_=1)
epss_chart.color_mode = "byte"

epss_chart.plot(epss_min.index, epss_min.values, lc=1, label="Min EPSS score")
epss_chart.plot(epss_mean.index, epss_mean.values, lc=2, label="Mean EPSS score")
epss_chart.plot(epss_median.index, epss_median.values, lc=3, label="Median EPSS score")
epss_chart.plot(epss_max.index, epss_max.values, lc=4, label="Max EPSS score")

print("EPSS statistics per day:")
print(epss_chart.show(legend=True))