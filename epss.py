# coding: utf-8
import requests

data = requests.get(
    "https://api.first.org/data/v1/epss?order=!epss_sort").json()['data']

cves = sorted(data, key=lambda d: d['epss'], reverse=True)[:10]
print(cves)