# AbuseIPDB Bulk IP Reputation Check

## Overview:
Python3 script for checking the reputation of IPs in bulk.

## Description:
This python3 script checks the *reputation of IPs in bulk* using a combination of multiple API keys without the hassle to do this manually one by one. All that is needed is a set of API keys (may be several free keys) to get the results of multiple IPs in bulk in a single go. The script will automatically manage the use of multiple provided keys if the API call limit of some keys is exceeded.

## Pre-requisites

### Packages

Installation of the following utilities is a pre-requisite before running the script on a host:
- Python 3

### Dependencies

The script has the following python library dependencies:
- import requests
- import json
- import csv
- import argparse

```sh
pip install requests argparse
```

### Others

The script has the following miscellaneous requirements other than packages and dependencies:
- A set of *AbuseIPDB API keys* (can be free keys with limited calls) that can be used to fetch reputation results.

## Usage

Type the following command on command line or terminal in order to run the script, being in the same directory as the script.
```sh
python abuseipdb_api.py [-h] [--api_file api_keys.txt] [--ip_file ip_list.txt] [--output repute_results.csv] [--days 90]
```
### Flags
- ***-k*** OR ***--api_file*** *(Optional)*: for specifying input filename with .txt extension to fetch AbuseIPDB API keys from.
- ***-i*** OR ***--ip_file*** *(Optional)*: for specifying input filename with .txt extension to fetch list of IPs.
- ***-o*** OR ***--output*** *(Optional)*: for specifying output filename with .csv extension to output results.
- ***-d*** OR ***--days*** *(Optional)*: for specifying the number of days to look back for reputation check.

## Running Time
The time taken by the script to fetch and save results for bulk IP reputation check can take up to several minutes but can vary depending upon the number of IPs, e.g. around 1 minute (60 seconds) for 60 IPs.

## Tweakable Parameters
Following paramters can be tweaked to change the course, scenario or requirements of the script, by changing the value of certain variables in the main function of this script:

  **Variable | Description**
- *ip_list*							| Default IP list for checking IP reputation if these are not specified in the arguments.
- *api_keys*						| Default API keys that will be used to fetch results if no API keys file is specified in the arguments.
- *days*							| Default number of days to look back the reputation if days are not explicit provided in the arguments.
- *csv_filename*					| Default csv output filename if no output filename is specified in the arguments.


## Output
The script will save the result output in a csv file with the following columns:

- IP Address
- Is Public?
- IP Version
- Is Whitelisted?
- Abuse Confidence Score
- Country Code
- Usage Type
- ISP
- Domain
- Hostnames
- Country Name
- Total Reports
- Number of Distincts Users
- Last Reported At
- Reports
