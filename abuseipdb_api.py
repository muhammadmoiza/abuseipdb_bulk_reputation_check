import requests
import json
import csv
import argparse

def bulk_reputation_check(ip_list, base_url, api_keys, days):

	try:
		reputation_results = []
		api_key_no = 0

		if len(api_keys) < 1:
			print('[!] Please provide at least one API key. Exiting now.')
			return

		for ip in ip_list:
			headers = {'Key': api_keys[api_key_no], 'Accept': 'application/json'}
			params = {'maxAgeInDays': days, 'ipAddress': ip, 'verbose': ''}

			response = requests.get(base_url, headers=headers, params=params)

			while response.status_code == 401 or response.status_code == 429:
				if response.status_code == 401:
						print('[*] API key:', api_keys[api_key_no], 'or key #', api_key_no + 1, 'is invalid.' )
				elif response.status_code == 429:
						print('[*] API key:', api_keys[api_key_no], 'or key #', api_key_no + 1, 'has crossed the number of allowed calls.')

				if api_key_no + 1 >= len(api_keys):
						print('[!] API key tokens were not sufficient. Exiting with limited results.')
						if len(reputation_results) < 1:
							return
						break
				api_key_no = api_key_no + 1
				headers = {'Key': api_keys[api_key_no], 'Accept': 'application/json'}
				response = requests.get(base_url, headers=headers, params=params)

			if response.text and json.loads(response.text)['data']:
				reputation_results.append(json.loads(response.text)['data'])

		return reputation_results
	except Exception as e:
		print('[!] Error in bulk_reputation_check function with reason:', e)

def output_to_csv(res, csv_filename):
		try:
			if not res:
				return
			with open(csv_filename, mode='w', encoding="utf-8") as csv_file:
				csv_writer = csv.writer(csv_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL, lineterminator='\n')
				csv_writer.writerow(['IP Address', 'Is Public?', 'IP Version', 'Is Whitelisted?', 'Abuse Confidence Score', 'Country Code', 'Usage Type', 'ISP', 'Domain', 'Hostnames', 'Country Name', 'Total Reports', 'Number of Distincts Users', 'Last Reported At', 'Reports'])
				for row in res:
					csv_writer.writerow([str(row['ipAddress']), str(row['isPublic']), str(row['ipVersion']), str(row['isWhitelisted']), str(row['abuseConfidenceScore']), str(row['countryCode']), str(row['usageType']), str(row['isp']), str(row['domain']), str(row['hostnames']), str(row['countryName']), str(row['totalReports']), str(row['numDistinctUsers']), str(row['lastReportedAt']), str(row['reports'])])
		except Exception as e:
			print('[!] Error in output_to_csv function with reason:', e)

def read_txt(filename):
	try:
		res = []
		with open(filename, 'r') as txt_file:
			while row := txt_file.readline():
				res.append(row.strip())
		return res
	except Exception as e:
		print('[!] Error in read_txt function with reason:', e)

def main():
	try:
		parser = argparse.ArgumentParser()
		parser.add_argument('-k', '--api_file', help='Filename with .txt extension to fetch AbuseIPDB API keys from')
		parser.add_argument('-i', '--ip_file', help='Filename with .txt extension to fetch list of IPs')
		parser.add_argument('-o', '--output', help='Filename with .csv extension to output results')
		parser.add_argument('-d', '--days', help='Number of days to look back')

		args = parser.parse_args()

		ip_list = ['111.222.11.22']
		base_url = 'https://api.abuseipdb.com/api/v2/check'
		days = 90
		output_filename = 'reputation_ips.csv'
		api_keys = ['api-key-1', 'api-key-2', 'api-key-3', '...']

		if args.api_file:
			api_keys = read_txt(args.api_file)
		if args.ip_file:
			ip_list = read_txt(args.ip_file)
		if args.output:
			output_filename = args.output
		if args.days:
			days = args.days

		print('[i] Program started... This may take some time.')
		reputation_results = bulk_reputation_check(ip_list, base_url, api_keys, days)
		print('[i] Results have been fetched. Now writing in CSV file.')
		output_to_csv(reputation_results, output_filename)
		print('[i] Output has been written to CSV file', output_filename)

	except Exception as e:
		print('[!] Error in main function with reason:', e)

main()
