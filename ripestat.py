#!/usr/bin/env python3

import argparse
import progressbar
import requests
import os
import sys

sourceapp = "AS50559-DIVD_NL"

def rest_get(call,resource,retries=3):
	url = "https://stat.ripe.net/data/{}/data.json?resource={}&sourceapp={}".format(call,resource,sourceapp)
	try:
		response = requests.get(url, timeout = 1)
	except KeyboardInterrupt:
		sys.exit()
	except:
		if retries > 0:
			return rest_get(call,resource,retries-1)
		else:
			return "Timeout"
	reply = response.json()
	return reply['data']

def get_info(line) :
		# Get abuse info
		# https://stat.ripe.net/data/abuse-contact-finder/data.<format>?<parameters>

		abuse_reply = rest_get("abuse-contact-finder",line)
		contacts = abuse_reply['anti_abuse_contacts']['abuse_c']
		if len(contacts) > 0 :
			abuse_email = contacts[0]['email']
		else:
			abuse_email = "Not found"

		# Get ASN
		# https://stat.ripe.net/data/network-info/data.json?resource=194.5.73.5

		asn_reply = rest_get("network-info",line)
		asn = asn_reply['asns'][0]
		prefix = asn_reply['prefix']

		# Get ASN info
		if asn in asns:
			asn_data = asns[asn]
		else:
			asn_data = rest_get("as-overview",asn)
			asns[asn] = asn_data

		holder = asn_data['holder']

		# Get geolocation
		if prefix in locations:
			location_data = locations[prefix]
		else:
			location_data = rest_get("maxmind-geo-lite",prefix)

		city=location_data['located_resources'][0]['locations'][0]['city']
		country=location_data['located_resources'][0]['locations'][0]['country']
		print('"{}","{}","{}","{}","{}","{}","{}"'.format(line,abuse_email,prefix,asn,holder,country,city))
		if args.output :
			outfile.write('"{}","{}","{}","{}","{}","{}","{}"\n'.format(line,abuse_email,prefix,asn,holder,country,city))
			outfile.flush()

parser = argparse.ArgumentParser(description='Get abuse and location information for IPs', allow_abbrev=False)
parser.add_argument('input', type=str, metavar="INPUT.txt", nargs="*", default="/dev/stdin", help="Either a list files with one IP address per line or a IP address [default: stdin]")
parser.add_argument('--output', "-o", type=str, metavar="OUTPUT.csv", help="output csv file")
args = parser.parse_args()

if isinstance(args.input,str):
	files = [args.input]
else :
	files = args.input
asns = {}
locations = {}

if args.output :
	outfile = open(args.output,"w")

if args.output :
	outfile.write('ip,abuse,prefix,asn,holder,country,city\n')
print('ip,abuse,prefix,asn,holder,country,city')
for f in files:
	if os.path.isfile(f):
		file = open(f,"r")
		for line in file.readlines():
			line = line.strip()
			try:
				get_info(line)
			except:
				print("Error with '{}'".format(line), file=sys.stderr)
	else:
		try:
			get_info(f)
		except:
			print("Error with '{}'".format(line), file=sys.stderr)


