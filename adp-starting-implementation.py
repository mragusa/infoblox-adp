#!/usr/bin/python3

import sys
import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Starting Configuration",
    description="Enables basic ADP steps based on current Infoblox runbook",
    epilog="For more information, please engage your Infoblox Professional Services Engineer",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
parser.add_argument("-n", "--name", default="Internal-Test", help="Name for profile creation")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)

# retreive existing grid members
grid_members_dns = []
grid_members = conn.get_object("member", return_fields=["host_name", "active_position", "master_candidate", "service_status"])
# print member object
if args.debug:
	print(grid_members)
for gm in grid_members:
	if args.debug:
		print(gm)
	for service in gm["service_status"]:
		if args.debug:
			print(service)
		if service["service"] == "DNS" and service["status"] == "WORKING":
			print("The following members have the DNS service enabled")
			print("Host: {} {}".format(gm["host_name"],service))
			grid_members_dns.append(gm["host_name"])

print("Grid members with DNS service")
print(grid_members_dns)
# Determine existing ruleset
ruleset = conn.get_object("grid:threatprotection", return_fields=["current_ruleset"])
if ruleset:
	# create adp profile
	new_adp_profile = conn.create_object("threatprotection:profile", {"name": args.name, "members": grid_members_dns, "use_current_ruleset": True, "current_ruleset": ruleset[0]["current_ruleset"]})
	if new_adp_profile:
		print("ADP profile {} created".format(args.name))
	else:
		print("ADP profile creation failed")
		sys.exit()
else:
	print("ADP ruleset not found. please enable rule downloading or install manually")
	sys.exit()

# Retreieve current rules assigned to profile
profile_rules = conn.get_object("threatprotection:profile:rule", return_fields=["profile", "rule", "disable", "config", "sid", "use_config", "use_disable"])
if profile_rules:
	for pr in profile_rules:
		print(pr)
else:
	print("Profile rules not found")
