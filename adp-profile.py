#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Framework Profile Interactions",
    description="Create/Remove ADP Profiles - Assign/Remove members to profiles",
    epilog="ADP Profiles are used to create customer rulesets for enterprise clients",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-g", "--get", help="Get Current ADP Profile")
parser.add_argument("-c", "--create", help="Create ADP Profile")
parser.add_argument("-m", "--members", help="Members to assign to ADP Profile")
parser.add_argument("-r", "--remove", help="Remove ADP Profile")
parser.add_argument("-n", "--name", help="Name of ADP Profile to Add/Remove")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# get current profiles
if args.get:
	existing_adp_profiles = conn.get_object("threatprotection:profile")
# print network view
if args.debug:
	print(existing_adp_profiles)
if existing_adp_profiles:
	for existing_profiles in existing_adp_profiles:
		print(existing_profiles["name"])
else:
	print("No profiles configured")

if args.create:
	if args.name:
		if args.members:
			new_adp_profile = conn.create_object("threatprotection:profile", name=args.name, members=[args.members], use_current_ruleset=True)
		else:
			new_adp_profile = conn.create_object("threatprotection:profile", name=args.name, use_current_ruleset=True)
	else:
		print("No name assigned")
