#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Framework Profile Interactions",
    description="Create/Remove ADP Profiles - Assign/Remove members to profiles",
    epilog="ADP Profiles are used to create custom rulesets for enterprise clients",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-g", "--get", action="store_true", help="Get Current ADP Profile")
parser.add_argument("-c", "--create", help="Create ADP Profile")
parser.add_argument("-m", "--members", help="Members to assign to ADP Profile")
parser.add_argument("-r", "--remove", help="Remove ADP Profile")
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
    ruleset = conn.get_object(
        "grid:threatprotection",
        return_fields=["current_ruleset", "grid_name", "last_rule_update_version"],
    )
    # print adp profile
    if args.debug:
        print(existing_adp_profiles)
    if existing_adp_profiles:
        for existing_profiles in existing_adp_profiles:
            print("\033[94mProfile:\033[00m {}".format(existing_profiles["name"]))
    else:
        print("No profiles configured")
    # TODO add ability to print members assigned to the profile
    if ruleset:
        for rs in ruleset:
            print("\033[94mGrid Name:\033[00m {}".format(rs["grid_name"]))
            print("\033[94mCurrent Ruleset:\033[00m {}".format(rs["current_ruleset"]))
            print(
                "\033[94mLast Rule Update:\033[00m {}".format(
                    rs["last_rule_update_version"]
                )
            )
    else:
        print("no rulesets configured")
# create adp profiles
if args.create:
    ruleset = conn.get_object(
        "grid:threatprotection", return_fields=["current_ruleset"]
    )
    if args.members:
        new_adp_profile = conn.create_object(
            "threatprotection:profile",
            {
                "name": args.create,
                "members": [args.members],
                "use_current_ruleset": True,
                "current_ruleset": ruleset[0]["current_ruleset"],
            },
        )
    else:
        new_adp_profile = conn.create_object(
            "threatprotection:profile",
            {
                "name": args.create,
                "use_current_ruleset": True,
                "current_ruleset": ruleset[0]["current_ruleset"],
            },
        )
    if new_adp_profile:
        if args.debug:
            print(new_adp_profile)
        print("ADP Profile created: {}".format(new_adp_profile))
    else:
        print("Error creating profile")

# remove adp profiles
if args.remove:
    adp_profile = conn.get_object("threatprotection:profile", {"name": args.remove})
    if adp_profile:
        del_adp_profile = conn.delete_object(adp_profile[0]["_ref"])
        if del_adp_profile:
            print("ADP profile {} removed".format(args.remove))
        else:
            print("ADP profile {} removal failed".format(args.remove))
    else:
        print("ADP Profile not found")
