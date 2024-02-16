#!/usr/bin/python3
import sys
import re
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
parser.add_argument("-n", "--name", default="Internal-Test", help="ADP Profile Name")
parser.add_argument(
    "-m",
    "--members",
    help="Infoblox Grid Members to ADP profile (multiple members should be added in a quoted comma seperated list)",
)
parser.add_argument(
    "-r", "--recursive", action="store_true", help="Infoblox members are recursive"
)
# TODO currently does not work. Need to determine which record types to disable if needed
parser.add_argument(
    "-a",
    "--authoritative",
    action="store_true",
    help="Infoblox members are authoritative",
)
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
recursive_sids = []
authoritative_sids = []


# function to enable rules
# set use_disable True to avoid interitence
def enable_rule(rule, ref):
    enabled_rule = conn.update_object(ref, {"disable": False, "use_disable": True})
    if enabled_rule:
        print("\033[96m{} Rule Enabled\033[00m".format(rule))
        if args.debug:
            print(enabled_rule)
    else:
        print("\033[93m{} Rule Enablment Failed\033[00m".format(rule))


if args.members:
    grid_members_dns.append(args.members)
else:
    # Find grid members running a working DNS service and add them to the grid_members_dns list
    print("\033[94mAutomatically finding grid members\033[00m")
    print("\033[94mLooking for all grid members actively running DNS\033[00m")
    grid_members = conn.get_object(
        "member",
        return_fields=[
            "host_name",
            "active_position",
            "master_candidate",
            "service_status",
        ],
    )
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
                print(
                    "\033[94mThe following members have the DNS service enabled\033[00m"
                )
                print("\033[94mHost\033[00m: {} {}".format(gm["host_name"], service))
                grid_members_dns.append(gm["host_name"])
print("\033[94mGrid members with DNS service:\033[00m {}".format(grid_members_dns))

# Determine existing ruleset
ruleset = conn.get_object("grid:threatprotection", return_fields=["current_ruleset"])
if ruleset:
    # create adp profile
    new_adp_profile = conn.create_object(
        "threatprotection:profile",
        {
            "name": args.name,
            "members": grid_members_dns,
            "use_current_ruleset": True,
            "current_ruleset": ruleset[0]["current_ruleset"],
        },
    )
    if new_adp_profile:
        print("\033[94mADP Profile Created:\033[00m {}".format(args.name))
    else:
        print("\033[91mADP Profile Creation Failed\033[00m")
        sys.exit()
else:
    print(
        "\033[91mADP ruleset not found. please enable rule downloading or install manually\033[00m"
    )
    sys.exit()

# Find SIDs for specific categories
# Tunneling Category (Recursive DNS)
# Malware Category (Recursive DNS)
# Disable RR Types not defined (Authoritative Only DNS)
grid_rules = conn.get_object(
    "threatprotection:grid:rule", return_fields=["name", "sid", "category"]
)
for rules in grid_rules:
    category = rules["category"].split("/")
    cat_name = category[2].replace("%20", " ")
    plain_cat_name = cat_name.replace("%2F", "/")
    if args.recursive:
        recursive_server_search = re.compile(r"Malware|Tunnel", re.IGNORECASE)
        recursive_server_category = recursive_server_search.findall(plain_cat_name)
        if recursive_server_category:
            recursive_sids.append(rules["sid"])
    if args.authoritative:
        # TODO determine how to disable specific record types (maybe from predefined list)
        authoritative_server_search = re.compile(r"DNS Message Types", re.IGNORECASE)
        authoritative_server_category = authoritative_server_search.findall(
            plain_cat_name
        )
        if authoritative_server_category:
            authoritative_sids.append(rules["sid"])

# Retreieve current rules assigned to profile
profile_rules = conn.get_object(
    "threatprotection:profile:rule",
    return_fields=[
        "profile",
        "rule",
        "disable",
        "config",
        "sid",
        "use_config",
        "use_disable",
    ],
)
if profile_rules:
    for pr in profile_rules:
        if args.debug:
            print(pr)
        # Flood rules
        if pr["sid"] == 130000200:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        if pr["sid"] == 130000400:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        # Early pass UDP response
        if pr["sid"] == 100000100:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        # DDoS Rules
        if pr["sid"] == 200000001:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        if pr["sid"] == 200000002:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        if pr["sid"] == 200000003:
            print(
                "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                    pr["rule"],
                    pr["sid"],
                )
            )
            enable_rule(pr["rule"], pr["_ref"])
        # Enable rules for recursive DNS servers
        # Enable Tunneling Category (Recursive DNS)
        # Enable Malware Category (Recursive DNS)
        if args.recursive:
            if pr["sid"] in recursive_sids:
                print(
                    "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                        pr["rule"],
                        pr["sid"],
                    )
                )
                enable_rule(pr["rule"], pr["_ref"])
        # TODO must be determined by client and tuned
        # Disable RR Types not defined (Authoritative Only DNS)
        if args.authoritative:
            if pr["sid"] in authoratative_sids:
                print(
                    "\033[94mRule\033[00m: {} \033[94mSID\033[00m: {}".format(
                        pr["rule"],
                        pr["sid"],
                    )
                )
                enable_rule(pr["rule"], pr["_ref"])
else:
    print("\033[91mProfile rules not found\033[00m")
