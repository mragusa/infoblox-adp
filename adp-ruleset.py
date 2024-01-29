#!/usr/bin/python3

import urllib3
urllib3.disable_warnings()
import re
from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Script Framework",
    description="Provides basic python script framework for interacting with ADP",
    epilog="Edit as needed",
)
parser.add_argument("gmhostname")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# get all network_views
grid_tp = conn.get_object(
    "grid:threatprotection",
    return_fields=["current_ruleset", "grid_name", "scheduled_download"],
)
# print(grid_tp)
for n in grid_tp:
    print("Grid Name: {}".format(n["grid_name"]))
    print("Grid Ruleset: {}".format(n["current_ruleset"]))
    # if "scheduled_download" in n:
    # 	print("Grid Scheduled Download: {}".format(n["scheduled_download"]))
    # else:
    # 	print("\033[93mNIOS Threat Protection Ruleset Applied Manually \033[00m")
grid_tp_ruleset = conn.get_object(
    "threatprotection:ruleset",
    return_fields=["used_by", "version", "add_type", "comment"],
)
# print(grid_tp_ruleset[0]["add_type"])
for rs in grid_tp_ruleset:
    print("Add Type: {}".format(rs["add_type"]))

# grid_tp_rulecategory = conn.get_object("threatprotection:rulecategory", return_fields=["name","ruleset"])
# print(grid_tp_rulecategory)
# for r in grid_tp_rulecategory:
# 	print("Ruleset: {} Name: {}".format(r["ruleset"], r["name"]))

grid_tp_rules = conn.get_object(
    "threatprotection:rule",
    return_fields=[
        "member",
        "sid",
        "rule",
        "config",
        "disable",
        "use_config",
        "use_disable",
    ],
)
# print(grid_tp_rules)
for mtpr in grid_tp_rules:
    tunnel = re.search("[tT]unnel", mtpr["rule"])
    if tunnel:
        if mtpr["disable"] is True:
            print( "Member: {}, Rule: {}, Disabled: \033[91m{}\033[00m".format( mtpr["member"], mtpr["rule"], mtpr["disable"]))
        else:
            print( "Member: {}, Rule: {}, Disabled: {}".format( mtpr["member"], mtpr["rule"], mtpr["disable"]))
