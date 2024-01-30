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
# print entire grid_tp object if debug
if args.debug:
    print(grid_tp)
for n in grid_tp:
    print("Grid Name: {}".format(n["grid_name"]))
    print("Grid Ruleset: {}".format(n["current_ruleset"]))
    if "scheduled_download" in n:
     	print("Grid Scheduled Download: {}".format(n["scheduled_download"]))
grid_tp_ruleset = conn.get_object(
    "threatprotection:ruleset",
    return_fields=["used_by", "version", "add_type", "comment"],
)
for rs in grid_tp_ruleset:
    print("Add Type: {}".format(rs["add_type"]))

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
if args.debug:
    print(grid_tp_rules)
for mtpr in grid_tp_rules:
    tunnel = re.search("[tT]unnel", mtpr["rule"])
    # display only antitunneling or tunneling rules
    if tunnel:
        # check if rule is disabled or not
        if mtpr["disable"] is True:
            if mtpr["config"]["log_severity"] == "INFORMATIONAL":
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
            elif mtpr["config"]["log_severity"] == "MAJOR":
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
            else:
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
        else:
            if mtpr["config"]["log_severity"] == "INFORMATIONAL":
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: {}".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
            elif mtpr["config"]["log_severity"] == "MAJOR":
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: {}".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
            else:
                print( "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} \033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: {}".format( mtpr["member"], mtpr["rule"], mtpr["config"]["action"],mtpr["config"]["log_severity"], mtpr["disable"]))
