#!/usr/bin/env python3

import urllib3

urllib3.disable_warnings()

import datetime

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Statistics",
    description="Provides ADP Threat Protection Statistics",
    epilog="Retreieve grid statistics for last 30 mins",
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
# get ADP statistics
adp_statistics = conn.get_object("threatprotection:statistics")
# print statistics
if args.debug:
    print(adp_statistics)
sorted_stats = []
for stats in adp_statistics:
    for info in stats["stat_infos"]:
        sorted_stats.append(
            "\033[94mTimestamp\033[00m: {} \033[94mCritical\033[00m: {} \033[94mInformational\033[00m: {} \033[94mMajor\033[00m: {} \033[94mTotal\033[00m: {} \033[94mWarning\033[00m: {}".format(
                datetime.datetime.fromtimestamp(info["timestamp"]).strftime("%c"),
                info["critical"],
                info["informational"],
                info["major"],
                info["total"],
                info["warning"],
            )
        )

# Sort items based on timestamp for clearer output
sorted_stats.sort()
for x in sorted_stats:
    print(x)
