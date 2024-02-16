#!/usr/bin/python3
# TODO Fix code duplication

import urllib3

urllib3.disable_warnings()

import re
from infoblox_client import connector
from infoblox_client import objects

import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Script Framework",
    description="View Current ADP DNS Tunneling Rules",
    epilog="Provides basic visability in ADP Anti-tunneling Rules for Profiles and Grid",
)
parser.add_argument("gmhostname", help="hostname of grid master")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="enable debugging")
parser.add_argument(
    "-g", "--grid", action="store_true", help="show grid adp anti tunneling rules"
)
parser.add_argument(
    "-c", "--profile", action="store_true", help="show profile adp anti tunneling rules"
)
# TODO Add functionality to enable or disable tunnel rules
parser.add_argument("-e", "--enable", action="store_true")
parser.add_argument("-t", "--disable", action="store_true")
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
    print("\033[94mGrid Name\033[00m: {}".format(n["grid_name"]))
    print("\033[94mGrid Ruleset\033[00m: {}".format(n["current_ruleset"]))
    if "scheduled_download" in n:
        print(
            "\033[94mGrid Scheduled Download\033[00m: {}".format(
                n["scheduled_download"]
            )
        )
grid_tp_ruleset = conn.get_object(
    "threatprotection:ruleset",
    return_fields=["used_by", "version", "add_type", "comment"],
)
for rs in grid_tp_ruleset:
    print("\033[94mAdd Type\033[00m: {}".format(rs["add_type"]))

if args.grid:
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
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )
                elif mtpr["config"]["log_severity"] == "MAJOR":
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )
                else:
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )
            else:
                if mtpr["config"]["log_severity"] == "INFORMATIONAL":
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: {}".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )
                elif mtpr["config"]["log_severity"] == "MAJOR":
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: {}".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )
                else:
                    print(
                        "\033[94mMember\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} \033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: {}".format(
                            mtpr["member"],
                            mtpr["rule"],
                            mtpr["config"]["action"],
                            mtpr["config"]["log_severity"],
                            mtpr["disable"],
                        )
                    )

if args.profile:
    adp_profile_config = conn.get_object(
        "threatprotection:profile", return_fields=["name", "members", "current_ruleset"]
    )
    if adp_profile_config:
        if args.debug:
            print(adp_profile_config)
        for profile_config in adp_profile_config:
            print("\033[94mProfile Name\033[00m: {}".format(profile_config["name"]))
            print(
                "\033[94mAssigned Members\033[00m: {}".format(profile_config["members"])
            )
            print(
                "\033[94mAssigned Ruleset\033[00m: {}".format(
                    profile_config["current_ruleset"]
                )
            )
    else:
        print("No ADP Profiles found")
    adp_profile_rules = conn.get_object(
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
    if adp_profile_rules:
        for ptpr in adp_profile_rules:
            if args.debug:
                print(adp_profile_rules)
            # display only antitunneling or tunneling rules
            tunnel = re.search("[tT]unnel", ptpr["rule"])
            if tunnel:
                if ptpr["disable"] is True:
                    if ptpr["config"]["log_severity"] == "INFORMATIONAL":
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
                    elif ptpr["config"]["log_severity"] == "MAJOR":
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
                    else:
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: \033[91m{}\033[00m".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
                else:
                    if ptpr["config"]["log_severity"] == "INFORMATIONAL":
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[93m{}\033[00m, \033[94mDisabled\033[00m: {}".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
                    elif ptpr["config"]["log_severity"] == "MAJOR":
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} ,\033[94mSeverity\033[00m: \033[91m{}\033[00m, \033[94mDisabled\033[00m: {}".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
                    else:
                        print(
                            "\033[94mProfile\033[00m: \033[96m{}\033[00m, \033[94mRule\033[00m: {}, \033[94mConfig\033[00m: {} \033[94mSeverity\033[00m: {}, \033[94mDisabled\033[00m: {}".format(
                                ptpr["profile"],
                                ptpr["rule"],
                                ptpr["config"]["action"],
                                ptpr["config"]["log_severity"],
                                ptpr["disable"],
                            )
                        )
