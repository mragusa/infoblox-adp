#!/usr/bin/python3
# TODO add more verbose output
import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="adp-customlist.py",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=" Update ADP Deny Lists for IOS triangulation domains",
    epilog="For more information vist: https://securelist.com/operation-triangulation/109842/"
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)

# Map options to template names
templates = {
    "blacklist-udp": "BLACKLIST UDP FQDN lookup",
    "blacklist-tcp": "BLACKLIST TCP FQDN lookup",
}

triangulation_domains = [
    "addatamarket.net",
    "backuprabbit.com",
    "businessvideonews.com",
    "cloudsponcer.com",
    "datamarketplace.net",
    "mobilegamerstats.com",
    "snoweeanalytics.com",
    "tagclick-cdn.com",
    "topographyupdates.com",
    "unlimitedteacup.com",
    "virtuallaughing.com",
    "web-trackers.com",
    "growthtransport.com",
    "anstv.net",
    "ans7tv.net",
]
# print(templates[args.template])
# get all threatprotection rule template
rule_template = conn.get_object(
    "threatprotection:ruletemplate", return_fields=["name", "default_config"]
)
# print rule templates
if args.debug:
    print(rule_template)
for t in templates:
    if args.debug:
        print(t)
    for rt in rule_template:
        if templates[t] == rt["name"]:
            if args.debug:
                # print rule template object
                for x in rt:
                    print(x)
            for d in triangulation_domains:
                if args.debug:
                    print(d)
                custom_rule = conn.create_object(
                    "threatprotection:grid:rule",
                    {
                        "template": rt["_ref"],
                        "disabled": False,
                        "comment": "Rule for blocking IOS triangulation domains: https://securelist.com/operation-triangulation/109842/",
                        "config": {
                            "action": "DROP",
                            "log_severity": "MAJOR",
                            "params": [{"name": "FQDN", "value": d}],
                        },
                    },
                )
                if custom_rule:
                    print("{} {} rule created successfully".format(d, rt["name"]))
                else:
                    print("{} {} rule creation failed".format(d, rt["name"]))
