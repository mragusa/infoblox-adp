#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Custom List",
    description="Update Allow/Deny Lists for ADP",
    epilog="Rules created are based on Infoblox provided Templates",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
# There are four different whitelists
parser.add_argument("-wu", "--whitelist-udp", help="Add FQDN to whitelist UDP")
parser.add_argument("-wt", "--whitelist-tcp", help="Add FQDN to whitelist TCP")
parser.add_argument("-wur", "--whitelist-udp-rate", help="Add FQDN to whitelist UDP prior to rate limiting")
parser.add_argument("-wtr", "--whitelist-tcp-rate", help="Add FQDN to whitelist TCP prior to rate limiting")
# There are six different blacklist
parser.add_argument("-bu", "--blacklist-udp", help="Add FQDN to blacklist UDP")
parser.add_argument("-bt", "--blacklist-tcp", help="Add FQDN to blacklist TCP")
parser.add_argument("-bur", "--blacklist-udp-rate", help="Add FQDN to whitelist")
#parser.add_argument("-b", "--blacklist", help="Add FQDN to whitelist")
#parser.add_argument("-b", "--blacklist", help="Add FQDN to whitelist")
#parser.add_argument("-b", "--blacklist", help="Add FQDN to whitelist")
args = parser.parse_args()
# for debugging
if args.debug:
    import logging

    logging.basicConfig(level=logging.DEBUG)
    print("Enabling Debug Output")

opts = {"host": args.gmhostname, "username": args.user, "password": args.password}
conn = connector.Connector(opts)
# get all network_views
network_views = conn.get_object("networkview")
# print network view
print(network_views)
