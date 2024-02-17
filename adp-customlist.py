#!/usr/bin/python3

import urllib3

urllib3.disable_warnings()

from infoblox_client import connector
from infoblox_client import objects
import argparse

parser = argparse.ArgumentParser(
    prog="Infoblox ADP Custom List",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description='''
	Update Allow/Deny Lists for ADP based on Infoblox provided Templates

	The folllowing templates are currently allowed:
	whitelist-udp : Use this rule template to create custom rules to allow DNS queries by FQDN lookups on UDP
	whitelist-tcp : Use this rule template to create custom rules to allow DNS queries by FQDN lookups on TCP
	whitelist-udp-rate : Use this rule template to create custom rules for allowing certain IP addresses on UDP before the appliance drops the packets based on rate limiting rules you have defined using the RATELIMITED IP UDP template
	whitelsit-tcp-rate : Use this rule template to create custom rules for allowing certain IP addresses on TCP before the appliance drops the packets based on rate limiting rules you have defined using the RATELIMITED IP TCP template
	blacklist-udp : Use this rule template to create custom rules for blacklisting DNS queries by FQDN lookups on UDP
	blacklist-tcp : Use this rule template to create custom rules for blacklisting DNS queries by FQDN lookups on TCP
	blacklist-udp-rate : Use this rule template to create rules for blocking IPv4 or IPv6 addresses on UDP before the appliance drops the packets based on rate limiting rules you have defined using the BLACKLIST IP UDP Drop prior to rate limiting template
	blacklist-tcp-rate : Use this rule template to create rules for blocking IPv4 or IPv6 addresses on TCP before the appliance drops the packets based on rate limiting rules you have defined using the BLACKLIST IP TCP Drop prior to rate limiting template
	blacklist-udp-type : Use this rule template to create custom rules for blacklisting FQDN lookups on UDP for the specified DNS message type
	blacklist-tcp-type : Use this rule template to create custom rules for blacklisting FQDN lookups on TCP for the specified DNS message type
	ratelimit-udp : Use this rule template to create custom rules that contains rate limiting restrictions for blacklisting IP addresses on UDP. If there are certain IP addresses that you want to block before its traffic reaches the rate limit restrictions
	ratelimit-tcp : Use this rule template to create custom rules that contains rate limiting restrictions for blacklisting IP addresses on TCP. If there are certain IP addresses that you want to block before its traffic reaches the rate limit restrictions
	ratelimit-udp-fqdn : Use this rule template to create custom rules that contains rate limiting restrictions for blocking DNS queries by FQDN lookups on UDP traffic
	ratelimit-tcp-fqdn : Use this rule template to create custom rules that contains rate limiting restrictions for blocking DNS queries by FQDN lookups on TCP traffic
	ratelimit-udp-type : Use this rule template to create custom rules that contain rate limiting restrictions for blacklisting UDP DNS packets that contain the specified DNS record type
	ratelimit-tcp-type : Use this rule template to create custom rules that contain rate limiting restrictions for blacklisting TCP DNS packets that contain the specified DNS record type
	pass-udp-type : Use this rule template to create custom rules to allow UDP DNS packets that contain the specified DNS record type
	pass-tcp-type : Use this rule template to create custom rules to allow TCP DNS packets that contain the specified DNS record type
	''',
    epilog="DNS message type templates do not support the following types: MD (3), MF (4), MB (7), MG (8), MR (9), WKS (11), HINFO (13), MINFO (14), IXFR (251), and AXFR (252) record.",
)
parser.add_argument("gmhostname", help="Grid Master IP")
parser.add_argument("-u", "--user")
parser.add_argument("-p", "--password")
parser.add_argument("-d", "--debug", action="store_true", help="Enable Debug Mode")
# Choose template from available options
parser.add_argument("-t", "--template", choices=["whitelist-udp", "whitelist-tcp", "whitelist-udp-rate", "whitelist-tcp-rate", "blacklist-udp", "blacklist-tcp", "blacklist-udp-rate", "blacklist-tcp-rate", "blacklist-udp-type", "blacklist-tcp-type", "ratelimit-udp", "ratelimit-tcp", "ratelimit-udp-fqdn", "ratelimit-tcp-fqdn", "ratelimit-udp-type", "ratelimit-tcp-type", "pass-udp-type", "pass-tcp-type"],)
parser.add_argument("-f", "--fqdn", help="Domain to add to specified list")
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
	"whitelist-udp":"WHITELIST UDP Domain",
	"whitelist-tcp":"WHITELIST TCP Domain",
	"whitelist-udp-rate" : "WHITELIST IP UDP Pass prior to rate limiting",
	"whitelist-tcp-rate" : "WHITELIST IP UDP Pass prior to rate limiting",
	"blacklist-udp" : "BLACKLIST FQDN lookup UDP",
	"blacklist-tcp" : "BLACKLIST FQDN lookup UDP",
	"blacklist-udp-rate" : "BLACKLIST IP UDP Drop prior to rate limiting",
	"blacklist-tcp-rate" : "BLACKLIST IP TCP Drop prior to rate limiting",
	"blacklist-udp-type" : "BLACKLIST UDP FQDN lookup for DNS Message Type",
	"blacklist-tcp-type" : "BLACKLIST TCP FQDN lookup for DNS Message Type",
	"ratelimit-udp" : "RATELIMITED IP UDP",
	"ratelimit-tcp" : "RATELIMITED IP TCP",
	"ratelimit-udp-fqdn" : "RATELIMITED FQDN lookup UDP",
	"ratelimit-tcp-fqdn" : "RATELIMITED FQDN lookup TCP",
	"ratelimit-udp-type" : "RATE LIMITED UDP DNS Message Type",
	"ratelimit-tcp-type" : "RATE LIMITED TCP DNS Message Type",
	"pass-udp-type" : "Pass UDP DNS Message Types",
	"pass-tcp-type" : "Pass TCP DNS Message Types",
}

print(templates[args.template])
# get all network_views
#network_views = conn.get_object("networkview")
# print network view
#print(network_views)
