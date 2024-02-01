# infoblox-adp
Infoblox Advanced DNS Protection Scripts

These are a collection of scripts developed to simplify interacting with the Infoblox ADP product [^1][^2]

## Configuring ADP
[!NOTE]
When enabling ADP, the LAN1 port becomes dedicated to DNS traffic. There for each member appliance will need to utilize the mgmt port for ssh/vpn

[!IMPORTANT]
Applying the license and enabling the service will cause a reboot of the appliances. Ensure this will be non-impacting for your end users

1. Enable the Threat Protection license on each grid member that will have ADP installed on them
2. Enable the Threat Protection software update license on each member that has had ADP applied
3. Download the latest rulesets automatically via the GUI from the appliance. If your appliances are on restricted networks, download the ruleset from https://support.infoblox.com
[!TIP]
if monitoring prior to implementing blocking is preferred run the following command on the member appliance cli prior to enabling the service
```
set adp monitor-mode on
```
4. Enable the ADP in the GUI and enable the threat protection service. (This will cause one more reboot of the appliance)
5. Create a Profile for ThreatProtection Rules
6. Monitor the dashboards and reporting appliance for events

## Scripts
| Script Name | Purpose |
| infoblox-adp-framework.py | basic framework script to jump start development |
| adp-stats.py | Query the grid for the last 30 mins of threat protection statistics |
| adp-profile.py | Query, Create and Remove ADP profiles on the Infoblox Grid |
| adp-tunnel-ruleset.py  | View current policies on Tunneling/AntiTunneling on the Grid or ADP Profiles |

[^1]: All code uses the infoblox-client module https://github.com/infobloxopen/infoblox-client
[^2]: All code is styled using black https://github.com/psf/black
