
# netbox-scripts

Collection of netbox scripts to automatically update OPNsense KEA and PowerDNS configuration

## Introduction

This is a small collection of Netbox scripts to automatically configure DHCP
and DNS using Netbox as a single source of truth. The main focus is simplicity,
targeting small/home/lab environments. The scripts aim to configure the
relevant services automatically when triggered via a Netbox event rule,
using the changed object's attributes as a source. It is important to note
this method doesn't follow Netbox best practices as it is up to the service to
get the configuration from Netbox (e.g. via webhooks).
However, this requires more complexity and may be overkill for small environments.

The provided scripts are a work in progress and are to be used fully at your own
risk.

## Installation

Scripts can be installed using following high level method:

- Add the script to Netbox via Customization -> Scripts
- Manual tasks can be triggered in the GUI by manually running the script
- Automatic updates can be configured via Integrations -> Event Rules

## Scripts

### OPNsense managed KEA DHCP - opnsense-kea-sync.py

This script manages subnets and reservation of Kea DHCP services managed via
the OPNsense API.

#### Features

- Automatic synchronization between Netbox Prefixes and OPNsense Kea subnets
- Mapping of Netbox IP Ranges to pools within the parent Prefix/subnets
- Configuration of subnet and pool options
- Automatic creation and configration of reservations
- Option to limit changing subnets/reservations based on OPNsense synchronization
- Custom object filtering
- Supported objects: IPAddress, IPRange, Prefix, Interface, VMInterface

#### Limitations

- Only DHCPv4 supported

#### Extra requirements

None

#### Configuration example

This is an example of a configuration that can be placed in the action field
when setting up a Netbox Event Rule.
The rule can e.g. be applied to the IPAM prefix object type and the
"Object updated" event type. Make sure to set the appropriate opn_kea_action
(add, set, del) for each event type.

The result will be that when updating a Netbox Prefix with role "DHCP Reserved",
the Kea subnet will be updated with the provided options. Additionally, all
child ip addresses of the prefix/subnet with status set to "dhcp" will have
their reservations added/updated if they are attached to an interface with a
valid mac address configured.

```
{
    "opn_api_base_url": "https://you_opnsense_management_url",
    "opn_api_key": "<your_api_key",
    "opn_api_secret": "your_api_secret",
    "opn_api_test": true,
    "opn_api_verify_ssl": true,
    "opn_kea_action": "set",
    "opn_kea_allowed_prefixes": [],
    "opn_kea_dry_run": false,    
    "opn_kea_filter_ip_exclude": {},
    "opn_kea_filter_ip_include": {
        "status": [
            "dhcp"
        ]
    },
    "opn_kea_filter_prefix_exclude": {},
    "opn_kea_filter_prefix_include": {
        "role__name": [
            "DHCP Reserved"
        ]
    },
    "opn_kea_force": false,
    "opn_kea_ha_sync": false,
    "opn_kea_set_hostname": true,
    "opn_kea_strict": false,    
    "opn_kea_opt_boot_file_name": "",    
    "opn_kea_opt_domain_name": "mydomain.com",
    "opn_kea_opt_domain_search": ""    ,
    "opn_kea_opt_domain_name_servers": "1.1.1.1,8.8.8.8",
    "opn_kea_opt_ntp_servers": "",
    "opn_kea_opt_routers": "10.10.10.1",
    "opn_kea_opt_static_routes": "",
    "opn_kea_opt_time_servers": "",    
    "opn_kea_opt_v6_only_preferred": "",
    "opn_kea_opt_tftp_server_name": "",
    "opn_kea_sub_managed_description": "Netbox managed",        
    "opn_kea_sub_next_server": "",
    "opn_kea_sub_match-client-id": false,
    "opn_kea_sub_option_data_autocollect": false    
}
```

Options starting with opn_kea_sub and opn_kea_opt correspond to
OPNsense Kea service settings. Please see the OPNsense documentation for more
information.

### PowerDNS Sync - powerdns-sync.py

This script creates and syncs Netbox IP addresses with PowerDNS.

#### Features

- Automatic synchronization between Netbox and PowerDNS Authoritive servers
- Automatic creation and configuration of reservations
- Option to limit changing records based on PowerDNS comments
- Custom IP filtering
- Supported objects: IPAddress

#### Limitations

- Only IPv4 supported

#### Extra requirements

- pip install python-powerdns

#### Configuration example

This is an example of a configuration that can be placed in the action field
when setting up a Netbox Event Rule.
The rule can be applied to e.g. the IPAM IPAddress object type and the
"Object updated" event type. Make sure to set the appropriate pdns_action
(add, set, del) for each event type.

When an IP address is updated,the A and PTR records in PowerDNS will be updated

```
{
    "pdns_action": "set",
    "pdns_api_key": "your_api_key",
    "pdns_api_url": "https://your_powerdns_api_url",
    "pdns_comment": "Netbox managed",
    "pdns_dry_run": false,
    "pdns_enable_reverse": true,
    "pdns_filter_exclude": {},
    "pdns_filter_include": {
        "status": [
            "active",
            "dhcp"
        ]
    },
    "pdns_force": false,
    "pdns_forward_zones": "mydomain.com,myotherdomain.com",
    "pdns_reverse_zones": "168.192.in-addr.arpa"
}
```
