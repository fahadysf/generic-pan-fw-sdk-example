# gp-user-session-limiter

## Pre-requisites and Installation

* Python v3.6 or later
* pandevice
* pan-os-python
* PyYAML

* Download and extract this package zip file in a folder at any location.
* Open a command prompt / terminal and cd into the directory where you extracted
 this package (gp-user-session-limiter.zip)

* After installing Python3 (v3.6+) you can install the pre-requisites using the pip

``` python3 -m pip install -r requirements.txt ```

## Configuration

Make a copy of config.yml.example and name it config.yml
The configuration format is YAML and the parameters are described below:

```
# This is the config file in YAML format having the Firewalls and GP Gateway 
# names that need to be monitored for multiple logon sesisons.

# WARNING: DO NOT REMOVE OR RENAME THIS FILE. MAKE A COPY AND MODIFY THAT 
# TO MAKE YOUR CONFIG. The config file "config.yml" will be overwritten 
# automatically by the script in case API Keys are not specified and 
# WARNING: All comments / instructions in them will be lost when config.yml
# is overwritten.

# As an example for a stand-alone firewall.

session_limit: 1    # Number of allowed sessions for a user
log_path: './logs'  # Location of log files for this script
dry_run: false

# This parameter will make the check for user sessions accross all GlobalProtect 
# gateways on the same Firewall / HA Pair. When disabled, the session limit
# Will be applied on individual GP Gateways but same user can connect to other
# GP Gateways defined on the same firewall.
match_user_accross_gateways: true

# Firewalls to be monitored.
# Note 1: In case of HA firewalls, only one of the firewalls should be defined
#         in the HA section and the peer firewall IP/Hostname should be 
#         provided in the ha_peer_ip field under the firewall entry


firewalls:
  "192.168.1.1":
    api_key: "<API-Key-for-user>"
    gp_gateway:
      - "gp_gateway_name"
      - "gp_gateway_name2"
    ha_peer_ip: "192.168.1.2"      # Specify HA peer IP if HA is enabled. 
    # whitelist_users is a list of users that are exempted from sesison limits 
    # and can have unlimited  sessions. The usernames specified here 
    # should have the same format as what appears on the firewall when running
    # the command 'show 
    whitelist_users:               
      - testuser2                  
```

An example config.yml is as follows:

```
log_path: ./logs
match_user_accross_gateways: true
session_limit: 1

dry_run: false
firewalls:
  192.168.100.55:
    api_key: <API-KEY>
    gp_gateways:
      - gw-name-1
      - gw-name-2
    ha_peer_ip: 192.168.1.1
    whitelist_users:
      - testuser2
```

## Usage

After configuration file is in place, run the script using python3:

``` python3 gp-user-session-tool.py ```

To enable debugging output on console. Use the -debug flag

``` python3 gp-user-session-tool.py -debug ```# generic-pan-fw-sdk-example
