#! python3
"""
Script:       generic-ngfw-control-logic.py

Author:       Fahad Yousuf <fyousuf@paloaltonetworks.com>

Description:
Tool to control maximum number of sessions from the same GlobalProtect User.

Requirements:
- Python v3.6 or later
- pandevice
- pan-os-python
- PyYAML

Interpreter:       Version 1

License:

© 2020 Palo Alto Networks, Inc. All rights reserved.
Licensed under SCRIPT SOFTWARE AGREEMENT, Palo Alto Networks, Inc., at
https://www.paloaltonetworks.com/legal/script-software-license-1-0.pdf

"""

import os
import sys
import time
import getpass
import logging
import logging.handlers as lh

try:
    from panos.firewall import Firewall
except ImportError:
    raise ValueError(
        "pan-os-python module not available, please install it by running 'python3 -m pip install pan-os-python'")

try:
    import yaml
except ImportError:
    raise ValueError(
        "PyYAML module not available, please install it by running 'python3 -m pip install PyYAML'")


def load_config(config_file='config.yml'):
    import yaml
    try:
        with open(config_file, "r") as ymlfile:
            cfg = yaml.safe_load(ymlfile)
            return cfg
    except BaseException as e:
        print("Config file 'config.yml' not found or couldn't be opened.")
        exit(1)


def get_config_param(dictpath, param):
    if not param in dictpath.keys():
        return None
    else:
        return dictpath[param]
    return None


# Setup logging
try:
    cfgdict = load_config()
except BaseException as e:
    app_log.error(
        "Unable to load configuration. Please ensure config.yml exists and has no errors")

# Setup logging
if not os.path.exists(cfgdict['log_path']):
    os.mkdir(cfgdict['log_path'])
log_file = os.path.join(cfgdict['log_path'], 'ngfw-control-script.log')
log_rotation_size = 10 * 1024 * 1024  # Size in bytes (This is 10 MB)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

file_handler = lh.RotatingFileHandler(
    log_file, maxBytes=log_rotation_size, backupCount=3)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

console_handler = logging.StreamHandler()
console_handler.setFormatter(log_formatter)
console_handler.setLevel(logging.DEBUG)

app_log = logging.getLogger('root')
if '-debug' in sys.argv:
    app_log.setLevel(logging.DEBUG)
else:
    app_log.setLevel(logging.INFO)
app_log.addHandler(file_handler)
app_log.addHandler(console_handler)


def save_config(cfgdict, config_file='config.yml'):
    with open(config_file, 'w') as outfile:
        yaml.dump(cfgdict, outfile, default_flow_style=False)
    return


def get_credentials(fw_addr):
    app_log.info(
        f"API Key for firewall {fw_addr} is not defined in config.yml")
    print("Please enter the username and password for the user for the API access.")
    print("Configuration file (config.yml) will be updated automatically once the API Key is created.")
    username = input("Enter username: ")
    password = getpass.getpass()
    return username, password


def gen_api_key(fw_addr, username='', password=''):
    if not (len(username) or len(password)):
        username, password = get_credentials(fw_addr)
        try:
            fw_obj = Firewall(fw_addr,
                              api_username=username,
                              api_password=password)
            if fw_obj.api_key:
                app_log.info(
                    f"API Key generated for firewall {fw_addr} for username {username}")
                return fw_obj, fw_obj.api_key
        except BaseException as e:
            app_log.error("Error generating API Key")
            app_log.exception(f"Got exception in gen_api_key: {e.message}")
            exit(1)


def initialize_fw_objs(cfgdict):
    """[summary]

    Arguments:
        cfgdict {[type]} -- [description]

    Returns:
        [type] -- [description]
    """
    fw_dict = cfgdict['firewalls']
    fw_objs = list()

    # Check for API Keys in Config
    config_dirty = 0
    for fw in fw_dict.keys():
        app_log.info(f"Connecting to firewall {fw}")
        try:
            if ('api_key' not in fw_dict[fw].keys()) or (fw_dict[fw]['api_key'] == None) or (fw_dict[fw]['api_key'] == ''):
                fw_obj, api_key = gen_api_key(fw)
                fw_objs.append(fw_obj)
                fw_dict[fw]['api_key'] = api_key
                config_dirty = 1
            else:
                fw_obj = Firewall(
                    fw, api_key=fw_dict[fw]['api_key'], timeout=5)

            if get_config_param(fw_dict[fw], 'ha_peer_ip') != None:
                fw2 = fw_dict[fw]['ha_peer_ip']
                fw_obj_ha = Firewall(fw2, api_key=fw_dict[fw]['api_key'])
                fw_obj.set_ha_peers(fw_obj_ha)

            fw_objs.append(fw_obj)

            if config_dirty:
                cfgdict['firewalls'] = fw_dict
                save_config(cfgdict)
        except BaseException as e:
            app_log.error(
                f"Could not initialize conneciton to {fw}: {e.message}")

    return fw_objs


def get_gp_sattelite_status(fw_obj, gp_gateway):
    """[summary] Tests to see the status of GP Satellite gateway with provided IP
    Arguments:
        fw_obj {pan} -- [description]
        gp_gateway {str} -- [description] IP address of GP Gateway as string
    """
    try:
        r = fw_obj.op(
            f'<show><global-protect-satellite><current-gateway><gateway>{gp_gateway}</gateway></current-gateway></global-protect-satellite></show>', cmd_xml=False, xml=True).decode('utf-8')
        if ('initializing' in r) or ('Initializing' in r):
            return False
        elif ('Tunnel monitoring up' in r):
            print(r)
            return True

    except BaseException as e:
        app_log.error(f'Failed to run query on firewall - {fw_obj}')
        app_log.exception(e.message)
        raise
    return False


def reset_gp_sattelite_session(fw_obj, gp_gateway, gp_satellite_name):
    """[summary] Resets the GP Satellite connection
    Arguments:
        fw_obj {pan} -- [description]
        gp_gateway {str} -- [description] IP address of GP Gateway as string
        gp_satellite_name {str} -- [description] GP Satellite Name
    """
    cmd_xml_str = f'<test><global-protect-satellite><gateway-reconnect><satellite>{gp_satellite_name}</satellite><gateway-address>{gp_gateway}</gateway-address><method>activation</method></gateway-reconnect></global-protect-satellite></test>'

    try:
        result = fw_obj.op(cmd_xml_str, cmd_xml=False, xml=True)
    except BaseException:
        raise
    return result.decode('utf-8')


def main():
    """This is a generic example of cycling through HA firewalls and doing something via API.

    Returns:
        [type]: [description]
    """
    # Cycle through the firewalls defined in the config.
    fw_objs = initialize_fw_objs(cfgdict)
    for fw in fw_objs:
        if fw.ha_peer != None:
            fw.refresh_ha_active()
            fw_active = fw.active()
            cfgdict['firewalls'][fw_active.hostname] = cfgdict['firewalls'][fw.hostname]
            app_log.info(
                f"HA enabled on firewall. Active firewall is {fw_active.hostname}")
        else:
            fw_active = fw

        app_log.info(
            f'Checking for GP Satellite connection status on Firewall {fw.hostname}')

        # Execute your logic here.

        # Write more logic here (Pending)
        # --------
        fail_counter = 0
        # Write some actual logic using the fw_active instance to execute stuff on the active FW.
        # ##
        app_log.info(
            f'Process completed on firewall {fw_active.hostname}.')
    return True


if __name__ == '__main__':
    if 'daemon_mode' in cfgdict.keys() and cfgdict['daemon_mode']:
        try:
            while True:
                start_time = time.time()
                main()
                end_time = time.time()
                elapsed = end_time - start_time
                app_log.info(
                    f"Execution took {elapsed} seconds for all firewalls.")
                if 'check_interval' in cfgdict.keys():
                    time.sleep(cfgdict['check_interval'])
                else:
                    # Default re-check time is 30 seconds.
                    time.sleep(30.0)
        except KeyboardInterrupt as kbi:
            app_log.warning("Ctrl+C pressed. Gracefully exiting.")
            exit(0)
    else:
        main()
        exit(0)
