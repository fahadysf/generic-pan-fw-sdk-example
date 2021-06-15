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

import time
import panoshelpers
import panoramahelpers
import json


def main():
    """This is a generic example of cycling through HA firewalls and doing something via API.

    Returns:
        [type]: [description]
    """
    panorama = panoramahelpers.get_active_panorama(cfgdict)

    # Execute your logic here.
    # data_str = panoshelpers.get_system_info(panorama)
    # print(json.dumps(data_str, indent=4, sort_keys=True))

    app_log.info(
        f'Doing something -- UPDATE THIS MESSAGE OBVIOUSLY -- on Panorama {panorama.hostname}')
    dglist = panoramahelpers.get_devicegroups(panorama)
    print(dglist)
    pre_rulebase = panoramahelpers.get_pre_rules(
        panorama, dglist[0])
    print(pre_rulebase)

    # Write more logic here (Pending)
    # --------
    fail_counter = 0
    # Write some actual logic using the panorama instance to execute stuff on the active panorama.
    # ##
    app_log.info(
        f'Process completed on Panorama {panorama.hostname}.')
    return True


if __name__ == '__main__':
    app_log = panoshelpers.app_log
    cfgdict = panoshelpers.cfgdict
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
