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


def calculate_rule_risk(security_rule):
    """[TODO] Impelementation Needed

    Args:
        security_rule ([type]): [description]

    Returns:
        [type]: [description]
    """
    return None


def gen_rule_group_data(rule_group: list):
    """[TODO] Implementation needed
    The idea heere is to return rule data in a flattened dictionary format.

    Args:
        rule_group (list): [description]
    """
    listhash = str(hex(str(rule_group)))
    return None


def make_shadowed_rule_list(jsdata):
    shadow_rule_dict = dict()
    try:
        for item in jsdata['response']['result']['shadow-warnings-count']['entry']['entry']:
            shadow_rule_dict[item['@name']] = {
                "uuid": item['@uuid'],
                "shadowcount": int(item['#text'])
            }
    except:
        app_log.error(f"JSDATA: {jsdata}")
        raise
    return shadow_rule_dict


def get_shadow_details(ruledata, panorama, dg, fw):
    uuid = ruledata['uuid']
    get_shadowed_rule_details = f"""<show>
    <shadow-warning><warning-message>
    <device-group>{dg.name}</device-group>
    <device-serial>{fw.serial}</device-serial>
    <uuid>{uuid}</uuid></warning-message>
    </shadow-warning></show>"""
    res = panoshelpers.get_xml_op(panorama,
                                  cmd=get_shadowed_rule_details, cmd_xml=False, xml=False)
    shadow_list = res['response']['result']['warning-msg']['member']
    if type(shadow_list) == list:
        shadow_list = list(map(lambda x: x[8:-1], shadow_list))
    else:
        shadow_list = [shadow_list[8:-1]]
    return shadow_list


def main():
    """This is a generic example of cycling through HA firewalls and doing
    something via API.

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
    for i, name in enumerate(dglist):
        print(f"{i} - {name}")
    print("Choose your DG Number")
    dgnum = int(input())
    dg = dglist[dgnum]
    fw = dg.children[0]
    get_shadowed_rules_cmd = f"""<show>
    <shadow-warning>
    <count>
    <device-serial>{fw.serial}</device-serial>
    </count>
    </shadow-warning></show>"""
    res = panoshelpers.get_xml_op(panorama,
                                  cmd=get_shadowed_rules_cmd, cmd_xml=False, xml=False)
    shadowed_rules = make_shadowed_rule_list(res)
    app_log.debug(json.dumps(shadowed_rules, indent=2, sort_keys=False))
    for r in shadowed_rules:
        shadowed_rules[r]['shadow_list'] = [r] + \
            get_shadow_details(shadowed_rules[r], panorama, dg, fw)
        app_log.info(
            f"Shadow list for {r}: {shadowed_rules[r]['shadow_list']}"
        )

    # pre_rulebase = panoramahelpers.get_pre_rules(
    #    panorama, dglist[0])
    # print(pre_rulebase)

    # Write more logic here (Pending)
    # --------
    # Write some actual logic using the panorama instance to execute stuff on
    # the active panorama.
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
