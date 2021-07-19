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
import hashlib
from panos.objects import Tag


def calculate_rule_risk(security_rule):
    """[TODO] Impelementation Needed

    Args:
        security_rule ([type]): [description]

    Returns:
        [type]: [description]
    """
    return None


def gen_rule_group_identifiers(rule_group: list):
    """[TODO] Implementation needed
    The idea heere is to return rule data in a flattened dictionary format.

    Args:
        rule_group (list): [description]
    """
    listhashid = hashlib.sha1(str(rule_group).encode('utf-8')).hexdigest()[-8:]
    tagname = f'shadow-grp-{listhashid}'
    ruleliststr = str(', '.join(rule_group))
    groupcomment = (f'Shadow Rule Group (Hash: {listhashid})'
                    f' - Members {ruleliststr}')
    return tagname, groupcomment


def make_shadowed_rule_list(jsdata):
    shadow_rule_dict = dict()
    try:
        for item in jsdata['response']['result']['shadow-warnings-count']['entry']['entry']:
            shadow_rule_dict[item['@name']] = {
                "uuid": item['@uuid'],
                "shadowcount": int(item['#text'])
            }
    except Exception as e:
        app_log.error(f"JSDATA: {jsdata}")
        raise e
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


def get_shadow_count(shadowdict):
    totalcount = 0
    for key in shadowdict:
        totalcount += shadowdict[key]['shadowcount']
    return totalcount


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
    if 'device_group' in cfgdict['panoramas'][panorama.hostname]:
        for i, dg in enumerate(dglist):
            if cfgdict['panoramas'][panorama.hostname]['device_group'] == dg.name:
                dg = dglist[i]
    else:
        for i, name in enumerate(dglist):
            print(f"{i} - {name}")
        print("Choose your DG Number")
        dgnum = int(input())
        dg = dglist[dgnum]
    app_log.info(f"Working on Device Group: {dg.name}")
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
    # app_log.debug(json.dumps(shadowed_rules, indent=2, sort_keys=False))
    app_log.info(f"Total Shadow rule groups: {len(shadowed_rules.keys())}")
    app_log.info(
        f"Total Rules in shadow groups: {get_shadow_count(shadowed_rules)}")
    rules = panoramahelpers.get_all_rules(panorama, dg)
    for r in shadowed_rules:
        shadowed_rules[r]['shadow_list'] = [r] + \
            get_shadow_details(shadowed_rules[r], panorama, dg, fw)
        app_log.info(
            f"Shadow list for {r}: {shadowed_rules[r]['shadow_list']}")
        tagname, comment = gen_rule_group_identifiers(
            shadowed_rules[r]['shadow_list'])
        shadowed_rules[r]['grouptag'] = tagname
        shadowed_rules[r]['groupcomment'] = comment
        # Create the tag
        tag = panoramahelpers.get_or_create_tag(
            tagname, panorama, dg, comments=comment[:1000])
        app_log.info(
            f"Adding tag {tagname} and comment to rulegroup: {str(shadowed_rules[r]['shadow_list'])}")
        for rule in shadowed_rules[r]['shadow_list']:
            for obj in rules:
                if rule == obj.name:
                    rule = obj
            if type(rule) == str:
                print(f'{rule} not found in rulebase')
            else:
                applyflag = False
                if (type(rule.tag) == list) and tag.name not in rule.tag:
                    rule.tag = rule.tag.append(tag.name)
                    rule.comment = f"Shadow rule group {tagname}"
                    applyflag = True
                elif rule.tag is None:
                    rule.tag = [tag.name]
                    rule.comment = f"Shadow rule group {tagname}"
                    applyflag = True
                else:
                    app_log.warning(
                        f"Rule {rule.name} already has correct tag: {tagname}")
                if applyflag:
                    try:
                        app_log.info(
                            f"Applying tag {tag.name} on rule {rule.name}")
                        rule.apply()
                        rule.refresh()
                    except Exception as e:
                        raise e
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
