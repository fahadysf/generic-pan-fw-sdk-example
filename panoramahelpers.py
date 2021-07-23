import panoshelpers
import panos
from panos.panorama import DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule
from panos.objects import Tag, AddressObject, AddressGroup, ServiceObject, ServiceGroup

app_log = panoshelpers.app_log


def get_active_panorama(cfgdict):
    # Cycle through the Panoramas defined in the config.
    panorama_objs = panoshelpers.initialize_panorama_objs(cfgdict)
    for panorama in panorama_objs:
        if panorama.ha_peer is not None:
            panorama.refresh_ha_active()
            panorama_active = panorama.active()
            cfgdict['panoramas'][panorama_active.hostname] = cfgdict['panoramas'][panorama.hostname]
            app_log.info(
                f"HA enabled on Panorama. Active Panorama is {panorama_active.hostname}")
        else:
            panorama_active = panorama

    return panorama_active


def get_devicegroups(panorama_obj):
    """ Returns a list of device groups on a Panorama device

    Args:
        panorama_obj (panos.panorama.Panorama): Panorama instance to extract device groups from
    """
    dglist = panorama_obj.refresh_devices()
    return dglist


def get_rules_from_rulebase(rulebase_type, panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup):
    """Returns pre or post-rulebase from a given dg

    Args:
        rulebase_type (str): "pre-rulebase or post-rulebase"
        panorama_obj (panos.panorama.Panorama): Panorama Object containing the DG
        dg_obj (panos.panorama.DeviceGroup): Device group to extract pre-rulebase from
    """
    panorama_obj.add(dg_obj)
    if rulebase_type == 'pre-rulebase':
        rb = PreRulebase()
    elif rulebase_type == 'post-rulebase':
        rb = PostRulebase()
    dg_obj.add(rb)
    rules = SecurityRule.refreshall(rb)
    return rules


def get_pre_rules(panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup):
    return get_rules_from_rulebase("pre-rulebase", panorama_obj, dg_obj)


def get_post_rules(panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup):
    return get_rules_from_rulebase("post-rulebase", panorama_obj, dg_obj)


def get_all_rules(panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup):
    return get_pre_rules(panorama_obj, dg_obj) + get_post_rules(panorama_obj, dg_obj)


def get_or_create_tag(tag_name, panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup, color=None, comments=""):
    tag = dg_obj.add(Tag(name=tag_name, color=color, comments=comments))
    try:
        tag.create()
    except Exception:
        raise
    return tag


def get_all_tags(panorama_obj, dg_obj):
    panorama_obj.add(dg_obj)
    tags = Tag.refreshall(dg_obj)
    return tags


def get_rule(dg_obj: panos.panorama.DeviceGroup, rule_name: str = ""):
    pre_rulebase = PreRulebase()
    post_rulebase = PostRulebase()
    dg_obj.add(pre_rulebase)
    dg_obj.add(post_rulebase)
    rule = SecurityRule.find(pre_rulebase, rule_name)
    if rule is None:
        rule = SecurityRule.find(post_rulebase, rule_name)
    return rule


def get_address_objects(panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup = None, merge_shared: bool = False):
    address_objs_dict = dict()
    address_objs = list()
    if merge_shared or (dg_obj == None):
        address_objs += AddressObject.refreshall(panorama_obj)
        for item in address_objs:
            address_objs_dict[item.name] = {
                "object": item,
                "value": item.value,
                "container": "shared"
            }
    if dg_obj:
        address_objs = AddressObject.refreshall(dg_obj)
        for item in address_objs:
            address_objs_dict[item.name] = {
                "object": item,
                "value": item.value,
                "container": dg_obj.name,
            }
    return address_objs_dict


def get_address(name: str, panorama_obj: panos.panorama.Panorama, dg_obj: panos.panorama.DeviceGroup = None):
    address_obj_dict = get_address_objects(
        panorama_obj, dg_obj=dg_obj, merge_shared=True)
    if name in address_obj_dict.keys():
        return address_obj_dict[name]
    else:
        return None
