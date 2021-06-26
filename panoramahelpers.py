import panoshelpers
from panos.panorama import DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule
from panos.objects import Tag


def get_active_panorama(cfgdict):
    # Cycle through the Panoramas defined in the config.
    panorama_objs = panoshelpers.initialize_panorama_objs(cfgdict)
    for panorama in panorama_objs:
        if panorama.ha_peer != None:
            panorama.refresh_ha_active()
            panorama_active = panorama.active()
            cfgdict['panoramas'][panorama_active.hostname] = cfgdict['panoramas'][panorama.hostname]
            app_log.info(
                f"HA enabled on Panorama. Active firewall is {panorama_active.hostname}")
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


def get_rules(rulebase_type, panorama_obj, dg_obj):
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


def get_pre_rules(panorama_obj, dg_obj):
    return get_rules("pre-rulebase", panorama_obj, dg_obj)


def get_post_rules(panorama_obj, dg_obj):
    return get_rules("post-rulebase", panorama_obj, dg_obj)


def get_or_create_tag(tag_name, panorama_obj, dg_obj, color=None, comments=""):
    tag = dg_obj.add(Tag(name=tag_name, color=color, comments=comments))
    try:
        tag.create()
    except Exception:
        raise
    return tag
