import panoshelpers
from panos.panorama import DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule


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


def get_pre_rules(panorama_obj, dg_obj):
    """Returns pre-rulebase from a given dg

    Args:
        dg_obj (panos.panorama.DeviceGroup): Device group to extract pre-rulebase from
    """
    panorama_obj.add(dg_obj)
    pre_rb = PreRulebase()
    dg_obj.add(pre_rb)
    rules = SecurityRule.refreshall(pre_rb)
    return rules
