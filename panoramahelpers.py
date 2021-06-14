from panos.panorama import DeviceGroup
from panos.policies import PreRulebase, PostRulebase, SecurityRule


def get_devicegroups(panorama_obj):
    """ Returns a list of device groups on a Panorama device

    Args:
        panorama_obj (panos.panorama.Panorama): Panorama instance to extract device groups from
    """
    dglist = panorama_obj.refresh_devices()
    return dglist


def get_pre_rules(dg_obj):
    """Returns pre-rulebase from a given dg

    Args:
        dg_obj (panos.panorama.DeviceGroup): Device group to extract pre-rulebase from
    """
    pre_rulebase = PreRulebase()
    pre_rulebase.refreshall(dg_obj)
    return pre_rulebase
