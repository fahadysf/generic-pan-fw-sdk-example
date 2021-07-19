import os
import sys
import getpass
import coloredlogs
import logging
import logging.handlers as lh
import xml.dom.minidom as minidom
import xmltodict
from xml.etree import ElementTree

try:
    import yaml
except ImportError:
    raise ValueError(
        "PyYAML module not available, please install it by running 'python3 -m pip install PyYAML'")


try:
    from panos.firewall import Firewall
    from panos.panorama import Panorama
except ImportError:
    raise ValueError(
        "pan-os-python module not available, please install it by running 'python3 -m pip install pan-os-python'")


def load_config(config_file='config.yml'):
    import yaml
    try:
        with open(config_file, "r") as ymlfile:
            cfg = yaml.safe_load(ymlfile)
            return cfg
    except Exception as e:
        print("Config file 'config.yml' not found or couldn't be opened.")
        raise e
        exit(1)


def get_config_param(dictpath, param):
    if param not in dictpath.keys():
        return None
    else:
        return dictpath[param]
    return None


def save_config(cfgdict, config_file='config.yml'):
    with open(config_file, 'w') as outfile:
        yaml.dump(cfgdict, outfile, default_flow_style=False)
    return


def get_credentials(panorama_addr):
    app_log.info(
        f"API Key for firewall {panorama_addr} is not defined in config.yml")
    print("Please enter the username and password for the user for the API access.")
    print("Configuration file (config.yml) will be updated automatically once the API Key is created.")
    username = input("Enter username: ")
    password = getpass.getpass()
    return username, password


def gen_api_key(panorama_addr, username='', password=''):
    if not (len(username) or len(password)):
        username, password = get_credentials(panorama_addr)
        try:
            panorama_obj = Panorama(panorama_addr,
                                    api_username=username,
                                    api_password=password)
            if panorama_obj.api_key:
                app_log.info(
                    f"API Key generated for firewall {panorama_addr} for username {username}")
                return panorama_obj, panorama_obj.api_key
        except Exception as e:
            app_log.error("Error generating API Key")
            app_log.exception(f"Got exception in gen_api_key: {e}")
            exit(1)


def initialize_fw_objs(cfgdict):
    """[summary]

    Arguments:
        cfgdict {[type]} -- [description]

    Returns:
        [type] -- [description]
    """
    if 'firewalls' in cfgdict.keys():
        fw_dict = cfgdict['firewalls']
    else:
        fw_dict = {}
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
                fw_obj_ha = Firewall(
                    fw2, api_key=fw_dict[fw]['api_key'])
                fw_obj.set_ha_peers(fw_obj_ha)

            fw_objs.append(fw_obj)

            if config_dirty:
                cfgdict['firewalls'] = fw_dict
                save_config(cfgdict)
        except BaseException as e:
            app_log.error(
                f"Could not initialize conneciton to {fw}: {e.message}")

    return fw_objs


def initialize_panorama_objs(cfgdict):
    """[summary]

    Arguments:
        cfgdict {[type]} -- [description]

    Returns:
        [type] -- [description]
    """
    if 'panoramas' in cfgdict.keys():
        panorama_dict = cfgdict['panoramas']
    else:
        panorama_dict = {}
    panorama_objs = list()

    # Check for API Keys in Config
    config_dirty = 0
    for panorama in panorama_dict.keys():
        app_log.info(f"Connecting to Panorama {panorama}")
        try:
            if ('api_key' not in panorama_dict[panorama].keys()) or (panorama_dict[panorama]['api_key'] == None) or (panorama_dict[panorama]['api_key'] == ''):
                panorama_obj, api_key = gen_api_key(panorama)
                panorama_objs.append(panorama_obj)
                panorama_dict[panorama]['api_key'] = api_key
                config_dirty = 1
            else:
                panorama_obj = Panorama(
                    panorama, api_key=panorama_dict[panorama]['api_key'], timeout=120)

            if get_config_param(panorama_dict[panorama], 'ha_peer_ip') != None:
                panorama2 = panorama_dict[panorama]['ha_peer_ip']
                panorama_obj_ha = Panorama(
                    panorama2, api_key=panorama_dict[panorama]['api_key'])
                panorama_obj.set_ha_peers(panorama_obj_ha)

            panorama_objs.append(panorama_obj)

            if config_dirty:
                cfgdict['panoramas'] = panorama_dict
                save_config(cfgdict)
        except BaseException as e:
            app_log.error(
                f"Could not initialize conneciton to {panorama}: {e.message}")

    return panorama_objs


def prettify(elem):
    """Return a pretty-printed XML string for the Element.
    """
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    data_str = reparsed.toprettyxml(indent="\t")
    data_str = os.linesep.join([s for s in data_str.splitlines() if s.strip()])
    return data_str


def get_xml_op(obj, cmd="show system info", cmd_xml=True, xml=False):
    data = obj.op(cmd, cmd_xml=cmd_xml)
    if xml:
        return ElementTree.tostring(data, encoding="unicode", method="xml")
    else:
        return xmltodict.parse(ElementTree.tostring(data, encoding='UTF-8', method='xml'))


# Read Config
app_log = logging.getLogger('root')
if '-debug' in sys.argv:
    app_log.setLevel(logging.DEBUG)
else:
    app_log.setLevel(logging.INFO)

try:
    cfgdict = load_config()
    if not os.path.exists(cfgdict['log_path']):
        os.mkdir(cfgdict['log_path'])
except BaseException as e:
    app_log.error(
        "Unable to load configuration. Please ensure config.yml exists and has no errors")
    raise(e)

# Setup logging
log_file = os.path.join(cfgdict['log_path'], 'ngfw-control-script.log')
log_rotation_size = 10 * 1024 * 1024  # Size in bytes (This is 10 MB)
log_formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')
# File Handler
file_handler = lh.RotatingFileHandler(
    log_file, maxBytes=log_rotation_size, backupCount=3)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
app_log.addHandler(file_handler)
# Colored Console Logging
coloredlogs.install()
# app_log.addHandler(console_handler) # no longer needed with coloredlogs
