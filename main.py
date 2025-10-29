#!/usr/bin/python3

import json
import os
import sys


def read_nekoray_profiles():
    """
    Function to read the nekoray profile json files
    :return: Profile json files contents
    """
    home_directory = os.path.expanduser("~/.config/nekoray/config/profiles")  # Get the user's home directory path
    contents = os.listdir(home_directory)  # List all files and directories in the home directory

    profiles = []
    for item in contents:
        file_path = os.path.join(home_directory, item)
        if os.path.isfile(file_path) and os.path.splitext(item)[1] == ".json":
            try:
                with open(file_path, "r") as f:
                    profiles.append(json.load(f))
            except FileNotFoundError:
                print(f"Error: File not found at {file_path}", file=sys.stderr)
            except json.JSONDecodeError:
                print(f"Error: Invalid JSON in file {file_path}", file=sys.stderr)
    profiles.sort(key=lambda x: x["id"])
    return profiles


def safe_get_nested_value(obj, keys):
    """
    Function to safely access nested dictionary values
    :param obj: Object to be accessed
    :param keys: List of keys to be accessed
    :return: Value of key if it exists
    """
    current = obj
    try:
        for key in keys:
            current = current[key]
        return current
    except KeyError:
        return None


def filter_null_values(obj):
    """
    Function to filter out null values from json object
    :param obj: Json object to be filtered
    :return: Filtered json object
    """
    if isinstance(obj, dict):
        return {k: filter_null_values(v) for k, v in obj.items() if v is not None}
    elif isinstance(obj, list):
        return [filter_null_values(elem) for elem in obj if elem is not None]
    else:
        return obj


def convert_json_format(obj):
    """
    Function to convert to sing-box json format from nekoray profile json
    :param obj: Nekoray profile json
    :return: Converted to sing-box json format object
    """
    ident = safe_get_nested_value(obj, ["id"])
    tag = safe_get_nested_value(obj, ["bean", "name"])
    if not tag:
        print(f"Error: Missing tag at nekoray profile object {obj}", file=sys.stderr)
        return

    server = safe_get_nested_value(obj, ["bean", "addr"])
    if not server:
        print(f"Missing server address at nekoray profile object {obj}", file=sys.stderr)
        return

    scheme = safe_get_nested_value(obj, ["type"])
    if not scheme:
        print(f"Missing connection schema at nekoray profile object {obj}", file=sys.stderr)
        return

    uuid = safe_get_nested_value(obj, ["bean", "pass"])
    if not uuid:
        print(f"Missing connection uid at nekoray profile object {obj}", file=sys.stderr)
        return

    reality = None
    if bool(safe_get_nested_value(obj, ["bean", "stream", "pbk"])):
        reality = {
            "enabled": True,
            "public_key": safe_get_nested_value(obj, ["bean", "stream", "pbk"]),
            "short_id": safe_get_nested_value(obj, ["bean", "stream", "sid"]),
            # "spider_x": safe_get_nested_value(obj, ["bean", "stream", "spx"]) # NOT AVAILABLE FOR NOW
        }

    transport = None
    if bool(safe_get_nested_value(obj, ["bean", "stream", "h_type"])):
        transport = {
            "headers": {
                "Host": safe_get_nested_value(obj, ["bean", "stream", "host"]),
            },
            "type": safe_get_nested_value(obj, ["bean", "stream", "h_type"]),
            "method": "GET",
            "path": safe_get_nested_value(obj, ["bean", "stream", "path"]),
        }

    alpn = None
    if bool(safe_get_nested_value(obj, ["bean", "stream", "alpn"])):
        alpn = safe_get_nested_value(obj, ["bean", "stream", "alpn"]).split(',')

    # todo: different connection methods
    # todo: multiplexing
    result = {
        "tag": str(ident) + " - " + tag,
        "server": server,
        "server_port": int(safe_get_nested_value(obj, ["bean", "port"])) or 443,
        "type": scheme,
        "uuid": uuid,
        "flow": safe_get_nested_value(obj, ["bean", "flow"]),
        "domain_strategy": None,
        "packet_encoding": safe_get_nested_value(obj, ["bean", "stream", "pac_enc"]),
        "tls": {
            "enabled": safe_get_nested_value(obj, ["bean", "stream", "sec"]) == "tls",
            "insecure": safe_get_nested_value(obj, ["bean", "stream", "insecure"]) or False,
            "server_name": safe_get_nested_value(obj, ["bean", "stream", "sni"]),
            "reality": reality,
            "alpn": alpn,
            "certificate": safe_get_nested_value(obj, ["bean", "stream", "cert"]),
            "utls": {
                "enabled": bool(safe_get_nested_value(obj, ["bean", "stream", "utls"])),
                "fingerprint": safe_get_nested_value(obj, ["bean", "stream", "utls"])
            }
        },
        "transport": transport,
    }

    if bool(safe_get_nested_value(obj, ["bean", "c_out"])):
        config = json.loads(safe_get_nested_value(obj, ["bean", "c_out"]))
        for key, value in config.items():
            result[key] = value

    return filter_null_values(result)


def same_outbound_exists(outbounds, item):
    """
    Function to check if an outbound configuration already exists
    :param outbounds: List of outbound configurations
    :param item: Item to check
    :return: True if outbound configuration exists
    """
    for outbound in outbounds:
        if outbound["server"] == item["server"] and outbound["server_port"] == item["server_port"] and \
                outbound["type"] == item["type"] and outbound["uuid"] == item["uuid"]:
            return True
    return False


def get_urltest(outbounds):
    """
    Function to get urltest configuration
    :param outbounds: Current outbound configurations
    :return: Urltest configuration
    """
    return {
        "type": "urltest",
        "tag": "auto",
        "outbounds": [val["tag"] for val in outbounds],
        "url": "https://www.gstatic.com/generate_204",
        "interval": "3m",
        "tolerance": 50,
        "idle_timeout": "30m",
        "interrupt_exist_connections": False
    }


def main():
    """
    Main function
    Prints result to console output
    :return: Nothing
    """
    profiles = read_nekoray_profiles()
    outbounds = []
    for profile in profiles:
        outbound = convert_json_format(profile)
        if outbound:
            if not same_outbound_exists(outbounds, outbound):
                outbounds.append(outbound)
            else:
                print(f"Error: Outbound already exists {outbound}", file=sys.stderr)

    outbounds.append(get_urltest(outbounds))
    result = {
        "outbounds": [
            {
                "type": "direct",
                "tag": "direct-out"
            },
            {
                "type": "dns",
                "tag": "dns-out"
            },
            *outbounds
        ],
    }
    print(json.dumps(result, indent=2), file=sys.stdout)


if __name__ == "__main__":
    main()
