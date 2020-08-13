import requests
from makeFilter import makeFilter
from pprint import pprint
from jinja2 import Environment, FileSystemLoader
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Optional
import yaml


def pdb(ixp_id: int, peer_asn: int, local_asn: int):
    try:
        with open("config.yml", "r") as config:
            # The FullLoader parameter handles the conversion from YAML
            # scalar values to Python the dictionary format
            configparsed = yaml.load(config, Loader=yaml.FullLoader)
            config.close()
    except Exception as e:
        raise (e)

    returnables = {}
    returnables["peer"] = {}
    returnables["peer"]["asn"] = peer_asn
    returnables["local"] = {}
    returnables["local"]["asn"] = local_asn

    # PeeringDB query for Peer Network
    try:
        pdb_peer_net_query = requests.get(
            "https://peeringdb.com/api/net",
            auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
            params={"asn": peer_asn},
        )
        pdb_peer_net_query.raise_for_status()
    except Exception as e:
        raise (e)
    else:
        peer_net_id = pdb_peer_net_query.json()["data"][0]["id"]
        returnables["peer"]["name"] = pdb_peer_net_query.json()["data"][0]["name"]
        returnables["peer"]["as_set"] = pdb_peer_net_query.json()["data"][0][
            "irr_as_set"
        ]
        returnables["peer"]["max_prefixes_4"] = pdb_peer_net_query.json()["data"][0][
            "info_prefixes4"
        ]
        returnables["peer"]["max_prefixes_6"] = pdb_peer_net_query.json()["data"][0][
            "info_prefixes6"
        ]

    # PeeringDB query for Peer Net on IX
    try:
        pdb_peer_lookup_on_ix_req = requests.get(
            "https://peeringdb.com/api/netixlan",
            auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
            params={"net_id": peer_net_id},
        )
        pdb_peer_lookup_on_ix_req.raise_for_status()
    except Exception as e:
        raise (e)
    else:
        pdb_peer_lookup_on_ix = pdb_peer_lookup_on_ix_req.json()["data"]

    # PeeringDB query for Local Network
    try:
        pdb_local_net_query = requests.get(
            "https://peeringdb.com/api/net",
            auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
            params={"asn": configparsed["public"]["asn"]},
        )
        pdb_local_net_query.raise_for_status()
    except Exception as e:
        raise (e)
    else:
        local_net_id = pdb_local_net_query.json()["data"][0]["id"]
        returnables["local"]["name"] = pdb_local_net_query.json()["data"][0]["name"]
        returnables["local"]["as_set"] = pdb_local_net_query.json()["data"][0][
            "irr_as_set"
        ]
        returnables["local"]["max_prefixes_4"] = pdb_local_net_query.json()["data"][0][
            "info_prefixes4"
        ]
        returnables["local"]["max_prefixes_6"] = pdb_local_net_query.json()["data"][0][
            "info_prefixes6"
        ]

    # PeeringDB query for Local Net on IX
    try:
        pdb_local_lookup_on_ix_req = requests.get(
            "https://peeringdb.com/api/netixlan",
            auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
            params={"net_id": local_net_id},
        )
        pdb_local_lookup_on_ix_req.raise_for_status()
    except Exception as e:
        raise (e)
    else:
        pdb_local_lookup_on_ix = pdb_local_lookup_on_ix_req.json()["data"]

    # Peer IPs on IX
    for ixp in pdb_peer_lookup_on_ix:
        if ixp["ix_id"] is ixp_id:
            if ixp["ipaddr4"] is None:
                pass
            else:
                returnables["peer"]["ipv4"] = ixp["ipaddr4"]

            if ixp["ipaddr6"] is None:
                pass
            else:
                returnables["peer"]["ipv6"] = ixp["ipaddr6"]

        else:
            pass

    # Local IPs on IX
    for ixp in pdb_local_lookup_on_ix:
        if ixp["ix_id"] is ixp_id:
            if ixp["ipaddr4"] is None:
                pass
            else:
                returnables["local"]["ipv4"] = ixp["ipaddr4"]

            if ixp["ipaddr6"] is None:
                pass
            else:
                returnables["local"]["ipv6"] = ixp["ipaddr6"]
        else:
            pass

    # pprint(returnables)
    return returnables
