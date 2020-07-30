import requests
from makeFilter import makeFilter
from pprint import pprint
from jinja2 import Environment, FileSystemLoader
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Optional
import yaml

with open("config.yml") as config:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
    configparsed = yaml.load(config, Loader=yaml.FullLoader)
    pprint(configparsed)


def templateBuild(
    ixp: str,
    ixp_id: int,
    peer_asn: int,
    peer_ip: str,
    public_ip: str,
    public_asn: int,
    password: Optional[str] = None,
):
    """
    ixp: str,
    peer_asn: int,
    peer_ip: str,
    public_ip: str,
    public_asn: int,
    password: Optional[str],

    """
    #    peer_name: str,

    peer_ip_a = ip_address(peer_ip)
    public_ip_a = ip_address(public_ip)

    file_loader = FileSystemLoader("templates")
    env = Environment(loader=file_loader)
    env.trim_blocks = True
    env.lstrip_blocks = True
    env.rstrip_blocks = True

    if type(peer_ip_a) is IPv4Address and type(public_ip_a) is IPv4Address:
        ip_type = "v4"
        template = env.get_template("./v4_template.jinja2")
    elif type(peer_ip_a) is IPv6Address and type(public_ip_a) is IPv6Address:
        ip_type = "v6"
        template = env.get_template("./v6_template.jinja2")
    else:
        exit(1)

    # PeeringDB query for ASN Name
    pdb_name_query_lookup = requests.get(
        "https://peeringdb.com/api/net",
        auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
        params={"asn": peer_asn},
    )
    if pdb_lookup.status_code == 200:
        peer_name = pdb_name_query_lookup.json()["data"][0]["name"]
        peer_id = pdb_name_query_lookup.json()["data"][0]["id"]
    else:
        exit(1)

    pdb_peer_ip_lookup_via_ix = requests.get(
        "https://peeringdb.com/api/netixlan",
        auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
        params={"net_id": peer_id},
    )

    for ixp in pdb_peer_ip_lookup_via_ix:
        if ixp["ix_id"] is ixp_id:
            if ixp["ipaddr4"] is None:
                pass
            else:
                peer_ip_4 = ixp["ipaddr4"]

            if ixp["ipaddr6"] is None:
                pass
            else:
                peer_ip_6 = ixp["ipaddr6"]
        else:
            pass
    # Make filter

    filter = makeFilter(ip_type, peer_asn)

    output = template.render(
        ixp=ixp,
        peer_asn=peer_asn,
        peer_name=peer_name,
        peer_ip=peer_ip,
        public_ip=public_ip,
        public_asn=public_asn,
        password=password,
        filter=filter,
    )
    pprint(output)
    with open("a.txt", "w") as a:
        a.write(output)

    return output
