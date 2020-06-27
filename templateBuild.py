import requests
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
    ixp: str, peer_asn: int, peer_ip: str, public_ip: str, public_asn: int, password: Optional[str] = None,
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
        template = env.get_template("./v4_template.jinja2")
    elif type(peer_ip_a) is IPv6Address and type(public_ip_a) is IPv6Address:
        template = env.get_template("./v6_template.jinja2")
    else:
        exit(1)

    # PeeringDB query for ASN Name
    pdb_lookup = requests.get(
        "https://peeringdb.com/api/net",
        auth=(configparsed["peeringdb"]["user"], configparsed["peeringdb"]["pass"]),
        params={"asn": peer_asn},
    )
    if pdb_lookup.status_code == 200:
        peer_name = pdb_lookup.json()["data"][0]["name"]
    else:
        exit(1)

    output = template.render(
        ixp=ixp,
        peer_asn=peer_asn,
        peer_name=peer_name,
        peer_ip=peer_ip,
        public_ip=public_ip,
        public_asn=public_asn,
        password=password,
    )
    print(output)
    return(output)
