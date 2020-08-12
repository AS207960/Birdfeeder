import requests
from makeFilter import makeFilter
from pdb import pdb
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

    test = pdb(input("ixp id: "), input("peer asn: "), input("local asn: "))
    pprint(test)

    file_loader = FileSystemLoader("templates")
    env = Environment(loader=file_loader)
    env.trim_blocks = True
    env.lstrip_blocks = True
    env.rstrip_blocks = True

    if type(ip_address(test["peer"]["ipv4"])) is IPv4Address and type(ip_address(test["local"]["ipv4"])) is IPv4Address:
        ip_type = "v4"
        template = env.get_template("./v4_template.jinja2")
    elif type(ip_address(test["peer"]["ipv6"])) is IPv6Address and type(ip_address(test["local"]["ipv6"])) is IPv6Address:
        ip_type = "v6"
        template = env.get_template("./v6_template.jinja2")
    else:
        exit(1)

    filter = makeFilter(ip, peer_asn)

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
