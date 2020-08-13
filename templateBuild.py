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

    test = pdb(
        int(input("ixp id: ")), int(input("peer asn: ")), int(input("local asn: "))
    )
    pprint(test)

    output_final = """"""

    file_loader = FileSystemLoader("templates")
    env = Environment(loader=file_loader)
    env.trim_blocks = True
    env.lstrip_blocks = True
    env.rstrip_blocks = True

    if (
        type(ip_address(test["peer"]["ipv4"])) is IPv4Address
        and type(ip_address(test["local"]["ipv4"])) is IPv4Address
    ):
        v4 = True
        local_v4_ip = test["local"]["ipv4"]
        peer_v4_ip = test["peer"]["ipv4"]
    else:
        pass
    if (
        type(ip_address(test["peer"]["ipv6"])) is IPv6Address
        and type(ip_address(test["local"]["ipv6"])) is IPv6Address
    ):
        v6 = True
        local_v6_ip = test["local"]["ipv6"]
        peer_v6_ip = test["peer"]["ipv6"]
    else:
        pass

    if v4 == True:
        template = env.get_template("./v4_template.jinja2")

        filter = makeFilter("127.0.0.1", peer_asn)
        print(filter)

        output = template.render(
            ixp=ixp,
            peer_asn=test["peer"]["asn"],
            peer_name=test["peer"]["name"],
            peer_ip=peer_v4_ip,
            public_ip=local_v4_ip,
            public_asn=test["local"]["asn"],
            password=password,
            filter=filter,
        )
        pprint(output)

        output_final = output_final + "\n" + output

    else:
        pass

    if v6 == True:
        template = env.get_template("./v6_template.jinja2")

        filter = makeFilter("::1", peer_asn)

        output = template.render(
            ixp=ixp,
            peer_asn=test["peer"]["asn"],
            peer_name=test["peer"]["name"],
            peer_ip=peer_v4_ip,
            public_ip=local_v4_ip,
            public_asn=test["local"]["asn"],
            password=password,
            filter=filter,
        )
        pprint(output)

        output_final = output_final + "\n" + output

    else:
        pass

    with open("a.txt", "w") as a:
        a.write(output_final)
        a.close()

    return output_final
