import subprocess
from pprint import pprint
from bgpq import bgpq4, bgpq3
from ipaddress import IPv4Address, IPv6Address, ip_address


def makeFilter(ip: str, peer_asn: int):
    """

    bgpq4
    
    """

    ip_parsed = ip_address(ip)

    if type(ip_parsed) is IPv4Address:
        filter = bgpq4(
            peer_asn,
            flags=["-4", "-A", "-b", "-l", f"as{peer_asn}_filter", f"AS{peer_asn}",],
        )
    elif type(ip_parsed) is IPv6Address:
        filter = bgpq4(
            peer_asn,
            flags=["-6", "-A", "-b", "-l", f"as{peer_asn}_filter", f"AS{peer_asn}",],
        )
    else:
        raise ("IP/ASN is incorrect")

    return filter


# filter = os.popen(f"bgpq4 -6 -b -l as{peer_asn}_filter AS{peer_asn}").read()
