import subprocess
from pprint import pprint
from bgpq import bgpq4, bgpq3


def makeFilter(ipType: str, peer_asn: int):
    """

    bgpq4
    
    """

    if ipType == "v4":
        filter = bgpq4(
            peer_asn,
            flags=["-4", "-A", "-b", "-l", f"as{peer_asn}_filter", f"AS{peer_asn}",],
        )
    elif ipType == "v6":
        filter = bgpq4(
            peer_asn,
            flags=["-6", "-A", "-b", "-l", f"as{peer_asn}_filter", f"AS{peer_asn}",],
        )
    else:
        exit(1)

    return filter


# filter = os.popen(f"bgpq4 -6 -b -l as{peer_asn}_filter AS{peer_asn}").read()
