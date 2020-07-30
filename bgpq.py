import subprocess
from typing import Optional


def bgpq3(peer_asn: int, flags: Optional[list] = None):

    """
    bgpq3 wrapper
    -------------

    Paramaters
    ----------
    peer_asn : int 
        Peer's ASN as intiger
    flags : list, optional
        Optional flags as List

    Returns
    -------
    str
        Output of generated bgpq3 command

    Notes
    -----
    Uses /usr/bin/env to use the correct bgpq3 binary

    """

    if flags == None:
        flags = [
            "-4",
            "-A",
            "-b",
            "-l",
            f"as{peer_asn}_filter",
            f"AS{peer_asn}",
        ]

    output = subprocess.check_output(["/usr/bin/env", "bgpq3", *flags],)

    return output.rstrip().decode("utf-8")


def bgpq4(peer_asn: int, flags: Optional[list] = None):

    """
    bgpq4 wrapper
    -------------

    Paramaters
    ----------
    peer_asn : int 
        Peer's ASN as intiger
    flags : list, optional
        Optional flags as List

    Returns
    -------
    str
        Output of generated bgpq4 command

    Notes
    -----
    
    Uses /usr/bin/env to use the correct bgpq4 binary

    """

    if flags == None:
        flags = [
            "-4",
            "-A",
            "-b",
            "-l",
            f"as{peer_asn}_filter",
            f"AS{peer_asn}",
        ]

    output = subprocess.check_output(["/usr/bin/env", "bgpq4", *flags],)

    return output.rstrip().decode("utf-8")
