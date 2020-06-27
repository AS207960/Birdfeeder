import subprocess
from pprint import pprint


def makeFilter(ipType: str, peer_asn: int):
    """

    bgpq4
    
    """

    if ipType == "v4":
        filter = subprocess.run(
            [
                "/usr/bin/env",
                "bgpq4",
                "-4",
                "-b",
                "-l",
                f"as{peer_asn}_filter",
                f"AS{peer_asn}",
            ],
            capture_output=True,
        )
    elif ipType == "v6":
        filter = subprocess.run(
            [
                "/usr/bin/env",
                "bgpq4",
                "-6",
                "-b",
                "-l",
                f"as{peer_asn}_filter",
                f"AS{peer_asn}",
            ],
            capture_output=True,
        )
    else:
        exit(1)

    return filter.stdout.splitlines()


# filter = os.popen(f"bgpq4 -6 -b -l as{peer_asn}_filter AS{peer_asn}").read()
