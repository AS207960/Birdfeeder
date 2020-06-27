# /usr/bin/env python3
from templateBuild import templateBuild
from pprint import pprint
import yaml

with open("config.yml") as config:
    # The FullLoader parameter handles the conversion from YAML
    # scalar values to Python the dictionary format
    configparsed = yaml.load(config, Loader=yaml.FullLoader)
    pprint(configparsed)

PublicASN = configparsed["public"]["asn"]

for name, box in configparsed["boxes"].items():
    print(f"{name}: {box}")
    for PublicIPVersion, PublicIPAddress in box["ips"].items():
        if PublicIPVersion == "v4":
            box_v4 = PublicIPAddress
            pprint(f"{box_v4}")
        elif PublicIPVersion == "v6":
            box_v6 = PublicIPAddress
            pprint(f"{box_v6}")
        else:
            exit(1)
    for ixName, ixDetails in box["ixs"].items():
        #        print(ixName)
        #         print(ixDetails)

        #        pprint(f'{ixName}: {ixDetails}')
        for IXPIPVersion, IXPIPAddress in ixDetails["ips"].items():
            #            pprint(f"{IXPIPVersion}: {IXPIPAddress}")
            if IXPIPVersion == "v4":
                ixp_name = ixName
                ixp_v4 = IXPIPAddress
                pprint(f"{ixp_name}: {ixp_v4}")
            elif IXPIPVersion == "v6":
                ixp_name = ixName
                ixp_v6 = IXPIPAddress
                pprint(f"{ixp_name}: {ixp_v6}")
            else:
                exit(1)

        for peerASN, peerDetails in (
            ixDetails["peers"].items() if ixDetails["peers"] else []
        ):
            pprint(f"{peerASN}: {peerDetails}")
            for PeerIPVersion, PeerIPAddress in peerDetails["ips"].items():
                templateBuild(
                    ixp_name, peerASN, PeerIPAddress, PublicIPAddress, PublicASN
                )
#                pprint(f"{IXPIPVersion}: {IXPIPAddress}")
