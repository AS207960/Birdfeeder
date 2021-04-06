# /usr/bin/env python3
from __future__ import annotations
import yaml
import dataclasses
import enum
import requests
import os
import sys
import json
import subprocess
import typing
import jinja2
import functools
import concurrent.futures


class Relationship(enum.Enum):
    TRANSIT = 0
    PEERING = 1
    DOWNSTREAM = 2
    RS = 3


@dataclasses.dataclass(eq=True, frozen=True)
class Prefix:
    network: str
    prefix: int
    le: typing.Optional[int]
    ge: typing.Optional[int]


@dataclasses.dataclass
class ASFilter:
    as_filter: typing.Set[int]
    v4_prefixes: typing.Set[Prefix]
    v6_prefixes: typing.Set[Prefix]

    def union(self, other: ASFilter):
        return ASFilter(
            as_filter=self.as_filter.union(other.as_filter),
            v4_prefixes=self.v4_prefixes.union(other.v4_prefixes),
            v6_prefixes=self.v6_prefixes.union(other.v6_prefixes),
        )


@dataclasses.dataclass
class Network:
    pdb_id: str
    name: str
    asn: int
    as_macro: str
    max_v4: int
    max_v6: int
    filter: typing.Optional[ASFilter]


@dataclasses.dataclass
class RouterIPs:
    v4_ip: typing.Optional[str]
    v6_ip: typing.Optional[str]
    peer_asn: typing.Optional[int]
    password: typing.Optional[str]
    multihop: typing.Optional[int]


@dataclasses.dataclass
class IXPPeer:
    routers: typing.List[RouterIPs]
    rs_peer: bool


@dataclasses.dataclass
class PNIPeer:
    routers: typing.List[RouterIPs]
    export_extra: typing.Optional[str]
    import_extra: typing.Optional[str]


@dataclasses.dataclass
class Peer:
    relationship: Relationship
    ixps: typing.Dict[str, IXPPeer]
    pnis: typing.Dict[str, PNIPeer]
    network: Network


@dataclasses.dataclass
class IXP:
    pdb_id: str
    name: str
    rs: typing.Optional[Network]
    rs_routers: typing.List[RouterIPs]
    peers: typing.Set[int]


@dataclasses.dataclass
class Router:
    name: str
    local_asn: int
    router_id: str
    prefsrc_v4: typing.Optional[str]
    prefsrc_v6: typing.Optional[str]
    pnis: typing.Set[int]
    ixps: typing.Dict[str, RouterIPs]


def make_dirs_and_open(path, *args):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, *args)


with open("config.yml") as config:
    config_parsed = yaml.load(config, Loader=yaml.FullLoader)

template_file_loader = jinja2.FileSystemLoader("templates")
jinja2_env = jinja2.Environment(loader=template_file_loader)
jinja2_env.trim_blocks = True
jinja2_env.lstrip_blocks = True
jinja2_env.rstrip_blocks = True
jinja2_env.keep_trailing_newline = True

global_template = jinja2_env.get_template("./global_template.jinja2")
own_template = jinja2_env.get_template("./own_template.jinja2")
router_template = jinja2_env.get_template("./router_template.jinja2")
executor1 = concurrent.futures.ThreadPoolExecutor(max_workers=25)
executor2 = concurrent.futures.ThreadPoolExecutor(max_workers=3)


def get_pdb_obj(path: str) -> typing.List:
    r = requests.get(f"https://www.peeringdb.com/api/{path}")
    if r.status_code == 404:
        return []
    r.raise_for_status()
    return r.json().get("data", [])


def run_bgpq4(sources, *args):
    tries = 0
    while True:
        try:
            p = subprocess.run(
                ["bgpq4", "-j", "-S", sources, "-l", "out", "-h", "whois.radb.net", *args],
                capture_output=True, check=True, text=True
            )
            d = json.loads(p.stdout)["out"]
            return d
        except subprocess.CalledProcessError as e:
            print(f"Failed to get IRR data with command {' '.join(e.cmd)}:\n{e.output}\n{e.stderr}")
            if tries < 3:
                tries += 1
                print("Retrying...")
            else:
                break

    sys.exit(1)


def get_prefix_list(as_macro: typing.Tuple[str, str], is_rs=False) -> ASFilter:
    sources, as_macro = as_macro

    def map_prefix(p_obj):
        network, prefix = p_obj["prefix"].rsplit("/", 1)
        prefix = int(prefix)
        return Prefix(
            network=network,
            prefix=prefix,
            le=None if p_obj["exact"] else p_obj["less-equal"],
            ge=None if p_obj["exact"] else (p_obj["greater-equal"] if "greater-equal" in p_obj else prefix),
        )

    try:
        macro = [as_macro]
        if is_rs:
            macro.append("EXCEPT")
            macro.extend(rs_exclude_as_sets)
        v4_fut = executor2.submit(run_bgpq4, sources, "-A", *macro)
        v6_fut = executor2.submit(run_bgpq4, sources, "-A", "-6", *macro)
        as_fut = executor2.submit(run_bgpq4, sources, "-t", *macro)
        v4_prefixes = set(map(map_prefix, v4_fut.result()))
        v6_prefixes = set(map(map_prefix, v6_fut.result()))
        as_filter = set(as_fut.result())
    except subprocess.CalledProcessError as e:
        print(f"Failed to get IRR data with command {' '.join(e.cmd)}:\n{e.output}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Failed parse bgpq4 output: {e}")
        sys.exit(1)

    return ASFilter(
        as_filter=as_filter,
        v4_prefixes=v4_prefixes,
        v6_prefixes=v6_prefixes
    )


def get_asn_data(asn: int, make_filters=True, is_rs=False) -> typing.Tuple[Network, typing.Dict]:
    asn_data = get_pdb_obj(f"net?asn={asn}&depth=2")
    if len(asn_data) != 1:
        print(f"Unable to find ASN {asn}")
        sys.exit(1)
    asn_data = asn_data[0]

    as_macros = asn_data["irr_as_set"] if asn_data["irr_as_set"] else f"AS{str(asn)}"
    as_macros = as_macros.split(" ")

    def extract_sources(m):
        parts = m.split("::", 1)
        if len(parts) == 1:
            return "RADB,RIPE,APNIC,AFRINIC,ARIN", parts[0]
        else:
            return parts[0], parts[1]

    as_macros = list(map(extract_sources, as_macros))

    if not is_rs:
        for _, macro in as_macros:
            rs_exclude_as_sets.add(macro)

    if make_filters:
        prefix_list = functools.reduce(
            lambda a, b: a.union(b),
            map(lambda m: get_prefix_list(m, is_rs), as_macros)
        )
    else:
        print(f"Not getting prefix lists for AS{asn}")
        prefix_list = None

    return Network(
        pdb_id=asn_data["id"],
        asn=asn_data["asn"],
        name=asn_data["name"],
        as_macro=asn_data["irr_as_set"],
        max_v4=asn_data["info_prefixes4"],
        max_v6=asn_data["info_prefixes6"],
        filter=prefix_list
    ), asn_data


ixps: typing.Dict[str, IXP] = {}
peers: typing.Dict[int, Peer] = {}
routers: typing.Dict[str, Router] = {}
rs_exclude_as_sets: typing.Set[str] = set()

print(f"Fetching data for own network")
own_network, _ = get_asn_data(config_parsed["about"]["asn"])


def map_ixp(ixp_id: str, ixp: dict) -> typing.Tuple[str, IXP]:
    print(f"Fetching IXP data for {ixp_id}")

    if "rs_asn" in ixp:
        rs_asn = ixp["rs_asn"]
        try:
            rs_asn = int(rs_asn)
        except ValueError:
            print(f"Invalid RS ASN: {rs_asn}")
            sys.exit(1)
    else:
        rs_asn = None

    ixp_data = get_pdb_obj(f"ix/{ixp['pdb_id']}")
    if len(ixp_data) != 1:
        print(f"Unable to find IXP {ixp_id}")
        sys.exit(1)
    ixp_data = ixp_data[0]

    if rs_asn:
        rs, rs_data = get_asn_data(rs_asn, is_rs=True)

        rs_routers = list(map(
            lambda l: RouterIPs(
                v4_ip=l["ipaddr4"] if l["ipaddr4"] else None,
                v6_ip=l["ipaddr6"] if l["ipaddr6"] else None,
                peer_asn=None,
                password=None,
                multihop=None
            ),
            filter(
                lambda l: l["ix_id"] == ixp["pdb_id"] and l["asn"] == rs_asn and l["operational"],
                rs_data["netixlan_set"]
            )
        ))
    else:
        rs = None
        rs_routers = []

    return ixp_id, IXP(
        pdb_id=ixp_data["id"],
        name=ixp_data["name"],
        rs=rs,
        rs_routers=rs_routers,
        peers=set()
    )


def map_peer(peer_asn: str, peer_data: dict) -> typing.Tuple[int, Peer]:
    try:
        peer_asn = int(peer_asn)
    except ValueError:
        print(f"Invalid ASN: {peer_asn}")
        sys.exit(1)

    if peer_data["relationship"] == "downstream":
        relationship = Relationship.DOWNSTREAM
    elif peer_data["relationship"] == "peering":
        relationship = Relationship.PEERING
    elif peer_data["relationship"] == "transit":
        relationship = Relationship.TRANSIT
    else:
        print(f"Invalid relationship: {peer_data['relationship']}")
        sys.exit(1)

    print(f"Fetching peer data for AS{peer_asn}")

    network, asn_data = get_asn_data(peer_asn, make_filters=relationship != Relationship.TRANSIT)
    asn_ixps = {}
    asn_pnis = {}

    if "ixps" in peer_data:
        for ixp_id in peer_data["ixps"]:
            if ixp_id not in ixps:
                print(f"Invalid IXP: {ixp_id}")
                sys.exit(1)

            ixp_data = ixps[ixp_id]
            rs_peer = False
            ixp_routers = []

            for l in filter(
                    lambda l: l["ix_id"] == ixp_data.pdb_id and l["asn"] == peer_asn and l["operational"],
                    asn_data["netixlan_set"]
            ):
                ixp_routers.append(RouterIPs(
                    v4_ip=l["ipaddr4"] if l["ipaddr4"] else None,
                    v6_ip=l["ipaddr6"] if l["ipaddr6"] else None,
                    peer_asn=None,
                    password=None,
                    multihop=None
                ))
                if l["is_rs_peer"]:
                    rs_peer = True

            ixp_data.peers.add(peer_asn)
            asn_ixps[ixp_id] = IXPPeer(
                routers=ixp_routers,
                rs_peer=rs_peer
            )

    if "pnis" in peer_data:
        for router_id, pni_data in peer_data["pnis"].items():
            routers[router_id].pnis.add(peer_asn)
            pni_routers = list(map(lambda r: RouterIPs(
                v4_ip=r["v4"] if r.get("v4") else None,
                v6_ip=r["v6"] if r.get("v6") else None,
                peer_asn=int(r["peer_asn"]) if r.get("peer_asn") else None,
                password=r["password"] if r.get("password") else None,
                multihop=int(r["multihop"]) if r.get("multihop") else None,
            ), pni_data["routers"]))

            asn_pnis[router_id] = PNIPeer(
                routers=pni_routers,
                export_extra=pni_data.get("export_extra"),
                import_extra=pni_data.get("import_extra"),
            )

    return peer_asn, Peer(
        relationship=relationship,
        ixps=asn_ixps,
        pnis=asn_pnis,
        network=network
    )


for router_name, router in config_parsed["routers"].items():
    local_asn = router["local_asn"]
    try:
        local_asn = int(local_asn)
    except ValueError:
        print(f"Invalid ASN: {local_asn}")
        sys.exit(1)

    routers_ixps = {}
    if "ixps" in router:
        for ixp_id, ixp_data in router["ixps"].items():
            routers_ixps[ixp_id] = RouterIPs(
                v4_ip=ixp_data["ips"]["v4"] if ixp_data["ips"].get("v4") else None,
                v6_ip=ixp_data["ips"]["v6"] if ixp_data["ips"].get("v6") else None,
                peer_asn=None,
                password=None,
                multihop=None
            )

    routers[router_name] = Router(
        name=router_name,
        local_asn=local_asn,
        router_id=router.get("router_id"),
        prefsrc_v4=router["prefsrc"].get("v4") if "prefsrc" in router else None,
        prefsrc_v6=router["prefsrc"].get("v6") if "prefsrc" in router else None,
        pnis=set(),
        ixps=routers_ixps
    )

for ixp_id, ixp_obj in config_parsed["ixps"].items():
    ixps[ixp_id] = IXP(
        pdb_id=ixp_obj["pdb_id"],
        name="",
        rs=None,
        rs_routers=[],
        peers=set()
    )

for peer_asn, peer_obj in executor1.map(lambda p: map_peer(*p), config_parsed["peers"].items()):
    peers[peer_asn] = peer_obj

for ixp_id, ixp_obj in executor1.map(lambda i: map_ixp(*i), config_parsed["ixps"].items()):
    ixps[ixp_id].pdb_id = ixp_obj.pdb_id
    ixps[ixp_id].name = ixp_obj.name
    ixps[ixp_id].rs = ixp_obj.rs
    ixps[ixp_id].rs_routers = ixp_obj.rs_routers

global_output = own_template.render(
    as_filter=own_network.filter.as_filter,
    prefix_filter_v4=own_network.filter.v4_prefixes,
    prefix_filter_v6=own_network.filter.v6_prefixes,
)

for router in routers.values():
    print(f"Generating config for {router.name}")

    incs = []

    for pni_asn in router.pnis:
        peer = peers[pni_asn]
        pni = peer.pnis[router.name]

        pni_output = router_template.render(
            ixp="pni",
            ixp_name="PNI",
            peer_asn=peer.network.asn,
            peer_name=peer.network.name,
            our_v4_ip="",
            our_v6_ip="",
            our_asn=own_network.asn,
            local_asn=router.local_asn,
            relationship=Relationship.RS,
            as_filter=peer.network.filter.as_filter if peer.network.filter else None,
            v4_prefix_filter=peer.network.filter.v4_prefixes if peer.network.filter else None,
            v6_prefix_filter=peer.network.filter.v6_prefixes if peer.network.filter else None,
            max_prefix_v4=peer.network.max_v4 if peer.relationship != Relationship.TRANSIT else None,
            max_prefix_v6=peer.network.max_v6 if peer.relationship != Relationship.TRANSIT else None,
            routers=pni.routers,
        )

        with make_dirs_and_open(f"./out/{router.name}/pnis/as{peer.network.asn}.conf", "w") as f:
            f.write(pni_output)
        incs.append(f"pnis/as{peer.network.asn}.conf")

    for ixp_id, ixp_data in router.ixps.items():
        if ixp_id not in ixps:
            print(f"Invalid IXP: {ixp_id}")
            sys.exit(1)

        ixp = ixps[ixp_id]

        if ixp.rs:
            ixp_rs_output = router_template.render(
                ixp=ixp_id,
                ixp_name=ixp.name,
                peer_asn=ixp.rs.asn,
                router_peer_asn=ixp.rs.asn,
                peer_name=ixp.rs.name,
                our_v4_ip="",
                our_v6_ip="",
                our_asn=own_network.asn,
                local_asn=router.local_asn,
                relationship=Relationship.RS,
                as_filter=ixp.rs.filter.as_filter if ixp.rs.filter else None,
                v4_prefix_filter=ixp.rs.filter.v4_prefixes if ixp.rs.filter else None,
                v6_prefix_filter=ixp.rs.filter.v6_prefixes if ixp.rs.filter else None,
                max_prefix_v4=ixp.rs.max_v4,
                max_prefix_v6=ixp.rs.max_v6,
                routers=ixp.rs_routers,
            )

            with make_dirs_and_open(f"./out/{router.name}/ixp/{ixp_id}/rs.conf", "w") as f:
                f.write(ixp_rs_output)
            incs.append(f"ixp/{ixp_id}/rs.conf")

        for peer_asn in ixp.peers:
            peer = peers[peer_asn]
            peer_ixp = peer.ixps[ixp_id]

            peer_output = router_template.render(
                ixp=ixp_id,
                ixp_name=ixp.name,
                peer_asn=peer.network.asn,
                router_peer_asn=peer.network.asn,
                peer_name=peer.network.name,
                our_v4_ip=ixp_data.v4_ip,
                our_v6_ip=ixp_data.v6_ip,
                our_asn=own_network.asn,
                local_asn=router.local_asn,
                relationship=peer.relationship,
                as_filter=peer.network.filter.as_filter if peer.network.filter else None,
                v4_prefix_filter=peer.network.filter.v4_prefixes if peer.network.filter else None,
                v6_prefix_filter=peer.network.filter.v6_prefixes if peer.network.filter else None,
                max_prefix_v4=peer.network.max_v4 if peer.relationship != Relationship.TRANSIT else None,
                max_prefix_v6=peer.network.max_v6 if peer.relationship != Relationship.TRANSIT else None,
                routers=peer_ixp.routers,
            )

            with make_dirs_and_open(f"./out/{router.name}/ixp/{ixp_id}/as{peer.network.asn}.conf", "w") as f:
                f.write(peer_output)
            incs.append(f"ixp/{ixp_id}/as{peer.network.asn}.conf")

    router_output = global_template.render(
        incs=incs,
        global_config=global_output,
        router_id=router.router_id,
        pref_src_v4=router.prefsrc_v4,
        pref_src_v6=router.prefsrc_v6,
    )
    with make_dirs_and_open(f"./out/{router.name}/main.conf", "w") as f:
        f.write(router_output)
