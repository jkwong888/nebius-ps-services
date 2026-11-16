"""Bind existing regional files to the canonical pair coordinator without rewriting them."""

from __future__ import annotations

import hashlib
import ipaddress
import re
from pathlib import Path

import yaml

from .apply_approval import digest
from .deploy.operator_keys import (
    protected_directory,
    publish_new,
    read_private_file,
    safe_ancestors,
)

SCHEMA = "nebius-vpngw.existing-pair.v1"
SIDES = ("a", "b")

# Admission dispatches here from pair_config; deferred imports avoid that cycle.


def configuration(path: Path) -> tuple[bytes, dict]:
    from . import pair_config

    if not path.is_absolute() or path != path.resolve(strict=True):
        raise ValueError("Existing pair requires original absolute configuration paths")
    safe_ancestors(path)
    raw = read_private_file(path)
    if raw is None or b"${" in raw:
        raise ValueError("Existing pair requires complete resolved configuration files")
    try:
        value = yaml.safe_load(raw)
    except yaml.YAMLError:
        raise ValueError("Existing paired configuration is invalid") from None
    if not isinstance(value, dict):
        raise ValueError("Existing paired configuration is malformed")
    pair_config._validate(value)
    return raw, value


def connection(config: dict, name: str) -> dict:
    selected = [item for item in config["connections"] if item["name"] == name]
    if len(selected) != 1:
        raise ValueError("Existing reciprocal connection is missing")
    return selected[0]


def topology(configs: dict[str, dict], selected: dict[str, str]) -> tuple[str, list[dict]]:
    from . import pair_config

    pair_config._prefixes(configs)
    if configs["a"]["region_id"] == configs["b"]["region_id"]:
        raise ValueError("Existing pair requires distinct regions")
    identities = {
        (value["project_id"], value["gateway_group"]["name"]) for value in configs.values()
    }
    if len(identities) != 2:
        raise ValueError("Existing pair requires distinct regional deployment owners")
    connections = {side: connection(configs[side], selected[side]) for side in SIDES}
    modes = set()
    endpoints = set()
    for side, peer in (("a", "b"), ("b", "a")):
        config = configs[side]
        group = config["gateway_group"]
        count = group["instance_count"]
        expected_count = 2 if (group.get("vm_ha") or {}).get("enabled") else 1
        if count != expected_count:
            raise ValueError("Existing pair requires Single-VM or two-member VM-HA")
        if int(group["vm_spec"].get("num_nics", 1)) != 1:
            raise ValueError("Existing pair requires one public endpoint per member")
        addresses = group.get("external_ips")
        if not isinstance(addresses, list) or len(addresses) != count:
            raise ValueError("Existing pair requires exact public member endpoints")
        for member in addresses:
            if not isinstance(member, list) or len(member) != 1:
                raise ValueError("Existing pair requires one public endpoint per member")
            address = ipaddress.IPv4Address(member[0])
            if address.is_unspecified or address.is_multicast or address in endpoints:
                raise ValueError(
                    "Existing pair public endpoints must be distinct unicast addresses"
                )
            endpoints.add(address)
        item = connections[side]
        mode = item["routing_mode"]
        modes.add(mode)
        if set(item.get("remote_prefixes") or []) != set(
            configs[peer]["gateway"]["local_prefixes"]
        ):
            raise ValueError("Existing pair prefixes are not reciprocal")
        if (
            mode == "bgp"
            and item.get("bgp", {}).get("remote_asn") != configs[peer]["gateway"]["local_asn"]
        ):
            raise ValueError("Existing pair BGP identities are not reciprocal")
    if len(modes) != 1 or not modes.issubset({"static", "bgp"}):
        raise ValueError("Existing reciprocal connections require one routing mode")

    right = {}
    for tunnel in connections["b"]["tunnels"]:
        cidr = tunnel["inner_cidr"]
        if cidr in right:
            raise ValueError("Existing pair contains ambiguous tunnel addressing")
        right[cidr] = tunnel
    paths = []
    combinations = set()
    for first in connections["a"]["tunnels"]:
        second = right.pop(first["inner_cidr"], None)
        if (
            second is None
            or first.get("ha_role") == "disable"
            or second.get("ha_role") == "disable"
        ):
            raise ValueError("Existing pair tunnel inventory is not reciprocal")
        a = first.get("gateway_instance_index", 0)
        b = second.get("gateway_instance_index", 0)
        if (
            a not in range(configs["a"]["gateway_group"]["instance_count"])
            or b not in range(configs["b"]["gateway_group"]["instance_count"])
            or first.get("local_public_ip_index") not in {None, 0}
            or second.get("local_public_ip_index") not in {None, 0}
        ):
            raise ValueError("Existing pair tunnel member identity is invalid")
        if (a, b) in combinations:
            raise ValueError("Existing pair repeats an owner combination")
        combinations.add((a, b))
        if (
            first["inner_local_ip"] != second["inner_remote_ip"]
            or first["inner_remote_ip"] != second["inner_local_ip"]
            or first["remote_public_ip"] != configs["b"]["gateway_group"]["external_ips"][b][0]
            or second["remote_public_ip"] != configs["a"]["gateway_group"]["external_ips"][a][0]
            or first.get("psk") != second.get("psk")
        ):
            raise ValueError("Existing pair tunnel endpoints or credentials differ")
        for field in ("ike_version", "crypto"):
            left_value = first.get(field) or configs["a"]["defaults"].get(field)
            right_value = second.get(field) or configs["b"]["defaults"].get(field)
            if left_value != right_value:
                raise ValueError("Existing pair cryptographic proposals differ")
        for tunnel, peer in ((first, "b"), (second, "a")):
            overrides = (tunnel.get("static_routes") or {}).get("remote_prefixes")
            if overrides is not None and set(overrides) != set(
                configs[peer]["gateway"]["local_prefixes"]
            ):
                raise ValueError("Existing pair tunnel selectors are not reciprocal")
        paths.append(
            {
                "a": a,
                "b": b,
                "inner_cidr": first["inner_cidr"],
                "tunnel_a": first["name"],
                "tunnel_b": second["name"],
            }
        )
    expected = set()
    for a in range(configs["a"]["gateway_group"]["instance_count"]):
        for b in range(configs["b"]["gateway_group"]["instance_count"]):
            expected.add((a, b))
    if right or combinations != expected:
        raise ValueError("Existing pair does not cover every owner combination")
    return next(iter(modes)), paths


def load(manifest: dict) -> tuple[dict, dict[str, dict]]:
    from . import pair_config

    if (
        set(manifest)
        != {"schema", "name", "identity", "mode", "operator_profiles", "deployments", "paths"}
        or manifest["schema"] != SCHEMA
        or not isinstance(manifest["deployments"], dict)
        or set(manifest["deployments"]) != set(SIDES)
    ):
        raise ValueError("Existing pair manifest is malformed")
    if not isinstance(manifest["name"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,63}", manifest["name"]
    ):
        raise ValueError("Existing pair name is invalid")
    pair_config._profiles(manifest["operator_profiles"])
    configs = {}
    selected = {}
    for side in SIDES:
        record = manifest["deployments"][side]
        if not isinstance(record, dict) or set(record) != {
            "config",
            "sha256",
            "intent",
            "connection",
            "project",
            "region",
            "gateway",
            "members",
            "asn",
        }:
            raise ValueError("Existing pair deployment reference is malformed")
        raw, value = configuration(Path(record["config"]))
        if hashlib.sha256(raw).hexdigest() != record["sha256"] or digest(value) != record["intent"]:
            raise ValueError("Existing paired configuration changed")
        group = value["gateway_group"]
        observed = (
            value["project_id"],
            value["region_id"],
            group["name"],
            group["instance_count"],
            value["gateway"]["local_asn"],
        )
        expected = tuple(record[key] for key in ("project", "region", "gateway", "members", "asn"))
        if observed != expected:
            raise ValueError("Existing pair deployment identity changed")
        configs[side] = value
        selected[side] = record["connection"]
    if manifest["deployments"]["a"]["config"] == manifest["deployments"]["b"]["config"]:
        raise ValueError("Existing pair requires distinct original configurations")
    mode, paths = topology(configs, selected)
    identity = {key: value for key, value in manifest.items() if key != "identity"}
    if (
        mode != manifest["mode"]
        or paths != manifest["paths"]
        or digest(identity) != manifest["identity"]
    ):
        raise ValueError("Existing pair manifest identity changed")
    return manifest, configs


def link(
    directory: Path,
    name: str,
    paths: dict[str, Path],
    selected: dict[str, str],
    profiles: dict[str, str | None],
) -> Path:
    from . import pair_config

    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", name):
        raise ValueError("Existing pair name is invalid")
    pair_config._profiles(profiles)
    configs = {}
    records = {}
    for side in SIDES:
        path = paths[side].expanduser().absolute()
        raw, value = configuration(path)
        configs[side] = value
        group = value["gateway_group"]
        records[side] = {
            "config": str(path),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "intent": digest(value),
            "connection": selected[side],
            "project": value["project_id"],
            "region": value["region_id"],
            "gateway": group["name"],
            "members": group["instance_count"],
            "asn": value["gateway"]["local_asn"],
        }
    mode, tunnels = topology(configs, selected)
    manifest = {
        "schema": SCHEMA,
        "name": name,
        "mode": mode,
        "operator_profiles": profiles,
        "deployments": records,
        "paths": tunnels,
    }
    manifest["identity"] = digest(manifest)
    load(manifest)
    directory = directory.expanduser().absolute()
    protected_directory(directory)
    path = directory / pair_config.MANIFEST
    raw_manifest = pair_config._bytes(manifest)
    old = read_private_file(path, required=False)
    if old is not None and old != raw_manifest:
        raise ValueError("Existing pair reference already has a different identity")
    if old is None:
        publish_new(path, raw_manifest)
    lock = directory / ".pair.lock"
    if not lock.exists():
        publish_new(lock, b"")
    return path
