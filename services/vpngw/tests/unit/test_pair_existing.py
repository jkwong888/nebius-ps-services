import json
import sys
from copy import deepcopy

import pytest
import yaml
from tests.unit.test_pair_apply import CHILD, prepared_pair
from typer.testing import CliRunner

from nebius_vpngw import pair_apply, pair_config, pair_existing
from nebius_vpngw.cli import app


def existing_files(tmp_path):
    generated = prepared_pair(tmp_path / "seed")
    _, configs = pair_config.load(generated, resolved=True)
    for config in configs.values():
        config["connections"][0]["routing_mode"] = "static"
        config["connections"][0]["bgp"]["enabled"] = False
    left = configs["a"]
    extra = deepcopy(left["connections"][0])
    extra.update(name="home-pfsense", remote_prefixes=None, routing_mode="bgp")
    extra["bgp"]["enabled"] = True
    extra["bgp"]["remote_asn"] = 65200
    extra["tunnels"] = extra["tunnels"][:2]
    for index, tunnel in enumerate(extra["tunnels"]):
        tunnel.update(
            name=f"home-pfsense-{index}",
            gateway_instance_index=index,
            ha_role="active",
            remote_public_ip="203.0.113.10",
            inner_cidr=f"169.254.250.{index * 4}/30",
            inner_local_ip=f"169.254.250.{index * 4 + 1}",
            inner_remote_ip=f"169.254.250.{index * 4 + 2}",
        )
    left["connections"].append(extra)
    paths = {}
    for side in pair_config.SIDES:
        directory = tmp_path / ("original-" + side)
        directory.mkdir(mode=0o700)
        path = directory / ("retained-" + side + ".yaml")
        path.write_text(yaml.safe_dump(configs[side], sort_keys=False))
        path.chmod(0o600)
        paths[side] = path
    return paths


def link(tmp_path, paths):
    return pair_existing.link(
        tmp_path / "reference",
        "retained",
        paths,
        {"a": "paired-region", "b": "paired-region"},
        {"a": None, "b": None},
    )


def saved(paths):
    return {side: (path.read_bytes(), path.stat().st_mtime_ns) for side, path in paths.items()}


def test_link_preserves_original_paths_home_and_every_source_byte(tmp_path, monkeypatch):
    paths = existing_files(tmp_path)
    before = saved(paths)
    monkeypatch.setattr(
        pair_config.secrets, "token_urlsafe", lambda *_: pytest.fail("new credential")
    )
    path = link(tmp_path, paths)
    manifest, configs = pair_config.load(path, resolved=True)
    assert saved(paths) == before
    assert len(configs["a"]["connections"]) == 2
    assert configs["a"]["connections"][1]["name"] == "home-pfsense"
    assert manifest["deployments"]["a"]["config"] == str(paths["a"])
    assert manifest["deployments"]["b"]["config"] == str(paths["b"])
    assert len(manifest["paths"]) == 4
    assert set(item.name for item in path.parent.iterdir()) == {"pair.json", ".pair.lock"}
    assert not (path.parent / ".pair-assignments.json").exists()
    for config in configs.values():
        for connection in config["connections"]:
            for tunnel in connection["tunnels"]:
                assert tunnel["psk"] not in path.read_text()
    first = (path.read_bytes(), path.stat().st_mtime_ns)
    assert link(tmp_path, paths) == path
    assert (path.read_bytes(), path.stat().st_mtime_ns) == first


def test_public_link_existing_preserves_inputs_and_allows_explicit_modes_without_defaults(tmp_path):
    paths = existing_files(tmp_path)
    for path in paths.values():
        config = yaml.safe_load(path.read_bytes())
        config["defaults"].pop("routing", None)
        path.write_text(yaml.safe_dump(config))
    before = saved(paths)
    directory = tmp_path / "reference"
    result = CliRunner().invoke(
        app,
        [
            "pair",
            "link-existing",
            str(directory),
            "--left",
            str(paths["a"]),
            "--right",
            str(paths["b"]),
            "--connection-a",
            "paired-region",
            "--connection-b",
            "paired-region",
            "--name",
            "retained",
        ],
    )
    assert result.exit_code == 0
    manifest, configs = pair_config.load(directory / "pair.json")
    assert manifest["mode"] == "static"
    assert configs["a"]["connections"][1]["routing_mode"] == "bgp"
    assert saved(paths) == before


@pytest.mark.parametrize("change", ["extra-home", "format-only", "reciprocal"])
def test_full_config_pin_refuses_any_source_drift_including_home(tmp_path, change):
    paths = existing_files(tmp_path)
    manifest = link(tmp_path, paths)
    raw = paths["a"].read_text()
    if change == "format-only":
        paths["a"].write_text(raw + "\n")
    else:
        value = yaml.safe_load(raw)
        index = 1 if change == "extra-home" else 0
        value["connections"][index]["description"] = "changed"
        paths["a"].write_text(yaml.safe_dump(value))
    with pytest.raises(ValueError, match="configuration changed"):
        pair_config.load(manifest)
    with pytest.raises(ValueError, match="different identity"):
        link(tmp_path, paths)


@pytest.mark.parametrize(
    "change",
    [
        "endpoint",
        "psk",
        "inner",
        "crypto",
        "prefixes",
        "tunnel-prefixes",
        "missing-path",
        "member",
        "disabled",
        "region",
        "owner",
        "duplicate-ip",
        "unspecified-ip",
        "multicast-ip",
    ],
)
def test_reciprocal_mismatch_refuses_before_publication(tmp_path, change):
    paths = existing_files(tmp_path)
    config = yaml.safe_load(paths["a"].read_bytes())
    connection = config["connections"][0]
    tunnel = connection["tunnels"][0]
    if change == "endpoint":
        tunnel["remote_public_ip"] = "203.0.113.99"
    elif change == "psk":
        tunnel["psk"] = "must-not-be-reported"
    elif change == "inner":
        tunnel["inner_local_ip"], tunnel["inner_remote_ip"] = (
            tunnel["inner_remote_ip"],
            tunnel["inner_local_ip"],
        )
    elif change == "crypto":
        tunnel["ike_version"] = 1
    elif change == "prefixes":
        connection["remote_prefixes"] = ["10.99.0.0/16"]
    elif change == "tunnel-prefixes":
        tunnel["static_routes"] = {"remote_prefixes": ["10.99.0.0/16"]}
    elif change == "missing-path":
        connection["tunnels"].pop()
    elif change == "member":
        tunnel["gateway_instance_index"] = 20
    elif change == "disabled":
        connection["tunnels"][1]["ha_role"] = "disable"
    elif change == "region":
        other = yaml.safe_load(paths["b"].read_bytes())
        config["region_id"] = other["region_id"]
    elif change == "owner":
        other = yaml.safe_load(paths["b"].read_bytes())
        config["project_id"] = other["project_id"]
        config["gateway_group"]["name"] = other["gateway_group"]["name"]
    elif change == "duplicate-ip":
        config["gateway_group"]["external_ips"][1] = config["gateway_group"]["external_ips"][0]
    else:
        config["gateway_group"]["external_ips"][0] = [
            "0.0.0.0" if change == "unspecified-ip" else "224.0.0.1"
        ]
    paths["a"].write_text(yaml.safe_dump(config))
    with pytest.raises(ValueError) as error:
        link(tmp_path, paths)
    assert "must-not-be-reported" not in str(error.value)
    assert not (tmp_path / "reference").exists()


@pytest.mark.parametrize("change", ["identity", "mode", "unknown-field", "relative", "symlink"])
def test_manifest_admission_is_strict_and_cannot_redirect_files(tmp_path, change):
    paths = existing_files(tmp_path)
    path = link(tmp_path, paths)
    manifest = json.loads(path.read_bytes())
    if change == "identity":
        manifest["identity"] = "0" * 64
    elif change == "mode":
        manifest["mode"] = "bgp"
    elif change == "unknown-field":
        manifest["secret"] = "do-not-accept"
    elif change == "relative":
        manifest["deployments"]["a"]["config"] = "../original-a/retained-a.yaml"
    else:
        redirect = paths["a"].parent / "redirect.yaml"
        redirect.symlink_to(paths["a"])
        manifest["deployments"]["a"]["config"] = str(redirect)
    path.write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        pair_config.load(path)


def test_existing_network_preparation_rejected_before_regional_command(tmp_path, monkeypatch):
    from nebius_vpngw import pair_cli

    paths = existing_files(tmp_path)
    path = link(tmp_path, paths)
    before = saved(paths)
    monkeypatch.setattr(pair_cli, "_run", lambda *a: pytest.fail("network effect"))
    result = CliRunner().invoke(app, ["pair", "apply", str(path), "--prepare-network"])
    assert result.exit_code != 0
    with pytest.raises(ValueError, match="cannot be rewritten"):
        pair_config.bind_endpoints(path)
    assert saved(paths) == before


def test_existing_configs_keep_canonical_repair_inspection_and_both_barriers(tmp_path, monkeypatch):
    import typer

    paths = existing_files(tmp_path)
    path = link(tmp_path, paths)
    before = saved(paths)
    wheel = tmp_path / "candidate.whl"
    wheel.write_bytes(b"exact candidate")
    monkeypatch.setattr(pair_apply, "artifact", lambda: wheel)
    code = CHILD.replace(
        "side=child.request['side']",
        """side=child.request['side']
assert child.config.name=='retained-'+side+'.yaml'
assert child.config.parent != Path(child.request['manifest']).parent
scope={'targets':[{'name':side,'compute':'compute-'+side,'disk':'disk-'+side}]}
assert child.request['repair'] is True
if child.request['inspect_repair']:
 child.record['repair_scope']=scope
 child.record['phase']='complete'
 child.save()
 os.close(child.request['lock_fd'])
 raise SystemExit(0)
assert child.request['repair_scope']==scope
""",
    )
    monkeypatch.setattr(pair_apply, "command", lambda: [sys.executable, "-c", code])
    prompts = []

    def confirm(prompt, *, default):
        inspections = list((path.parent / ".pair-runs").glob("*/inspection/*.status.json"))
        assert len(inspections) == 2
        assert all(json.loads(item.read_text())["phase"] == "complete" for item in inspections)
        assert default is False
        prompts.append(prompt)
        return True

    monkeypatch.setattr(typer, "confirm", confirm)
    state = pair_apply.apply(path, approvals={"a": None, "b": None}, repair=True)
    assert state["phase"] == "complete"
    assert len(prompts) == 1
    for child in state["children"].values():
        assert set(child["receipts"]) == {"prepared", "originating"}
    assert saved(paths) == before
    assert not any(path.parent.glob("*.config.yaml"))
