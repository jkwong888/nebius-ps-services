"""Owner fences complete the locked resume proof, never active forwarding."""

from copy import deepcopy
from types import SimpleNamespace as NS

import pytest

from nebius_vpngw import cli
from nebius_vpngw.apply_approval import digest
from nebius_vpngw.deploy.activation_driver import Completion, activate
from nebius_vpngw.deploy.activation_recovery import Diagnosis, Recovery


def fenced_owner():
    return {
        "apply_locked": True,
        "apply_operation_id": "e" * 64,
        "observed_owner_node_id": "node",
        "data_plane_mode": "passive",
        "guard_boot_id": "boot",
        "apply_convergence": {"fresh": True, "data_plane_mode": "passive", "boot_id": "boot"},
    }


@pytest.mark.parametrize(
    "change,expected",
    [
        ({}, Completion.COMPLETE),
        ({"apply_locked": False}, Completion.UNKNOWN),
        ({"apply_operation_id": "foreign"}, Completion.UNKNOWN),
        ({"observed_owner_node_id": "foreign"}, Completion.UNKNOWN),
        ({"data_plane_mode": "originating"}, Completion.UNKNOWN),
        ({"guard_boot_id": "old-boot"}, Completion.UNKNOWN),
        ({"apply_convergence": {"fresh": False}}, Completion.UNKNOWN),
        ({"pending_operation_id": "pending"}, Completion.UNKNOWN),
    ],
)
def test_locked_phase_requires_exact_fresh_fence(change, expected):
    payload = {**fenced_owner(), **change}
    assert (
        cli._vm_ha_owner_phase_completion(
            lambda: payload, owner="node", binding=NS(), operation="e" * 64, locked=True
        )
        is expected
    )


def test_fenced_resume_proof_cannot_complete_active_forwarding():
    assert (
        cli._vm_ha_owner_phase_completion(
            fenced_owner, owner="node", binding=NS(), operation="e" * 64, locked=False
        )
        is Completion.UNKNOWN
    )


def test_resume_preserves_failed_correction_and_uses_only_unlock(tmp_path):
    owner = Recovery(tmp_path, execution="a" * 32, authority="b" * 64, boot=lambda: "boot")
    owner.initialize()
    stage = "verify-active-forwarding-and-routes-node"
    owner.initial(stage, state="started")
    units = {"service": {"Job": "", "ControlPID": "0", "ActiveState": "active"}}
    fingerprint = digest({"boot": "boot", "materialized": True, "units": units})
    failed = owner.reserve(stage, Diagnosis("configuration", fingerprint))
    failed = owner.transition(failed, "dispatched")
    failed = owner.transition(failed, "failed")
    owner.cleaned(failed)
    history = deepcopy(owner.history())
    calls, released = [], []

    def control(_target, _instance, _local, request, **_kwargs):
        calls.append(request)
        return {
            "clock": owner.clock(),
            "boot": "boot",
            "materialized": True,
            "complete": True,
            "units": units,
        }

    def resume(_deadline):
        return cli._vm_ha_owner_phase_completion(
            fenced_owner, owner="node", binding=NS(), operation="e" * 64, locked=True
        )

    activate(
        NS(activation_control=control),
        "target",
        NS(),
        {},
        recovery=owner,
        phase="verify-active-forwarding-and-routes",
        phase_effect=released.append,
        phase_complete=lambda _: Completion.COMPLETE if released else Completion.INCOMPLETE,
        phase_resume=resume,
        staged_receipt=NS(node_id="node", generation_id="c" * 64, staged_file_sha256="d" * 64),
        runtime_binding=NS(cluster_id="cluster"),
        apply_operation_id="e" * 64,
    )
    assert [request["action"] for request in calls] == ["inspect-unlock", "arm", "finish"]
    assert calls[1]["unlock_only"] is True
    assert calls[2]["verified"] is True
    assert len(released) == 1
    assert owner.history()[:-1] == history
    assert owner.history()[-1]["action"] == "unlock"
    assert owner.history()[-1]["state"] == "verified"
    assert owner.history()[-1]["cleaned"] is True
