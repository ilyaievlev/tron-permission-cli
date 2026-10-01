"""DIFF permissions и hard-stop lockout по известным ключам."""

import pytest

from tests.helpers import make_account, make_active, make_owner
from tronperm.services.permission_update import (
    add_key_to_permissions,
    compare_account_permissions,
    execute_permission_update,
    simulate_permission_update,
)
from tronperm.tron.permissions import PermissionType


def test_add_unknown_key_with_threshold_2_is_lockout(key_a, key_b) -> None:
    current = make_account(
        make_owner([(key_a.address, 1)], threshold=1),
        [make_active([(key_a.address, 1)])],
    )
    proposed = add_key_to_permissions(
        current,
        key_b.address,
        target_permission_type=PermissionType.OWNER,
        key_weight=1,
        new_threshold=2,
    )
    diff = compare_account_permissions(
        key_a.address,
        current,
        proposed,
        known_user_addresses={key_a.address},
    )
    assert diff.has_lockout_risk is True
    assert any("Известные вам ключи" in warning for warning in diff.warnings)


def test_add_held_key_with_threshold_2_is_not_lockout(key_a, key_b) -> None:
    current = make_account(
        make_owner([(key_a.address, 1)], threshold=1),
        [make_active([(key_a.address, 1)])],
    )
    proposed = add_key_to_permissions(
        current,
        key_b.address,
        target_permission_type=PermissionType.OWNER,
        key_weight=1,
        new_threshold=2,
    )
    diff = compare_account_permissions(
        key_a.address,
        current,
        proposed,
        known_user_addresses={key_a.address, key_b.address},
    )
    assert diff.has_lockout_risk is False


def test_simulate_sets_can_proceed_false_on_lockout(monkeypatch, key_a, key_b) -> None:
    current = make_account(make_owner([(key_a.address, 1)], threshold=1))
    proposed = add_key_to_permissions(
        current,
        key_b.address,
        target_permission_type=PermissionType.OWNER,
        key_weight=1,
        new_threshold=2,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.fetch_account_permissions",
        lambda client, address: current,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.check_funds_for_permission_update",
        lambda client, address: (True, 200.0, 100.0, True),
    )
    result = simulate_permission_update(
        key_a.address,
        proposed,
        client=object(),
        known_user_addresses={key_a.address},
    )
    assert result.has_sufficient_fee is True
    assert result.required_fee_trx == 100.0
    assert result.fee_from_chain is True
    assert result.diff.has_lockout_risk is True
    assert result.can_proceed is False


def test_execute_hard_stops_lockout_without_force(monkeypatch, key_a, key_b) -> None:
    current = make_account(make_owner([(key_a.address, 1)], threshold=1))
    proposed = add_key_to_permissions(
        current,
        key_b.address,
        target_permission_type=PermissionType.OWNER,
        key_weight=1,
        new_threshold=2,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.fetch_account_permissions",
        lambda client, address: current,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.check_funds_for_permission_update",
        lambda client, address: (True, 200.0, 100.0, True),
    )
    with pytest.raises(ValueError, match="lockout"):
        execute_permission_update(
            account_address=key_a.address,
            proposed_permissions=proposed,
            signing_private_keys=[key_a.private_key],
            client=object(),
            known_user_addresses={key_a.address},
            allow_lockout=False,
        )
