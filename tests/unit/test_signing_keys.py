"""Подпись AccountPermissionUpdate только ключами CURRENT Owner."""

import pytest

from tests.helpers import make_account, make_owner
from tronperm.services.permission_update import add_key_to_permissions, execute_permission_update
from tronperm.services.signing import addresses_from_private_keys, filter_keys_for_permission
from tronperm.tron.permissions import PermissionType


def test_filter_keys_drops_newly_added_key(key_a, key_b) -> None:
    current_owner = make_owner([(key_a.address, 1)], threshold=1)
    filtered = filter_keys_for_permission(
        [key_b.private_key, key_a.private_key, key_b.private_key],
        current_owner,
    )
    assert addresses_from_private_keys(filtered) == [key_a.address]


def test_execute_rejects_signing_with_new_key_only(monkeypatch, key_a, key_b) -> None:
    current = make_account(make_owner([(key_a.address, 1)], threshold=1))
    proposed = add_key_to_permissions(
        current,
        key_b.address,
        target_permission_type=PermissionType.OWNER,
        key_weight=1,
        new_threshold=1,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.fetch_account_permissions",
        lambda client, address: current,
    )
    monkeypatch.setattr(
        "tronperm.services.permission_update.check_funds_for_permission_update",
        lambda client, address: (True, 200.0, 100.0, True),
    )
    with pytest.raises(ValueError, match="CURRENT Owner"):
        execute_permission_update(
            account_address=key_a.address,
            proposed_permissions=proposed,
            signing_private_keys=[key_b.private_key],
            client=object(),
            known_user_addresses={key_a.address, key_b.address},
            allow_lockout=False,
        )
