"""Проверка доступа ключей к Owner/Active без сети."""

from tests.helpers import make_account, make_active, make_owner
from tronperm.services.access import check_account_access
from tronperm.tron.operations import encode_operations


def test_owner_access_and_active_bit_are_independent(key_a, key_b) -> None:
    mask_with_46 = encode_operations([1, 31, 46])
    account = make_account(
        make_owner([(key_a.address, 1)], threshold=1),
        [make_active([(key_a.address, 1)], operations=mask_with_46)],
    )

    report = check_account_access(
        account_address=key_a.address,
        signer_addresses=[key_a.address],
        permissions=account,
    )
    assert report.owner.has_access is True
    assert report.owner.can_modify_permissions is True
    assert report.actives[0].has_access is True
    assert report.actives[0].has_account_permission_update_bit is True
    assert report.actives[0].can_modify_permissions is False

    outsider = check_account_access(
        account_address=key_a.address,
        signer_addresses=[key_b.address],
        permissions=account,
    )
    assert outsider.owner.has_access is False
    assert outsider.owner.can_modify_permissions is False
    assert outsider.actives[0].has_access is False
    assert outsider.actives[0].can_modify_permissions is False
    assert outsider.actives[0].has_account_permission_update_bit is False
