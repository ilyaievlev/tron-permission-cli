"""Owner vs Active: смена прав возможна только у Owner."""

from tests.helpers import make_active, make_owner
from tronperm.tron.account import FALLBACK_PERMISSION_UPDATE_FEE_TRX, fetch_permission_update_fee_trx
from tronperm.tron.operations import encode_operations
from tronperm.tron.permissions import PermissionType


def test_owner_can_modify_permissions(key_a) -> None:
    owner = make_owner([(key_a.address, 1)], threshold=1)
    assert owner.type == PermissionType.OWNER
    assert owner.id == 0
    assert owner.can_modify_permissions is True
    assert owner.has_account_permission_update_bit is True
    assert owner.can_transfer_trx is True
    assert owner.can_transfer_trc20 is True


def test_active_cannot_modify_permissions_even_with_bit_46(key_a) -> None:
    mask = encode_operations([1, 31, 46])
    active = make_active([(key_a.address, 1)], operations=mask)
    assert active.has_account_permission_update_bit is True
    assert active.can_modify_permissions is False
    assert active.can_transfer_trx is True
    assert active.can_transfer_trc20 is True


def test_active_without_bit_46(key_a) -> None:
    active = make_active([(key_a.address, 1)])
    assert active.has_account_permission_update_bit is False
    assert active.can_modify_permissions is False


def test_permission_update_fee_from_chain_params() -> None:
    class FakeClient:
        def get_chain_parameters(self):
            return [{"key": "getUpdateAccountPermissionFee", "value": 100_000_000}]

    fee, from_chain = fetch_permission_update_fee_trx(FakeClient())
    assert fee == 100.0
    assert from_chain is True


def test_permission_update_fee_fallback() -> None:
    class BrokenClient:
        def get_chain_parameters(self):
            raise RuntimeError("unavailable")

    fee, from_chain = fetch_permission_update_fee_trx(BrokenClient())
    assert fee == FALLBACK_PERMISSION_UPDATE_FEE_TRX
    assert from_chain is False
