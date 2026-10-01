"""Битовая маска Active operations: little-endian layout TRON."""

from tronperm.tron.operations import (
    DEFAULT_ACTIVE_OPERATIONS_HEX,
    TronContractType,
    can_modify_permissions,
    can_transfer_trc20,
    can_transfer_trx,
    decode_operation_ids,
    encode_operations,
    has_account_permission_update_bit,
    normalize_operations_hex,
)


def test_bit_i_lives_in_byte_i_div_8() -> None:
    mask = encode_operations([TronContractType.TransferContract])
    raw = bytes.fromhex(mask)
    cid = TronContractType.TransferContract.value
    assert raw[cid // 8] & (1 << (cid % 8))
    assert decode_operation_ids(mask) == {cid}


def test_default_active_mask_allows_transfers_not_permission_update() -> None:
    ids = decode_operation_ids(DEFAULT_ACTIVE_OPERATIONS_HEX)
    assert TronContractType.TransferContract.value in ids
    assert TronContractType.TriggerSmartContract.value in ids
    assert TronContractType.AccountPermissionUpdateContract.value not in ids
    assert can_transfer_trx(DEFAULT_ACTIVE_OPERATIONS_HEX)
    assert can_transfer_trc20(DEFAULT_ACTIVE_OPERATIONS_HEX)
    assert not has_account_permission_update_bit(DEFAULT_ACTIVE_OPERATIONS_HEX)


def test_account_permission_update_bit_is_46() -> None:
    mask = encode_operations([TronContractType.AccountPermissionUpdateContract])
    raw = bytes.fromhex(mask)
    cid = 46
    assert raw[cid // 8] & (1 << (cid % 8))
    assert has_account_permission_update_bit(mask)
    assert can_modify_permissions(mask) is True
    assert not can_transfer_trx(mask)


def test_encode_decode_roundtrip() -> None:
    wanted = [
        TronContractType.TransferContract,
        TronContractType.TriggerSmartContract,
        TronContractType.AccountPermissionUpdateContract,
    ]
    mask = encode_operations(wanted)
    assert len(mask) == 64
    ids = decode_operation_ids(mask)
    assert ids == {item.value for item in wanted}


def test_normalize_operations_hex_rejects_bad_length() -> None:
    try:
        normalize_operations_hex("aa")
        assert False, "ожидался ValueError"
    except ValueError as exc:
        assert "64" in str(exc)
