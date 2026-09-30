"""Модуль взаимодействия с блокчейном TRON."""

from tronperm.tron.account import (
    AccountError,
    AccountNotFoundError,
    PERMISSION_UPDATE_FEE_TRX,
    check_funds_for_permission_update,
    fetch_account_balance,
    fetch_account_permissions,
)
from tronperm.tron.client import get_tron_client
from tronperm.tron.operations import (
    DEFAULT_ACTIVE_OPERATIONS_HEX,
    TronContractType,
    can_modify_permissions,
    can_transfer_trc20,
    can_transfer_trx,
    decode_operation_ids,
    decode_operations,
    encode_operations,
)
from tronperm.tron.permissions import (
    AccountPermissions,
    KeyWeight,
    Permission,
    PermissionType,
)
from tronperm.tron.transactions import (
    BroadcastError,
    ConfirmationTimeoutError,
    TransactionError,
    build_permission_update_transaction,
    broadcast_and_wait,
    sign_transaction,
)

__all__ = [
    "get_tron_client",
    "TronContractType",
    "DEFAULT_ACTIVE_OPERATIONS_HEX",
    "decode_operations",
    "decode_operation_ids",
    "encode_operations",
    "can_transfer_trx",
    "can_transfer_trc20",
    "can_modify_permissions",
    "PermissionType",
    "KeyWeight",
    "Permission",
    "AccountPermissions",
    "AccountError",
    "AccountNotFoundError",
    "PERMISSION_UPDATE_FEE_TRX",
    "fetch_account_permissions",
    "fetch_account_balance",
    "check_funds_for_permission_update",
    "TransactionError",
    "BroadcastError",
    "ConfirmationTimeoutError",
    "build_permission_update_transaction",
    "sign_transaction",
    "broadcast_and_wait",
]
