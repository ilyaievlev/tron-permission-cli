"""Сервисы бизнес-логики: проверка доступа, инспекция и обновление прав."""

from tronperm.services.access import (
    AccountAccessReport,
    PermissionAccessReport,
    check_account_access,
    resolve_signer_addresses,
)
from tronperm.services.inspect import (
    AccountInspectionReport,
    inspect_account,
)
from tronperm.services.permission_update import (
    KeyDiff,
    PermissionsDiffReport,
    SinglePermissionDiff,
    UpdateSimulationResult,
    add_key_to_permissions,
    calculate_permission_diff,
    compare_account_permissions,
    execute_permission_update,
    simulate_permission_update,
)

__all__ = [
    "inspect_account",
    "AccountInspectionReport",
    "check_account_access",
    "resolve_signer_addresses",
    "PermissionAccessReport",
    "AccountAccessReport",
    "add_key_to_permissions",
    "calculate_permission_diff",
    "compare_account_permissions",
    "simulate_permission_update",
    "execute_permission_update",
    "KeyDiff",
    "SinglePermissionDiff",
    "PermissionsDiffReport",
    "UpdateSimulationResult",
]
