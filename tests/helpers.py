"""Хелперы для сборки тестовых TRON permissions."""

from tronperm.tron.operations import DEFAULT_ACTIVE_OPERATIONS_HEX
from tronperm.tron.permissions import AccountPermissions, KeyWeight, Permission, PermissionType


def make_owner(pairs: list[tuple[str, int]], threshold: int = 1) -> Permission:
    return Permission(
        type=PermissionType.OWNER,
        id=0,
        permission_name="owner",
        threshold=threshold,
        keys=[KeyWeight(address=addr, weight=weight) for addr, weight in pairs],
    )


def make_active(
    pairs: list[tuple[str, int]],
    threshold: int = 1,
    operations: str | None = None,
    perm_id: int = 2,
    name: str = "active",
) -> Permission:
    return Permission(
        type=PermissionType.ACTIVE,
        id=perm_id,
        permission_name=name,
        threshold=threshold,
        keys=[KeyWeight(address=addr, weight=weight) for addr, weight in pairs],
        operations=operations or DEFAULT_ACTIVE_OPERATIONS_HEX,
    )


def make_account(owner: Permission, actives: list[Permission] | None = None) -> AccountPermissions:
    return AccountPermissions(owner=owner, actives=actives or [])
