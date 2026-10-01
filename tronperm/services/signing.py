"""Отбор ключей подписи по CURRENT permission аккаунта."""

from typing import Iterable, List

from tronperm.keys.generate import address_from_private_key
from tronperm.tron.permissions import Permission


def addresses_from_private_keys(private_keys: Iterable[str]) -> List[str]:
    """Возвращает уникальные TRON-адреса, соответствующие приватным ключам."""
    result: List[str] = []
    for pk in private_keys:
        addr = address_from_private_key(pk)
        if addr not in result:
            result.append(addr)
    return result


def filter_keys_for_permission(
    private_keys: Iterable[str],
    permission: Permission,
) -> List[str]:
    """Оставляет только ключи, которые уже входят в указанное CURRENT permission.

    Новый ключ, который только предлагается добавить, отбрасывается:
    он не может подписать AccountPermissionUpdateContract до confirmation.
    """
    allowed = {k.address for k in permission.keys}
    filtered: List[str] = []
    seen: set[str] = set()
    for pk in private_keys:
        addr = address_from_private_key(pk)
        if addr in allowed and addr not in seen:
            filtered.append(pk)
            seen.add(addr)
    return filtered
