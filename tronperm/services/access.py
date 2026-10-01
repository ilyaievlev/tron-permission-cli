"""Сервис проверки прав доступа подписывающих лиц (signers) к аккаунту TRON."""

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Set
from tronpy import Tron

from tronperm.config import config
from tronperm.keys.storage import read_keystore_address
from tronperm.keys.validate import validate_tron_address
from tronperm.tron.account import fetch_account_permissions
from tronperm.tron.client import get_tron_client
from tronperm.tron.permissions import AccountPermissions, KeyWeight, Permission, PermissionType


@dataclass
class PermissionAccessReport:
    """Отчет о доступности конкретного permission для заданных ключей."""
    permission_type: PermissionType
    permission_id: int
    permission_name: str
    threshold: int
    available_weight: int
    has_access: bool
    matching_signers: List[KeyWeight]
    can_transfer_trx: bool
    can_transfer_trc20: bool
    can_modify_permissions: bool
    has_account_permission_update_bit: bool


@dataclass
class AccountAccessReport:
    """Сводный отчет о доступе предоставленных ключей ко всему аккаунту."""
    account_address: str
    provided_signers: List[str]
    owner: PermissionAccessReport
    actives: List[PermissionAccessReport]


def resolve_signer_addresses(
    addresses: Optional[Iterable[str]] = None,
    key_files: Optional[Iterable[Path | str]] = None,
) -> List[str]:
    """Собирает и нормализует список TRON-адресов подписывающих лиц.
    
    Адреса могут быть переданы явно строками или прочитаны из JSON-файлов keystore.
    """
    resolved: List[str] = []

    if addresses:
        for addr in addresses:
            clean = validate_tron_address(addr)
            if clean not in resolved:
                resolved.append(clean)

    if key_files:
        for kf in key_files:
            addr = read_keystore_address(kf)
            if addr not in resolved:
                resolved.append(addr)

    return resolved


def collect_known_signer_addresses(
    key_files: Optional[Iterable[Path | str]] = None,
    extra_addresses: Optional[Iterable[str]] = None,
    include_env_key: bool = True,
) -> Set[str]:
    """Собирает адреса, которыми пользователь реально располагает (без расшифровки, кроме .env)."""
    from tronperm.keys.generate import address_from_private_key

    known = set(resolve_signer_addresses(key_files=key_files))
    if include_env_key and config.default_owner_private_key:
        known.add(address_from_private_key(config.default_owner_private_key))
    if extra_addresses:
        for addr in extra_addresses:
            if addr:
                known.add(validate_tron_address(addr))
    return known


def _evaluate_permission_access(
    permission: Permission,
    signers: List[str],
) -> PermissionAccessReport:
    """Анализирует доступность одного permission для списка адресов."""
    signer_set = set(signers)
    matching = [k for k in permission.keys if k.address in signer_set]
    available_weight = sum(k.weight for k in matching)
    has_access = available_weight >= permission.threshold

    # Если порог веса достигнут, проверяем конкретные операции
    if has_access:
        trx_ok = permission.can_transfer_trx
        trc20_ok = permission.can_transfer_trc20
        perm_edit_ok = permission.can_modify_permissions
        update_bit = permission.has_account_permission_update_bit
    else:
        trx_ok = False
        trc20_ok = False
        perm_edit_ok = False
        update_bit = False

    return PermissionAccessReport(
        permission_type=permission.type,
        permission_id=permission.id,
        permission_name=permission.permission_name,
        threshold=permission.threshold,
        available_weight=available_weight,
        has_access=has_access,
        matching_signers=matching,
        can_transfer_trx=trx_ok,
        can_transfer_trc20=trc20_ok,
        can_modify_permissions=perm_edit_ok,
        has_account_permission_update_bit=update_bit,
    )


def check_account_access(
    account_address: Optional[str] = None,
    signer_addresses: Optional[Iterable[str]] = None,
    key_files: Optional[Iterable[Path | str]] = None,
    client: Optional[Tron] = None,
    permissions: Optional[AccountPermissions] = None,
) -> AccountAccessReport:
    """Проверяет уровень доступа предоставленных ключей к аккаунту TRON.

    Args:
        account_address: Адрес целевого аккаунта.
        signer_addresses: Список адресов подписывающих лиц.
        key_files: Список путей к файлам keystore.
        client: Экземпляр клиента Tron.
        permissions: Заранее полученные permissions (если уже запрошены).

    Returns:
        AccountAccessReport со статусами доступа по каждому permission.
    """
    target_addr = account_address or config.default_account
    if not target_addr:
        raise ValueError("Адрес целевого аккаунта не указан")

    clean_target = validate_tron_address(target_addr)
    signers = resolve_signer_addresses(signer_addresses, key_files)

    if not signers:
        raise ValueError("Не передано ни одного адреса или файла ключа для проверки")

    if permissions is None:
        tron_client = client or get_tron_client()
        perms = fetch_account_permissions(tron_client, clean_target)
    else:
        perms = permissions

    owner_report = _evaluate_permission_access(perms.owner, signers)
    active_reports = [_evaluate_permission_access(act, signers) for act in perms.actives]

    return AccountAccessReport(
        account_address=clean_target,
        provided_signers=signers,
        owner=owner_report,
        actives=active_reports,
    )
