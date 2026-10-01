"""Сервис безопасного обновления Account Permissions и симуляции изменений."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from tronpy import Tron

from tronperm.keys.validate import validate_tron_address
from tronperm.tron.account import (
    check_funds_for_permission_update,
    fetch_account_permissions,
)
from tronperm.tron.client import get_tron_client
from tronperm.tron.permissions import (
    AccountPermissions,
    KeyWeight,
    Permission,
    PermissionType,
)
from tronperm.tron.transactions import (
    broadcast_and_wait,
    build_permission_update_transaction,
    sign_transaction,
)
from tronperm.services.signing import filter_keys_for_permission, addresses_from_private_keys


@dataclass
class KeyDiff:
    """Изменение конкретного ключа."""
    address: str
    action: str  # 'added', 'removed', 'modified', 'unchanged'
    old_weight: Optional[int] = None
    new_weight: Optional[int] = None


@dataclass
class SinglePermissionDiff:
    """Разница между текущей и предложенной конфигурацией одного разрешения."""
    permission_name: str
    permission_type: PermissionType
    permission_id: int
    old_threshold: int
    new_threshold: int
    key_diffs: List[KeyDiff]
    added_operations: List[str] = field(default_factory=list)
    removed_operations: List[str] = field(default_factory=list)


@dataclass
class PermissionsDiffReport:
    """Полный отчет о различиях между текущими и новыми permissions."""
    account_address: str
    owner_diff: SinglePermissionDiff
    active_diffs: List[SinglePermissionDiff]
    warnings: List[str]
    has_lockout_risk: bool


@dataclass
class UpdateSimulationResult:
    """Результат симуляции обновления прав (Dry-Run)."""
    account_address: str
    current_balance_trx: float
    has_sufficient_fee: bool
    required_fee_trx: float
    fee_from_chain: bool
    diff: PermissionsDiffReport
    proposed_permissions: AccountPermissions
    can_proceed: bool


def calculate_permission_diff(
    current: Permission,
    proposed: Permission,
) -> SinglePermissionDiff:
    """Сравнивает два состояния одного permission и возвращает подробный diff."""
    curr_keys = {k.address: k.weight for k in current.keys}
    prop_keys = {k.address: k.weight for k in proposed.keys}

    all_addrs = set(curr_keys.keys()) | set(prop_keys.keys())
    key_diffs: List[KeyDiff] = []

    for addr in sorted(all_addrs):
        in_curr = addr in curr_keys
        in_prop = addr in prop_keys

        if in_curr and not in_prop:
            key_diffs.append(KeyDiff(address=addr, action="removed", old_weight=curr_keys[addr]))
        elif not in_curr and in_prop:
            key_diffs.append(KeyDiff(address=addr, action="added", new_weight=prop_keys[addr]))
        elif curr_keys[addr] != prop_keys[addr]:
            key_diffs.append(
                KeyDiff(
                    address=addr,
                    action="modified",
                    old_weight=curr_keys[addr],
                    new_weight=prop_keys[addr],
                )
            )
        else:
            key_diffs.append(
                KeyDiff(
                    address=addr,
                    action="unchanged",
                    old_weight=curr_keys[addr],
                    new_weight=prop_keys[addr],
                )
            )

    added_ops: List[str] = []
    removed_ops: List[str] = []
    if current.type == PermissionType.ACTIVE and proposed.type == PermissionType.ACTIVE:
        curr_ops = set(current.allowed_operations)
        prop_ops = set(proposed.allowed_operations)
        added_ops = sorted(list(prop_ops - curr_ops))
        removed_ops = sorted(list(curr_ops - prop_ops))

    return SinglePermissionDiff(
        permission_name=proposed.permission_name,
        permission_type=proposed.type,
        permission_id=proposed.id,
        old_threshold=current.threshold,
        new_threshold=proposed.threshold,
        key_diffs=key_diffs,
        added_operations=added_ops,
        removed_operations=removed_ops,
    )


def compare_account_permissions(
    account_address: str,
    current: AccountPermissions,
    proposed: AccountPermissions,
    known_user_addresses: Optional[Set[str]] = None,
) -> PermissionsDiffReport:
    """Сравнивает текущие и предложенные права аккаунта и оценивает риски потери доступа."""
    owner_diff = calculate_permission_diff(current.owner, proposed.owner)

    active_diffs: List[SinglePermissionDiff] = []
    curr_actives = {a.id: a for a in current.actives}
    for prop_act in proposed.actives:
        curr_act = curr_actives.get(prop_act.id, prop_act)
        active_diffs.append(calculate_permission_diff(curr_act, prop_act))

    warnings: List[str] = []
    has_lockout_risk = False

    # 1. Проверка достижимости порога Owner
    if not proposed.owner.is_threshold_reachable:
        warnings.append("КРИТИЧНО: Сумма весов ключей Owner меньше требуемого threshold!")
        has_lockout_risk = True

    # 2. Проверка контроля над Owner известными пользователю ключами
    if known_user_addresses:
        clean_known = {validate_tron_address(a) for a in known_user_addresses}
        user_weight = sum(k.weight for k in proposed.owner.keys if k.address in clean_known)
        if user_weight < proposed.owner.threshold:
            warnings.append(
                f"ВНИМАНИЕ: Известные вам ключи имеют вес {user_weight} из {proposed.owner.threshold} "
                f"для Owner. Вы потеряете единоличный контроль над аккаунтом!"
            )
            has_lockout_risk = True

    # 3. Предупреждение об увеличении threshold
    if proposed.owner.threshold > current.owner.threshold:
        warnings.append(
            f"Порог Owner увеличивается с {current.owner.threshold} до {proposed.owner.threshold}. "
            f"Для любых операций владельца потребуется больше подписей."
        )

    # 4. Проверка прав Active
    for act in proposed.actives:
        if not act.is_threshold_reachable:
            warnings.append(f"КРИТИЧНО: Сумма весов Active '{act.permission_name}' меньше threshold!")
            has_lockout_risk = True
        if not act.can_transfer_trx and not act.can_transfer_trc20:
            warnings.append(
                f"Разрешение Active '{act.permission_name}' не содержит прав на перевод TRX или смарт-контрактов."
            )

    return PermissionsDiffReport(
        account_address=account_address,
        owner_diff=owner_diff,
        active_diffs=active_diffs,
        warnings=warnings,
        has_lockout_risk=has_lockout_risk,
    )


def simulate_permission_update(
    account_address: str,
    proposed_permissions: AccountPermissions,
    client: Optional[Tron] = None,
    known_user_addresses: Optional[Set[str]] = None,
) -> UpdateSimulationResult:
    """Проводит полную симуляцию обновления прав без отправки транзакции (Dry-Run)."""
    clean_addr = validate_tron_address(account_address)
    tron_client = client or get_tron_client()

    current_perms = fetch_account_permissions(tron_client, clean_addr)
    has_fee, balance, required_fee, fee_from_chain = check_funds_for_permission_update(tron_client, clean_addr)

    diff_report = compare_account_permissions(
        account_address=clean_addr,
        current=current_perms,
        proposed=proposed_permissions,
        known_user_addresses=known_user_addresses,
    )

    if not has_fee:
        source = "chain parameters" if fee_from_chain else "fallback"
        diff_report.warnings.append(
            f"Недостаточно средств на балансе ({balance:.2f} TRX). "
            f"Для смены прав требуется минимум {required_fee:.2f} TRX ({source})."
        )

    can_proceed = has_fee and not diff_report.has_lockout_risk

    return UpdateSimulationResult(
        account_address=clean_addr,
        current_balance_trx=balance,
        has_sufficient_fee=has_fee,
        required_fee_trx=required_fee,
        fee_from_chain=fee_from_chain,
        diff=diff_report,
        proposed_permissions=proposed_permissions,
        can_proceed=can_proceed,
    )


def add_key_to_permissions(
    current: AccountPermissions,
    new_address: str,
    target_permission_type: PermissionType = PermissionType.OWNER,
    active_id: Optional[int] = None,
    key_weight: int = 1,
    new_threshold: Optional[int] = None,
) -> AccountPermissions:
    """Создаёт предложенную конфигурацию прав с добавлением нового адреса."""
    clean_new_addr = validate_tron_address(new_address)

    if target_permission_type == PermissionType.OWNER:
        # Добавляем ключ в Owner
        keys_copy = [k for k in current.owner.keys if k.address != clean_new_addr]
        keys_copy.append(KeyWeight(address=clean_new_addr, weight=key_weight))
        threshold = new_threshold if new_threshold is not None else current.owner.threshold

        new_owner = Permission(
            type=PermissionType.OWNER,
            id=current.owner.id,
            permission_name=current.owner.permission_name,
            threshold=threshold,
            keys=keys_copy,
            operations=None,
        )
        return AccountPermissions(
            owner=new_owner,
            witness=current.witness,
            actives=current.actives,
        )

    elif target_permission_type == PermissionType.ACTIVE:
        # Добавляем ключ в Active
        new_actives: List[Permission] = []
        target_id = active_id if active_id is not None else (current.actives[0].id if current.actives else 2)

        found = False
        for act in current.actives:
            if act.id == target_id:
                keys_copy = [k for k in act.keys if k.address != clean_new_addr]
                keys_copy.append(KeyWeight(address=clean_new_addr, weight=key_weight))
                threshold = new_threshold if new_threshold is not None else act.threshold
                new_actives.append(
                    Permission(
                        type=PermissionType.ACTIVE,
                        id=act.id,
                        permission_name=act.permission_name,
                        threshold=threshold,
                        keys=keys_copy,
                        operations=act.operations,
                    )
                )
                found = True
            else:
                new_actives.append(act)

        if not found:
            # Создаем новое активное разрешение
            new_actives.append(
                Permission(
                    type=PermissionType.ACTIVE,
                    id=target_id,
                    permission_name=f"active_{target_id}",
                    threshold=new_threshold or 1,
                    keys=[KeyWeight(address=clean_new_addr, weight=key_weight)],
                )
            )

        return AccountPermissions(
            owner=current.owner,
            witness=current.witness,
            actives=new_actives,
        )

    raise ValueError(f"Неподдерживаемый тип разрешения для добавления: {target_permission_type}")


def execute_permission_update(
    account_address: str,
    proposed_permissions: AccountPermissions,
    signing_private_keys: List[str],
    client: Optional[Tron] = None,
    timeout: float = 30.0,
    known_user_addresses: Optional[Set[str]] = None,
    allow_lockout: bool = False,
) -> Tuple[str, Dict[str, Any], AccountPermissions]:
    """Безопасно собирает, подписывает, отправляет и верифицирует смену прав аккаунта.

    Подпись выполняется только ключами из CURRENT Owner permission.

    Returns:
        (txid, receipt, updated_permissions)
    """
    clean_addr = validate_tron_address(account_address)
    tron_client = client or get_tron_client()

    has_funds, balance, required_fee, _from_chain = check_funds_for_permission_update(tron_client, clean_addr)
    if not has_funds:
        raise ValueError(
            f"Недостаточно TRX на балансе для смены прав. Баланс: {balance:.2f} TRX, требуется: {required_fee:.2f} TRX"
        )

    fresh_current = fetch_account_permissions(tron_client, clean_addr)
    diff = compare_account_permissions(
        clean_addr,
        fresh_current,
        proposed_permissions,
        known_user_addresses=known_user_addresses,
    )
    if not proposed_permissions.owner.is_threshold_reachable:
        raise ValueError("Невозможно отправить транзакцию: сумма весов Owner меньше threshold!")
    if diff.has_lockout_risk and not allow_lockout:
        raise ValueError("Отмена: обнаружен риск потери управления аккаунтом (lockout).")

    current_owner_keys = filter_keys_for_permission(signing_private_keys, fresh_current.owner)
    if not current_owner_keys:
        raise ValueError(
            "Ни один из ключей подписи не входит в текущий Owner permission. "
            "AccountPermissionUpdateContract должен подписываться CURRENT Owner, "
            "а не ключом, который только добавляется."
        )
    signer_addrs = addresses_from_private_keys(current_owner_keys)
    if not fresh_current.owner.has_access(signer_addrs):
        raise ValueError(
            f"Недостаточно подписей CURRENT Owner: вес {fresh_current.owner.calculate_weight(signer_addrs)} "
            f"< порог {fresh_current.owner.threshold}"
        )

    tx = build_permission_update_transaction(tron_client, clean_addr, proposed_permissions)
    signed_tx = sign_transaction(tx, current_owner_keys)
    txid, receipt = broadcast_and_wait(signed_tx, timeout=timeout)
    final_perms = fetch_account_permissions(tron_client, clean_addr)

    expected_owner_addrs = {k.address for k in proposed_permissions.owner.keys}
    actual_owner_addrs = {k.address for k in final_perms.owner.keys}
    missing = expected_owner_addrs - actual_owner_addrs
    if missing:
        raise ValueError(
            f"Транзакция {txid} подтверждена, но в Owner не найдены ожидаемые адреса: {', '.join(sorted(missing))}"
        )
    if final_perms.owner.threshold != proposed_permissions.owner.threshold:
        raise ValueError(
            f"Транзакция {txid} подтверждена, но threshold Owner "
            f"{final_perms.owner.threshold} != предложенному {proposed_permissions.owner.threshold}"
        )

    for proposed_act in proposed_permissions.actives:
        actual_act = final_perms.find_active_by_id(proposed_act.id)
        if actual_act is None:
            raise ValueError(
                f"Транзакция {txid} подтверждена, но Active id={proposed_act.id} отсутствует on-chain"
            )
        missing_act = {k.address for k in proposed_act.keys} - {k.address for k in actual_act.keys}
        if missing_act:
            raise ValueError(
                f"Транзакция {txid} подтверждена, но в Active id={proposed_act.id} "
                f"не найдены адреса: {', '.join(sorted(missing_act))}"
            )

    return (txid, receipt, final_perms)
