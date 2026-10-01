"""Сервис переводов TRX и USDT с учётом мультиподписи permissions."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from tronpy import Tron

from tronperm.config import config
from tronperm.keys.generate import address_from_private_key
from tronperm.keys.validate import validate_tron_address
from tronperm.tron.account import (
    fetch_account_balance_sun,
    fetch_account_permissions,
    fetch_trc20_balance,
)
from tronperm.tron.client import get_tron_client
from tronperm.tron.permissions import AccountPermissions, Permission, PermissionType
from tronperm.tron.tokens import (
    DEFAULT_FEE_LIMIT_SUN,
    format_token_amount,
    format_trx_amount,
    get_usdt_contract,
    parse_token_amount,
    parse_trx_amount,
)
from tronperm.tron.transactions import (
    broadcast_and_wait,
    build_trc20_transfer_transaction,
    build_trx_transfer_transaction,
    sign_transaction,
)

ASSET_TRX = "trx"
ASSET_USDT = "usdt"


@dataclass
class TransferPlan:
    """Подготовленный план перевода до подписи и broadcast."""
    asset: str
    from_address: str
    to_address: str
    amount_display: str
    amount_units: int
    decimals: int
    symbol: str
    permission: Permission
    signer_addresses: List[str]
    available_weight: int
    sender_balance_display: str
    contract_address: Optional[str] = None
    fee_limit_sun: int = DEFAULT_FEE_LIMIT_SUN
    warnings: List[str] = field(default_factory=list)
    can_proceed: bool = True


def select_permission_for_transfer(
    permissions: AccountPermissions,
    signer_addresses: List[str],
    asset: str,
    permission_id: Optional[int] = None,
) -> Permission:
    """Выбирает Owner или Active permission для перевода с учётом весов и operations."""
    wants_trc20 = asset == ASSET_USDT

    def allows_operation(perm: Permission) -> bool:
        if wants_trc20:
            return perm.can_transfer_trc20
        return perm.can_transfer_trx

    if permission_id is not None:
        if permission_id == 0:
            candidate = permissions.owner
        else:
            candidate = permissions.find_active_by_id(permission_id)
            if candidate is None:
                raise ValueError(f"Active permission с id={permission_id} не найдено у аккаунта")
        if not allows_operation(candidate):
            op_name = "TRC-20 / USDT" if wants_trc20 else "TRX"
            raise ValueError(
                f"Разрешение '{candidate.permission_name}' (id={candidate.id}) не позволяет перевод {op_name}"
            )
        if not candidate.has_access(signer_addresses):
            raise ValueError(
                f"Недостаточно подписей для '{candidate.permission_name}' "
                f"(вес {candidate.calculate_weight(signer_addresses)} < порог {candidate.threshold})"
            )
        return candidate

    candidates: List[Permission] = [permissions.owner, *permissions.actives]
    usable = [
        perm for perm in candidates
        if allows_operation(perm) and perm.has_access(signer_addresses)
    ]
    if not usable:
        op_name = "USDT (TriggerSmartContract)" if wants_trc20 else "TRX (TransferContract)"
        raise ValueError(
            f"Предоставленные ключи не набирают threshold ни для одного permission, "
            f"разрешающего {op_name}"
        )

    signer_set = set(signer_addresses)

    def coverage(perm: Permission) -> Tuple[int, int, int]:
        covered = sum(1 for k in perm.keys if k.address in signer_set)
        # Предпочитаем permission, куда входят все переданные ключи, затем больший coverage, затем Active
        all_covered = 1 if covered == len(signer_addresses) else 0
        is_active = 1 if perm.type == PermissionType.ACTIVE else 0
        return (all_covered, covered, is_active)

    usable.sort(key=coverage, reverse=True)
    return usable[0]


def simulate_transfer(
    from_address: Optional[str],
    to_address: str,
    amount: str,
    asset: str,
    signer_addresses: List[str],
    permission_id: Optional[int] = None,
    contract_address: Optional[str] = None,
    client: Optional[Tron] = None,
    fee_limit_sun: int = DEFAULT_FEE_LIMIT_SUN,
) -> TransferPlan:
    """Проверяет балансы, права и собирает план перевода без отправки в сеть."""
    asset_name = asset.strip().lower()
    if asset_name not in (ASSET_TRX, ASSET_USDT):
        raise ValueError("Поддерживаются только активы 'trx' и 'usdt'")

    source = from_address or config.default_account
    if not source:
        raise ValueError("Адрес отправителя не указан и отсутствует TRON_ACCOUNT")

    clean_from = validate_tron_address(source)
    clean_to = validate_tron_address(to_address)
    if clean_from == clean_to:
        raise ValueError("Адрес отправителя и получателя совпадают")
    if not signer_addresses:
        raise ValueError("Не передано ни одного адреса подписывающего лица")

    tron_client = client or get_tron_client()
    perms = fetch_account_permissions(tron_client, clean_from)
    permission = select_permission_for_transfer(perms, signer_addresses, asset_name, permission_id)

    warnings: List[str] = []
    if permission.type == PermissionType.OWNER and perms.actives:
        for act in perms.actives:
            can_op = act.can_transfer_trc20 if asset_name == ASSET_USDT else act.can_transfer_trx
            if can_op and act.threshold == 1 and len(act.keys) == 1:
                warnings.append(
                    f"Active #{act.id} по-прежнему позволяет {asset_name.upper()} одной подписью. "
                    f"Мультисиг Owner не защищает этот перевод, если не указать --permission-id {permission.id} "
                    f"или не ужесточить Active."
                )

    extra_signers = [s for s in signer_addresses if permission.get_key(s) is None]
    if extra_signers:
        warnings.append(
            "Часть ключей не входит в выбранное permission и не будет использована при подписи: "
            + ", ".join(extra_signers)
        )

    if asset_name == ASSET_TRX:
        amount_units = parse_trx_amount(amount)
        sender_sun = fetch_account_balance_sun(tron_client, clean_from)
        if sender_sun < amount_units:
            raise ValueError(
                f"Недостаточно TRX: баланс {format_trx_amount(sender_sun)} TRX, "
                f"нужно {format_trx_amount(amount_units)} TRX"
            )
        return TransferPlan(
            asset=ASSET_TRX,
            from_address=clean_from,
            to_address=clean_to,
            amount_display=f"{format_trx_amount(amount_units)} TRX",
            amount_units=amount_units,
            decimals=6,
            symbol="TRX",
            permission=permission,
            signer_addresses=signer_addresses,
            available_weight=permission.calculate_weight(signer_addresses),
            sender_balance_display=f"{format_trx_amount(sender_sun)} TRX",
            warnings=warnings,
            can_proceed=True,
        )

    token_contract = validate_tron_address(contract_address or get_usdt_contract())
    raw_balance, decimals = fetch_trc20_balance(tron_client, clean_from, token_contract)
    amount_units = parse_token_amount(amount, decimals)
    if raw_balance < amount_units:
        raise ValueError(
            f"Недостаточно USDT: баланс {format_token_amount(raw_balance, decimals)} USDT, "
            f"нужно {format_token_amount(amount_units, decimals)} USDT"
        )

    trx_balance_sun = fetch_account_balance_sun(tron_client, clean_from)
    if trx_balance_sun <= 0:
        warnings.append("На аккаунте 0 TRX: вызов смарт-контракта USDT может не пройти из-за нехватки Energy/Bandwidth.")

    return TransferPlan(
        asset=ASSET_USDT,
        from_address=clean_from,
        to_address=clean_to,
        amount_display=f"{format_token_amount(amount_units, decimals)} USDT",
        amount_units=amount_units,
        decimals=decimals,
        symbol="USDT",
        permission=permission,
        signer_addresses=signer_addresses,
        available_weight=permission.calculate_weight(signer_addresses),
        sender_balance_display=f"{format_token_amount(raw_balance, decimals)} USDT",
        contract_address=token_contract,
        fee_limit_sun=fee_limit_sun,
        warnings=warnings,
        can_proceed=True,
    )


def execute_transfer(
    plan: TransferPlan,
    signing_private_keys: List[str],
    client: Optional[Tron] = None,
    timeout: float = 30.0,
) -> Tuple[str, Dict[str, Any]]:
    """Собирает, подписывает и отправляет перевод по заранее проверенному плану."""
    if not signing_private_keys:
        raise ValueError("Не передано ни одного приватного ключа для подписи")

    tron_client = client or get_tron_client()

    allowed_addresses = {k.address for k in plan.permission.keys}
    filtered_keys: List[str] = []
    for pk in signing_private_keys:
        addr = address_from_private_key(pk)
        if addr in allowed_addresses and pk not in filtered_keys:
            filtered_keys.append(pk)

    if not filtered_keys:
        raise ValueError("Ни один из расшифрованных ключей не входит в выбранное permission")

    filtered_addrs = [address_from_private_key(pk) for pk in filtered_keys]
    if not plan.permission.has_access(filtered_addrs):
        raise ValueError(
            f"После отбора ключей вес {plan.permission.calculate_weight(filtered_addrs)} "
            f"меньше порога {plan.permission.threshold}"
        )

    if plan.asset == ASSET_TRX:
        tx = build_trx_transfer_transaction(
            client=tron_client,
            from_address=plan.from_address,
            to_address=plan.to_address,
            amount_sun=plan.amount_units,
            permission_id=plan.permission.id,
        )
    else:
        if not plan.contract_address:
            raise ValueError("Для перевода USDT не задан адрес контракта")
        tx = build_trc20_transfer_transaction(
            client=tron_client,
            from_address=plan.from_address,
            to_address=plan.to_address,
            contract_address=plan.contract_address,
            amount_units=plan.amount_units,
            permission_id=plan.permission.id,
            fee_limit_sun=plan.fee_limit_sun,
        )

    signed = sign_transaction(tx, filtered_keys)
    return broadcast_and_wait(signed, timeout=timeout)
