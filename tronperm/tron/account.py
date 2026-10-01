"""Чтение и нормализация данных аккаунта TRON."""

from typing import Tuple
from tronpy import Tron
from tronpy.exceptions import AddressNotFound

from tronperm.keys.validate import validate_tron_address
from tronperm.tron.permissions import AccountPermissions

# Fallback, если нода не вернула chain parameter (значение в TRX)
FALLBACK_PERMISSION_UPDATE_FEE_TRX = 100.0
PERMISSION_UPDATE_FEE_PARAM = "getUpdateAccountPermissionFee"
SUN_PER_TRX = 1_000_000

# Совместимость со старым именем константы
PERMISSION_UPDATE_FEE_TRX = FALLBACK_PERMISSION_UPDATE_FEE_TRX


class AccountError(Exception):
    """Базовое исключение для ошибок аккаунта."""


class AccountNotFoundError(AccountError):
    """Аккаунт не активирован или не найден в блокчейне."""


def fetch_account_permissions(client: Tron, address: str) -> AccountPermissions:
    """Запрашивает и нормализует permissions аккаунта из блокчейна TRON.

    Args:
        client: Экземпляр клиента Tron.
        address: TRON Base58Check адрес.

    Returns:
        Нормализованный объект AccountPermissions.

    Raises:
        AccountNotFoundError: Если адрес ещё не активирован в сети.
        ValueError: При невалидном адресе.
    """
    clean_addr = validate_tron_address(address)
    try:
        raw_perm = client.get_account_permission(clean_addr)
        return AccountPermissions.from_tronpy_dict(raw_perm)
    except AddressNotFound:
        raise AccountNotFoundError(
            f"Аккаунт {clean_addr} не найден в сети. Возможно, он ещё не активирован (требуется перевод TRX)."
        )
    except Exception as e:
        if "not found" in str(e).lower():
            raise AccountNotFoundError(f"Аккаунт {clean_addr} не найден в блокчейне.")
        raise


def fetch_account_balance_sun(client: Tron, address: str) -> int:
    """Возвращает баланс аккаунта в SUN (1 TRX = 1_000_000 SUN)."""
    clean_addr = validate_tron_address(address)
    try:
        account_info = client.get_account(clean_addr)
        return int(account_info.get("balance", 0) or 0)
    except AddressNotFound:
        return 0


def fetch_account_balance(client: Tron, address: str) -> float:
    """Возвращает баланс аккаунта в TRX.

    Args:
        client: Экземпляр клиента Tron.
        address: TRON Base58Check адрес.
    """
    return fetch_account_balance_sun(client, address) / 1_000_000.0


def fetch_trc20_balance(
    client: Tron,
    owner_address: str,
    contract_address: str,
) -> tuple[int, int]:
    """Возвращает (баланс в минимальных единицах, decimals) токена TRC-20."""
    from tronperm.tron.tokens import DEFAULT_USDT_DECIMALS

    clean_owner = validate_tron_address(owner_address)
    clean_contract = validate_tron_address(contract_address)
    try:
        contract = client.get_contract(clean_contract)
    except Exception as e:
        raise AccountError(f"Не удалось загрузить контракт {clean_contract}: {e}") from e

    decimals = DEFAULT_USDT_DECIMALS
    try:
        decimals = int(contract.functions.decimals.with_owner(clean_owner)())
    except Exception:
        pass

    try:
        raw_balance = contract.functions.balanceOf.with_owner(clean_owner)(clean_owner)
        return (int(raw_balance), decimals)
    except Exception as e:
        raise AccountError(f"Не удалось прочитать баланс TRC-20 {clean_contract}: {e}") from e


def fetch_permission_update_fee_trx(client: Tron) -> Tuple[float, bool]:
    """Читает комиссию AccountPermissionUpdateContract из chain parameters.

    Returns:
        (fee_trx, from_chain): from_chain=False означает, что использован fallback 100 TRX.
    """
    try:
        params = client.get_chain_parameters()
        items = params if isinstance(params, list) else []
        for item in items:
            name = str(item.get("key") or item.get("name") or "")
            if name == PERMISSION_UPDATE_FEE_PARAM:
                value = item.get("value")
                if value is None:
                    break
                fee_trx = int(value) / SUN_PER_TRX
                if fee_trx > 0:
                    return (fee_trx, True)
                break
    except Exception:
        pass
    return (FALLBACK_PERMISSION_UPDATE_FEE_TRX, False)


def check_funds_for_permission_update(client: Tron, address: str) -> Tuple[bool, float, float, bool]:
    """Проверяет, достаточно ли TRX для комиссии за смену прав.

    Returns:
        (has_enough_funds, current_balance_trx, required_fee_trx, fee_from_chain)
    """
    fee_trx, from_chain = fetch_permission_update_fee_trx(client)
    balance = fetch_account_balance(client, address)
    return (balance >= fee_trx, balance, fee_trx, from_chain)
