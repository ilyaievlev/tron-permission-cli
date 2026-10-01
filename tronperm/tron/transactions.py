"""Создание, подписание и отправка транзакций TRON."""

from typing import Any, Dict, Iterable, Tuple
from tronpy import Tron
from tronpy.exceptions import BadKey, TransactionNotFound
from tronpy.keys import PrivateKey
from tronpy.tron import Transaction

from tronperm.keys.validate import validate_private_key, validate_tron_address
from tronperm.tron.permissions import AccountPermissions
from tronperm.tron.tokens import DEFAULT_FEE_LIMIT_SUN


class TransactionError(Exception):
    """Базовое исключение для ошибок транзакций."""


class BroadcastError(TransactionError):
    """Ошибка валидации или отправки транзакции нодой TRON."""


class ConfirmationTimeoutError(TransactionError):
    """Транзакция отправлена, но не подтверждена за отведенное время."""


def build_permission_update_transaction(
    client: Tron,
    owner_address: str,
    permissions: AccountPermissions,
) -> Transaction:
    """Формирует транзакцию AccountPermissionUpdateContract без отправки в сеть.

    Args:
        client: Экземпляр клиента Tron.
        owner_address: Адрес владельца аккаунта (Base58Check).
        permissions: Новая конфигурация permissions.

    Returns:
        Собранный объект Transaction, готовый к подписи.
    """
    clean_owner = validate_tron_address(owner_address)
    perm_dict = permissions.to_tronpy_dict()

    try:
        tx_builder = client.trx.account_permission_update(clean_owner, perm_dict)
        return tx_builder.build()
    except Exception as e:
        raise TransactionError(f"Ошибка при сборке транзакции AccountPermissionUpdate: {e}") from e


def build_trx_transfer_transaction(
    client: Tron,
    from_address: str,
    to_address: str,
    amount_sun: int,
    permission_id: int = 0,
) -> Transaction:
    """Формирует транзакцию перевода нативного TRX (TransferContract)."""
    clean_from = validate_tron_address(from_address)
    clean_to = validate_tron_address(to_address)
    if amount_sun <= 0:
        raise TransactionError("Сумма перевода TRX должна быть больше нуля")

    try:
        builder = client.trx.transfer(clean_from, clean_to, amount_sun)
        if permission_id:
            builder = builder.permission_id(permission_id)
        return builder.build()
    except Exception as e:
        raise TransactionError(f"Ошибка при сборке перевода TRX: {e}") from e


def build_trc20_transfer_transaction(
    client: Tron,
    from_address: str,
    to_address: str,
    contract_address: str,
    amount_units: int,
    permission_id: int = 0,
    fee_limit_sun: int = DEFAULT_FEE_LIMIT_SUN,
) -> Transaction:
    """Формирует транзакцию перевода TRC-20 (TriggerSmartContract.transfer)."""
    clean_from = validate_tron_address(from_address)
    clean_to = validate_tron_address(to_address)
    clean_contract = validate_tron_address(contract_address)
    if amount_units <= 0:
        raise TransactionError("Сумма перевода токена должна быть больше нуля")

    try:
        contract = client.get_contract(clean_contract)
        builder = (
            contract.functions.transfer(clean_to, amount_units)
            .with_owner(clean_from)
            .fee_limit(fee_limit_sun)
        )
        if permission_id:
            builder = builder.permission_id(permission_id)
        return builder.build()
    except Exception as e:
        raise TransactionError(f"Ошибка при сборке перевода TRC-20: {e}") from e


def sign_transaction(
    transaction: Transaction,
    private_keys: Iterable[str],
) -> Transaction:
    """Подписывает транзакцию одним или несколькими приватными ключами.

    Args:
        transaction: Собранный объект Transaction.
        private_keys: Итерируемый набор hex-строк приватных ключей.

    Returns:
        Тот же объект Transaction с добавленными подписями.
    """
    for pk_hex in private_keys:
        clean_pk = validate_private_key(pk_hex)
        pk_obj = PrivateKey(bytes.fromhex(clean_pk))
        try:
            transaction.sign(pk_obj)
        except BadKey as e:
            raise TransactionError(
                f"Ключ {pk_obj.public_key.to_base58check_address()} не входит в список разрешённых подписывающих лиц."
            ) from e
        except Exception as e:
            raise TransactionError(f"Ошибка при подписи транзакции: {e}") from e

    return transaction


def broadcast_and_wait(
    transaction: Transaction,
    timeout: float = 30.0,
) -> Tuple[str, Dict[str, Any]]:
    """Отправляет подписанную транзакцию в сеть и ждёт подтверждения в блоке.

    Args:
        transaction: Подписанная транзакция.
        timeout: Максимальное время ожидания подтверждения в секундах.

    Returns:
        Кортеж (txid, receipt_dict).

    Raises:
        BroadcastError: Если нода отклонила транзакцию.
        ConfirmationTimeoutError: Если транзакция не попала в блок за timeout секунд.
    """
    try:
        ret = transaction.broadcast()
    except Exception as e:
        raise BroadcastError(f"Сетевая ошибка при отправке транзакции: {e}") from e

    # Проверяем ответ ноды TRON
    result_val = ret.get("result")
    if result_val is False:
        code = ret.get("code", "UNKNOWN")
        message = ret.get("message", "Транзакция отклонена нодой")
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        elif isinstance(message, str) and message.startswith("0x"):
            try:
                message = bytes.fromhex(message[2:]).decode("utf-8", errors="replace")
            except Exception:
                pass
        raise BroadcastError(f"Нода отклонила транзакцию ({code}): {message}")

    txid = ret.get("txid") or transaction.txid
    if not txid:
        raise BroadcastError("Нода не вернула txid для отправленной транзакции")

    try:
        receipt = ret.wait(timeout=timeout)
    except TransactionNotFound:
        raise ConfirmationTimeoutError(
            f"Транзакция {txid} отправлена в мемпул, но не подтверждена за {timeout} секунд. "
            f"Проверьте статус в эксплорере через некоторое время."
        )

    exec_result = receipt.get("receipt", {}).get("result") if isinstance(receipt, dict) else None
    if exec_result and str(exec_result).upper() not in ("SUCCESS", "DEFAULT"):
        raise BroadcastError(
            f"Транзакция {txid} попала в блок, но исполнение завершилось с ошибкой: {exec_result}"
        )

    return (txid, receipt)
