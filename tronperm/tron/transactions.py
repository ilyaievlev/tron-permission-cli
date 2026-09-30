"""Создание, подписание и отправка транзакций AccountPermissionUpdate."""

from typing import Any, Dict, Iterable, Tuple
from tronpy import Tron
from tronpy.exceptions import BadKey, TransactionNotFound
from tronpy.keys import PrivateKey
from tronpy.tron import Transaction

from tronperm.keys.validate import validate_private_key, validate_tron_address
from tronperm.tron.permissions import AccountPermissions


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
        return (txid, receipt)
    except TransactionNotFound:
        raise ConfirmationTimeoutError(
            f"Транзакция {txid} отправлена в мемпул, но не подтверждена за {timeout} секунд. "
            f"Проверьте статус в эксплорере через некоторое время."
        )
