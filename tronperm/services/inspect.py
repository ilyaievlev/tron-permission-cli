"""Сервис инспекции и форматированного вывода прав аккаунта TRON."""

from dataclasses import dataclass
from typing import List, Optional
from tronpy import Tron

from tronperm.config import config
from tronperm.keys.validate import validate_tron_address
from tronperm.tron.account import (
    AccountNotFoundError,
    fetch_account_balance,
    fetch_account_permissions,
)
from tronperm.tron.client import get_tron_client
from tronperm.tron.permissions import AccountPermissions, Permission


@dataclass
class AccountInspectionReport:
    """Полный отчет о правах и балансе аккаунта TRON."""
    address: str
    balance_trx: float
    permissions: AccountPermissions

    @property
    def owner(self) -> Permission:
        return self.permissions.owner

    @property
    def witness(self) -> Optional[Permission]:
        return self.permissions.witness

    @property
    def actives(self) -> List[Permission]:
        return self.permissions.actives


def inspect_account(
    address: Optional[str] = None,
    client: Optional[Tron] = None,
) -> AccountInspectionReport:
    """Запрашивает из блокчейна актуальные права и баланс аккаунта.

    Args:
        address: TRON-адрес. Если не указан, берется из TRON_ACCOUNT в .env.
        client: Экземпляр клиента Tron. Если не передан, создается дефолтный.

    Returns:
        AccountInspectionReport с правами и балансом.

    Raises:
        ValueError: Если адрес не передан и не задан в .env.
        AccountNotFoundError: Если аккаунт не найден в блокчейне.
    """
    target_addr = address or config.default_account
    if not target_addr:
        raise ValueError("Адрес аккаунта не указан и отсутствует TRON_ACCOUNT в конфигурации")

    clean_addr = validate_tron_address(target_addr)
    tron_client = client or get_tron_client()

    balance = fetch_account_balance(tron_client, clean_addr)
    perms = fetch_account_permissions(tron_client, clean_addr)

    return AccountInspectionReport(
        address=clean_addr,
        balance_trx=balance,
        permissions=perms,
    )
