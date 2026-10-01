"""Адреса и единицы измерения токенов TRON (TRX, USDT TRC-20)."""

from decimal import Decimal, ROUND_DOWN
from typing import Optional

from tronperm.config import NetworkConfig, config

# 1 TRX = 1_000_000 SUN
SUN_PER_TRX = 1_000_000

# Известные контракты USDT TRC-20 по сетям
USDT_CONTRACTS = {
    NetworkConfig.MAINNET: "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",
    NetworkConfig.SHASTA: "TG3XXyExBkPp9nzdajDZsozEu4BkaSJozs",
    NetworkConfig.NILE: "TXYZopYRdj2D9XRtbG411XZZ3kM5VkAeBf",
}

DEFAULT_USDT_DECIMALS = 6
# Лимит комиссии за вызов смарт-контракта (15 TRX в SUN)
DEFAULT_FEE_LIMIT_SUN = 15_000_000


def get_usdt_contract(network: Optional[str] = None) -> str:
    """Возвращает адрес контракта USDT для текущей или указанной сети.

    Можно переопределить переменной окружения USDT_CONTRACT.
    """
    override = config.usdt_contract
    if override:
        return override

    net = (network or config.network).strip().lower()
    if net not in USDT_CONTRACTS:
        raise ValueError(f"Неизвестная сеть для USDT: {net}")
    return USDT_CONTRACTS[net]


def parse_token_amount(amount: str | Decimal, decimals: int) -> int:
    """Переводит человекочитаемую сумму в целые единицы токена (SUN / 10^decimals)."""
    value = Decimal(str(amount).strip())
    if value <= 0:
        raise ValueError("Сумма перевода должна быть больше нуля")

    scale = Decimal(10) ** decimals
    units = (value * scale).quantize(Decimal("1"), rounding=ROUND_DOWN)
    if units <= 0:
        raise ValueError(f"Сумма слишком мала для {decimals} знаков после запятой")
    return int(units)


def format_token_amount(units: int, decimals: int) -> str:
    """Форматирует целые единицы токена в человекочитаемую строку."""
    scale = Decimal(10) ** decimals
    value = Decimal(units) / scale
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


def parse_trx_amount(amount: str | Decimal) -> int:
    """Переводит сумму TRX в SUN."""
    return parse_token_amount(amount, 6)


def format_trx_amount(sun: int) -> str:
    """Форматирует SUN в строку TRX."""
    return format_token_amount(sun, 6)
