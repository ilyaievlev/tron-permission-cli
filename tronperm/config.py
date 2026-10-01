"""Конфигурация приложения и сетевых параметров TRON."""

import os
from pathlib import Path
from typing import Optional
from dotenv import load_dotenv

# Загружаем переменные окружения из .env файла
load_dotenv()


class NetworkConfig:
    """Параметры сетей TRON."""
    MAINNET = "mainnet"
    SHASTA = "shasta"
    NILE = "nile"

    ENDPOINTS = {
        MAINNET: "https://api.trongrid.io",
        SHASTA: "https://api.shasta.trongrid.io",
        NILE: "https://nile.trongrid.io",
    }


class Config:
    """Глобальная конфигурация приложения."""

    @property
    def network(self) -> str:
        """Имя текущей сети (mainnet, shasta, nile)."""
        net = os.getenv("TRON_NETWORK", NetworkConfig.SHASTA).strip().lower()
        if net not in NetworkConfig.ENDPOINTS:
            raise ValueError(
                f"Неизвестная сеть '{net}'. Доступные варианты: {', '.join(NetworkConfig.ENDPOINTS.keys())}"
            )
        return net

    @property
    def is_mainnet(self) -> bool:
        """Флаг основной сети Mainnet (для предупреждений)."""
        return self.network == NetworkConfig.MAINNET

    @property
    def trongrid_api_key(self) -> Optional[str]:
        """API-ключ TronGrid."""
        key = os.getenv("TRONGRID_API_KEY", "").strip()
        return key if key else None

    @property
    def default_account(self) -> Optional[str]:
        """Адрес аккаунта по умолчанию из .env."""
        addr = os.getenv("TRON_ACCOUNT", "").strip()
        return addr if addr else None

    @property
    def default_owner_private_key(self) -> Optional[str]:
        """Опциональный приватный ключ для разработки (не рекомендуется для продакшена)."""
        pk = os.getenv("OWNER_PRIVATE_KEY", "").strip()
        return pk if pk else None

    @property
    def usdt_contract(self) -> Optional[str]:
        """Переопределение адреса контракта USDT (TRC-20)."""
        addr = os.getenv("USDT_CONTRACT", "").strip()
        return addr if addr else None

    @property
    def keys_dir(self) -> Path:
        """Директория хранения зашифрованных ключей."""
        return Path("keys")


config = Config()
