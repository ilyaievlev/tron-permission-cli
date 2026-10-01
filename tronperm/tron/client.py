"""Клиент подключения к блокчейну TRON через TronPy."""

from typing import Optional
from tronpy import Tron
from tronpy.defaults import conf_for_name
from tronpy.providers import HTTPProvider

from tronperm.config import config


def get_tron_client(
    network: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: float = 10.0,
) -> Tron:
    """Создаёт и возвращает настроенный экземпляр TronPy Tron клиента.

    Args:
        network: Имя сети ('mainnet', 'shasta', 'nile'). По умолчанию из .env.
        api_key: API-ключ TronGrid (опционально).
        timeout: Таймаут запросов в секундах.
    """
    net = (network or config.network).strip().lower()
    key = api_key or config.trongrid_api_key
    conf = conf_for_name(net)
    if key:
        provider = HTTPProvider(conf, timeout=timeout, api_key=key)
    else:
        provider = HTTPProvider(conf, timeout=timeout)
    return Tron(provider=provider, network=net)
