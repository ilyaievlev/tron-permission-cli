"""Валидация адресов и приватных ключей TRON."""

import re
from tronpy.keys import is_address

# Порядок эллиптической кривой secp256k1
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
HEX_64_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def is_valid_tron_address(address: str) -> bool:
    """Проверяет валидность TRON-адреса (Base58Check)."""
    if not isinstance(address, str):
        return False
    if len(address) != 34 or not address.startswith("T"):
        return False
    if any(c not in BASE58_ALPHABET for c in address):
        return False

    try:
        return is_address(address)
    except Exception:
        return False


def validate_tron_address(address: str) -> str:
    """Проверяет и возвращает очищенный TRON-адрес.
    
    Бросает ValueError, если адрес некорректен.
    """
    clean_addr = address.strip()
    if not is_valid_tron_address(clean_addr):
        raise ValueError(f"Некорректный TRON-адрес: {address}")
    return clean_addr


def is_valid_private_key(hex_key: str) -> bool:
    """Проверяет, что строка — это корректный 32-байтный ключ secp256k1 в hex."""
    if not isinstance(hex_key, str):
        return False
    clean = hex_key.strip()
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]
    if not HEX_64_REGEX.match(clean):
        return False

    val = int(clean, 16)
    return 1 <= val < SECP256K1_N


def validate_private_key(hex_key: str) -> str:
    """Проверяет приватный ключ и возвращает 64 hex-символа в нижнем регистре.
    
    Бросает ValueError без утечки значения ключа в текст ошибки.
    """
    if not is_valid_private_key(hex_key):
        raise ValueError("Некорректный приватный ключ (ожидается 64 hex-символа secp256k1)")
    clean = hex_key.strip()
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]
    return clean.lower()
