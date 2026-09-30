"""Зашифрованное хранилище ключей (Keystore)."""

import json
import os
from pathlib import Path
from typing import Any, Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from tronperm.keys.validate import (
    validate_private_key,
    validate_tron_address,
)

# 600 000 итераций PBKDF2 по рекомендации OWASP
PBKDF2_ITERATIONS = 600_000
KEYSTORE_VERSION = 1


class KeystoreError(Exception):
    """Базовая ошибка хранилища ключей."""


class InvalidPasswordError(KeystoreError):
    """Неверный пароль или поврежденные данные ключа."""


def _derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """Генерирует 256-битный ключ из пароля через PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def save_keystore(
    file_path: Path | str,
    private_key: str,
    address: str,
    password: str,
) -> Path:
    """Шифрует приватный ключ (AES-256-GCM) и сохраняет в JSON с правами 0600."""
    path = Path(file_path)
    clean_pk = validate_private_key(private_key)
    clean_addr = validate_tron_address(address)

    if not password:
        raise ValueError("Пароль не может быть пустым")

    # 16 байт соли и 12 байт nonce для AES-GCM
    salt = os.urandom(16)
    nonce = os.urandom(12)

    derived_key = _derive_key(password, salt, PBKDF2_ITERATIONS)
    aesgcm = AESGCM(derived_key)

    ciphertext = aesgcm.encrypt(nonce, clean_pk.encode("utf-8"), None)

    keystore_data: Dict[str, Any] = {
        "version": KEYSTORE_VERSION,
        "address": clean_addr,
        "crypto": {
            "cipher": "aes-256-gcm",
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "kdf": "pbkdf2-sha256",
            "kdfparams": {
                "iterations": PBKDF2_ITERATIONS,
                "salt": salt.hex(),
            },
        },
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    # Запись с ограничением доступа только текущему пользователю (-rw-------)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(keystore_data, f, indent=2)

    return path


def read_keystore_address(file_path: Path | str) -> str:
    """Читает адрес из файла ключа без запроса пароля."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Файл ключа не найден: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    address = data.get("address")
    if not address:
        raise KeystoreError("В keystore отсутствует поле 'address'")

    return validate_tron_address(address)


def load_private_key(file_path: Path | str, password: str) -> str:
    """Расшифровывает и возвращает hex-приватный ключ."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"Файл ключа не найден: {path}")

    with path.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if data.get("version") != KEYSTORE_VERSION:
        raise KeystoreError(f"Неподдерживаемая версия keystore: {data.get('version')}")

    crypto = data.get("crypto", {})
    if crypto.get("cipher") != "aes-256-gcm":
        raise KeystoreError(f"Неподдерживаемый шифр: {crypto.get('cipher')}")

    kdfparams = crypto.get("kdfparams", {})
    salt = bytes.fromhex(kdfparams["salt"])
    iterations = int(kdfparams.get("iterations", PBKDF2_ITERATIONS))
    nonce = bytes.fromhex(crypto["nonce"])
    ciphertext = bytes.fromhex(crypto["ciphertext"])

    derived_key = _derive_key(password, salt, iterations)
    aesgcm = AESGCM(derived_key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return validate_private_key(decrypted_bytes.decode("utf-8"))
    except (InvalidTag, UnicodeDecodeError):
        raise InvalidPasswordError("Неверный пароль для расшифровки приватного ключа")
