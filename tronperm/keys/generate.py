"""Генерация криптографических ключей TRON."""

from dataclasses import dataclass
import secrets
from tronpy.keys import PrivateKey


@dataclass(frozen=True)
class GeneratedKey:
    """Сгенерированная пара ключей TRON."""
    private_key: str
    public_key: str
    address: str

    def __repr__(self) -> str:
        # Защита от случайного логирования приватного ключа
        return f"GeneratedKey(address='{self.address}', public_key='{self.public_key}', private_key='***')"


def generate_keypair() -> GeneratedKey:
    """Генерирует криптографически стойкую пару ключей TRON."""
    random_bytes = secrets.token_bytes(32)
    pk = PrivateKey(random_bytes)
    return GeneratedKey(
        private_key=pk.hex(),
        public_key=pk.public_key.hex(),
        address=pk.public_key.to_base58check_address(),
    )
