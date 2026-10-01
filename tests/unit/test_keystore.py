"""AES-256-GCM keystore и отсутствие утечек приватного ключа."""

import pytest

from tronperm.keys import (
    InvalidPasswordError,
    generate_keypair,
    load_private_key,
    read_keystore_address,
    save_keystore,
    validate_private_key,
)


def test_keystore_roundtrip(tmp_path) -> None:
    key = generate_keypair()
    path = tmp_path / "owner.json"
    save_keystore(path, key.private_key, key.address, "correct-password")
    assert read_keystore_address(path) == key.address
    assert load_private_key(path, "correct-password") == key.private_key.lower()


def test_keystore_wrong_password(tmp_path) -> None:
    key = generate_keypair()
    path = tmp_path / "owner.json"
    save_keystore(path, key.private_key, key.address, "correct-password")
    with pytest.raises(InvalidPasswordError):
        load_private_key(path, "wrong-password")


def test_generated_key_repr_hides_private_key() -> None:
    key = generate_keypair()
    text = repr(key)
    assert key.private_key not in text
    assert "***" in text
    assert key.address in text


def test_validate_private_key_error_does_not_leak_secret() -> None:
    secret = "0" * 64
    with pytest.raises(ValueError) as exc:
        validate_private_key("not-a-key")
    assert "not-a-key" not in str(exc.value)
    with pytest.raises(ValueError) as exc2:
        validate_private_key(secret)
    assert secret not in str(exc2.value)
