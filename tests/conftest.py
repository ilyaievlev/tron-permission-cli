"""Общие фикстуры для unit-тестов tronperm."""

import pytest

from tronperm.keys.generate import generate_keypair


@pytest.fixture(scope="session")
def key_a():
    return generate_keypair()


@pytest.fixture(scope="session")
def key_b():
    return generate_keypair()
