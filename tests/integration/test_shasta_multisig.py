"""Живые проверки Shasta. Никогда не запускаются на mainnet и не делают broadcast."""

import os

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.getenv("RUN_SHASTA_INTEGRATION") != "1"
        or os.getenv("TRON_NETWORK", "shasta").strip().lower() != "shasta",
        reason="Set RUN_SHASTA_INTEGRATION=1 and TRON_NETWORK=shasta (never mainnet)",
    ),
]


def test_refuses_mainnet_network() -> None:
    from tronperm.config import config

    assert config.network == "shasta"
    assert config.is_mainnet is False


def test_inspect_shasta_account_owner_only_edits_permissions() -> None:
    from tronperm.config import config
    from tronperm.services.inspect import inspect_account

    if config.is_mainnet:
        pytest.fail("Integration tests must never run against mainnet")
    if not config.default_account:
        pytest.skip("TRON_ACCOUNT is not set")

    report = inspect_account(config.default_account)
    assert report.owner.id == 0
    assert report.owner.can_modify_permissions is True
    for active in report.actives:
        assert active.can_modify_permissions is False
