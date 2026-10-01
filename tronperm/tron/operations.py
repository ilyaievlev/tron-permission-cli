"""Битовая маска разрешённых операций (operations) в TRON Active Permissions."""

from enum import IntEnum
from typing import Iterable, Set


class TronContractType(IntEnum):
    """Типы системных контрактов TRON (core/Tron.proto)."""
    AccountCreateContract = 0
    TransferContract = 1                      # Перевод TRX
    TransferAssetContract = 2                 # Перевод TRC-10 токенов
    VoteAssetContract = 3
    VoteWitnessContract = 4                   # Голосование за суперпредставителей (SR)
    WitnessCreateContract = 5
    AssetIssueContract = 6
    WitnessUpdateContract = 8
    ParticipateAssetIssueContract = 9
    AccountUpdateContract = 10
    FreezeBalanceContract = 11                # Стейкинг 1.0 (заморозка)
    UnfreezeBalanceContract = 12
    WithdrawBalanceContract = 13
    UnfreezeAssetContract = 14
    UpdateAssetContract = 15
    ProposalCreateContract = 16
    ProposalApproveContract = 17
    ProposalDeleteContract = 18
    SetAccountIdContract = 19
    CustomContract = 20
    CreateSmartContract = 30                  # Деплой смарт-контракта
    TriggerSmartContract = 31                 # Вызов смарт-контракта (TRC-20, USDT)
    GetContract = 32
    UpdateSettingContract = 33
    ExchangeCreateContract = 41
    ExchangeInjectContract = 42
    ExchangeWithdrawContract = 43
    ExchangeTransactionContract = 44
    UpdateEnergyLimitContract = 45
    AccountPermissionUpdateContract = 46      # Смена прав аккаунта
    ClearABIContract = 48
    UpdateBrokerageContract = 49
    ShieldedTransferContract = 51
    MarketSellAssetContract = 52
    MarketCancelOrderContract = 53
    FreezeBalanceV2Contract = 54              # Стейкинг 2.0
    UnfreezeBalanceV2Contract = 55
    WithdrawExpireUnfreezeContract = 56
    DelegateResourceContract = 57             # Делегирование энергии / Bandwidth
    UnDelegateResourceContract = 58
    CancelAllUnfreezeV2Contract = 59


# Карта ID -> название контракта
CONTRACT_TYPE_NAMES = {c.value: c.name for c in TronContractType}

# Обратная карта (название в нижнем регистре -> ID)
CONTRACT_NAME_TO_ID = {c.name.lower(): c.value for c in TronContractType}

# Стандартная маска активного разрешения без смены прав (64 hex-символа = 32 байта)
DEFAULT_ACTIVE_OPERATIONS_HEX = "7fff1fc0033e0000000000000000000000000000000000000000000000000000"


def normalize_operations_hex(hex_str: str) -> str:
    """Нормализует строку operations до 64 hex-символов.
    
    Бросает ValueError при невалидном формате.
    """
    clean = hex_str.strip()
    if clean.startswith(("0x", "0X")):
        clean = clean[2:]
    if len(clean) != 64:
        raise ValueError(f"Маска операций должна содержать ровно 64 hex-символа (32 байта), получено: {len(clean)}")
    try:
        int(clean, 16)
    except ValueError:
        raise ValueError(f"Маска операций содержит недопустимые hex-символы: {hex_str}")
    return clean.lower()


def decode_operation_ids(operations_hex: str) -> Set[int]:
    """Декодирует hex-маску operations в множество числовых ID контрактов.
    
    В протоколе TRON: бит (id % 8) в байте (id // 8).
    """
    clean = normalize_operations_hex(operations_hex)
    raw = bytes.fromhex(clean)
    enabled_ids: Set[int] = set()

    for i in range(256):
        byte_index = i // 8
        bit_index = i % 8
        if raw[byte_index] & (1 << bit_index):
            enabled_ids.add(i)

    return enabled_ids


def decode_operations(operations_hex: str) -> Set[str]:
    """Декодирует hex-маску operations в человекочитаемые названия контрактов."""
    ids = decode_operation_ids(operations_hex)
    return {CONTRACT_TYPE_NAMES.get(i, f"ContractType_{i}") for i in ids}


def encode_operations(operations: Iterable[str | int | TronContractType]) -> str:
    """Кодирует список названий или ID контрактов в 64-символьную hex-маску TRON."""
    raw = bytearray(32)

    for item in operations:
        if isinstance(item, TronContractType):
            cid = item.value
        elif isinstance(item, int):
            cid = item
        elif isinstance(item, str):
            clean_name = item.strip().lower()
            if clean_name not in CONTRACT_NAME_TO_ID:
                raise ValueError(f"Неизвестный тип контракта TRON: '{item}'")
            cid = CONTRACT_NAME_TO_ID[clean_name]
        else:
            raise TypeError(f"Недопустимый тип операции: {type(item)}")

        if not 0 <= cid < 256:
            raise ValueError(f"ID контракта должен быть от 0 до 255, получено: {cid}")

        byte_index = cid // 8
        bit_index = cid % 8
        raw[byte_index] |= (1 << bit_index)

    return raw.hex()


def _enabled_contract_ids(operations: str | Iterable[str | int]) -> Set[int]:
    """Приводит hex-маску или список операций к множеству ID контрактов."""
    if isinstance(operations, str):
        return decode_operation_ids(operations)
    enabled_ids: Set[int] = set()
    for item in operations:
        if isinstance(item, TronContractType):
            enabled_ids.add(item.value)
        elif isinstance(item, int):
            enabled_ids.add(item)
        elif isinstance(item, str):
            enabled_ids.add(CONTRACT_NAME_TO_ID.get(item.strip().lower(), -1))
        else:
            raise TypeError(f"Недопустимый тип операции: {type(item)}")
    return enabled_ids


def can_transfer_trx(operations: str | Iterable[str | int]) -> bool:
    """Проверяет, разрешен ли перевод нативного TRX (TransferContract)."""
    return TronContractType.TransferContract.value in _enabled_contract_ids(operations)


def can_transfer_trc20(operations: str | Iterable[str | int]) -> bool:
    """Проверяет, разрешен ли вызов смарт-контрактов / TRC-20 (TriggerSmartContract)."""
    return TronContractType.TriggerSmartContract.value in _enabled_contract_ids(operations)


def has_account_permission_update_bit(operations: str | Iterable[str | int]) -> bool:
    """Проверяет наличие бита AccountPermissionUpdateContract в маске Active.

    Это факт битовой маски, а не доказательство, что Active может сменить права.
    Смена permissions в TRON выполняется Owner permission (id = 0).
    """
    return TronContractType.AccountPermissionUpdateContract.value in _enabled_contract_ids(operations)


def can_modify_permissions(operations: str | Iterable[str | int]) -> bool:
    """Устаревший алиас: только бит AccountPermissionUpdateContract в operations."""
    return has_account_permission_update_bit(operations)
