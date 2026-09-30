"""Модели данных и валидация TRON Account Permissions."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator, model_validator
from tronpy.keys import to_base58check_address

from tronperm.keys.validate import is_valid_tron_address, validate_tron_address
from tronperm.tron.operations import (
    DEFAULT_ACTIVE_OPERATIONS_HEX,
    can_modify_permissions,
    can_transfer_trc20,
    can_transfer_trx,
    decode_operations,
    normalize_operations_hex,
)


class PermissionType(str, Enum):
    """Типы разрешений в протоколе TRON."""
    OWNER = "Owner"
    WITNESS = "Witness"
    ACTIVE = "Active"


class KeyWeight(BaseModel):
    """Пара: TRON-адрес подписывающего лица и его вес голоса."""
    address: str = Field(description="TRON Base58Check адрес (T...)")
    weight: int = Field(ge=1, description="Вес голоса ключа (целое число >= 1)")

    @field_validator("address")
    @classmethod
    def validate_addr(cls, v: str) -> str:
        # Нормализуем адрес: если пришёл hex (41...), конвертируем в Base58Check (T...)
        clean = v.strip()
        if clean.startswith("41") and len(clean) == 42:
            clean = to_base58check_address(clean)
        return validate_tron_address(clean)


class Permission(BaseModel):
    """Модель отдельного разрешения (Owner, Witness или Active)."""
    type: PermissionType
    id: int = Field(ge=0, description="0 для Owner, 1 для Witness, >=2 для Active")
    permission_name: str = Field(min_length=1, max_length=32)
    threshold: int = Field(ge=1, description="Минимальный порог весов для выполнения транзакции")
    keys: List[KeyWeight] = Field(min_length=1, description="Список ключей и их весов")
    operations: Optional[str] = Field(
        default=None,
        description="64-символьная hex-маска разрешённых контрактов (только для Active)",
    )

    @field_validator("operations")
    @classmethod
    def validate_ops(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        return normalize_operations_hex(v)

    @model_validator(mode="after")
    def validate_integrity(self) -> "Permission":
        # Проверка отсутствия дубликатов адресов внутри одного permission
        addrs = [k.address for k in self.keys]
        if len(addrs) != len(set(addrs)):
            raise ValueError(f"Разрешение '{self.permission_name}' содержит дублирующиеся адреса")

        # Проверка достижимости порога
        if self.total_weight < self.threshold:
            raise ValueError(
                f"В разрешении '{self.permission_name}' сумма весов ({self.total_weight}) "
                f"меньше порога threshold ({self.threshold})"
            )

        # Active permission обязан иметь поле operations
        if self.type == PermissionType.ACTIVE and not self.operations:
            self.operations = DEFAULT_ACTIVE_OPERATIONS_HEX

        # Owner и Witness не должны иметь operations
        if self.type in (PermissionType.OWNER, PermissionType.WITNESS) and self.operations:
            self.operations = None

        return self

    @property
    def total_weight(self) -> int:
        """Суммарный вес всех ключей разрешения."""
        return sum(k.weight for k in self.keys)

    @property
    def is_threshold_reachable(self) -> bool:
        """Достижим ли порог хотя бы при объединении всех ключей."""
        return self.total_weight >= self.threshold

    def get_key(self, address: str) -> Optional[KeyWeight]:
        """Поиск ключа по TRON-адресу."""
        target = address.strip()
        if target.startswith("41") and len(target) == 42:
            target = to_base58check_address(target)
        for k in self.keys:
            if k.address == target:
                return k
        return None

    def calculate_weight(self, signers: List[str]) -> int:
        """Вычисляет суммарный доступный вес для переданного списка адресов подписывающих."""
        clean_signers = set()
        for s in signers:
            clean = s.strip()
            if clean.startswith("41") and len(clean) == 42:
                clean = to_base58check_address(clean)
            clean_signers.add(clean)

        return sum(k.weight for k in self.keys if k.address in clean_signers)

    def has_access(self, signers: List[str]) -> bool:
        """Проверяет, достаточно ли голосов у предоставленных адресов для преодоления threshold."""
        return self.calculate_weight(signers) >= self.threshold

    @property
    def allowed_operations(self) -> List[str]:
        """Список названий разрешённых контрактов (только для Active)."""
        if not self.operations:
            return []
        return sorted(list(decode_operations(self.operations)))

    @property
    def can_transfer_trx(self) -> bool:
        """Разрешён ли перевод нативного TRX."""
        if self.type == PermissionType.OWNER:
            return True
        return bool(self.operations and can_transfer_trx(self.operations))

    @property
    def can_transfer_trc20(self) -> bool:
        """Разрешён ли вызов смарт-контрактов / перевод TRC-20 (USDT)."""
        if self.type == PermissionType.OWNER:
            return True
        return bool(self.operations and can_transfer_trc20(self.operations))

    @property
    def can_modify_permissions(self) -> bool:
        """Разрешено ли изменение прав аккаунта."""
        if self.type == PermissionType.OWNER:
            return True
        return bool(self.operations and can_modify_permissions(self.operations))

    def to_dict(self) -> Dict[str, Any]:
        """Преобразует в формат словаря для TronPy и TRON API."""
        type_val = 0 if self.type == PermissionType.OWNER else (1 if self.type == PermissionType.WITNESS else 2)
        res: Dict[str, Any] = {
            "type": type_val,
            "id": self.id,
            "permission_name": self.permission_name,
            "threshold": self.threshold,
            "keys": [{"address": k.address, "weight": k.weight} for k in self.keys],
        }
        if self.type == PermissionType.ACTIVE and self.operations:
            res["operations"] = self.operations
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any], default_type: PermissionType = PermissionType.ACTIVE) -> "Permission":
        """Создаёт модель из ответа ноды TRON или TronPy."""
        raw_type = data.get("type")
        if raw_type in (0, "0", "Owner", PermissionType.OWNER):
            perm_type = PermissionType.OWNER
        elif raw_type in (1, "1", "Witness", PermissionType.WITNESS):
            perm_type = PermissionType.WITNESS
        elif raw_type in (2, "2", "Active", PermissionType.ACTIVE):
            perm_type = PermissionType.ACTIVE
        else:
            perm_type = default_type

        perm_id = int(data.get("id", 0 if perm_type == PermissionType.OWNER else 2))
        name = data.get("permission_name") or perm_type.value.lower()
        threshold = int(data.get("threshold", 1))

        raw_keys = data.get("keys", [])
        keys = [
            KeyWeight(
                address=k["address"],
                weight=int(k.get("weight", 1)),
            )
            for k in raw_keys
        ]

        operations = data.get("operations")
        return cls(
            type=perm_type,
            id=perm_id,
            permission_name=name,
            threshold=threshold,
            keys=keys,
            operations=operations,
        )


class AccountPermissions(BaseModel):
    """Полная структура прав аккаунта TRON (Owner, Witness, Active)."""
    owner: Permission
    witness: Optional[Permission] = None
    actives: List[Permission] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def validate_account_structure(self) -> "AccountPermissions":
        if self.owner.type != PermissionType.OWNER:
            raise ValueError("Разрешение owner должно иметь тип Owner")
        for act in self.actives:
            if act.type != PermissionType.ACTIVE:
                raise ValueError(f"Разрешение '{act.permission_name}' должно иметь тип Active")
        return self

    def find_active_by_id(self, perm_id: int) -> Optional[Permission]:
        """Поиск Active разрешения по числовому ID."""
        for act in self.actives:
            if act.id == perm_id:
                return act
        return None

    def to_tronpy_dict(self) -> Dict[str, Any]:
        """Формирует словарь, готовый для Trx.account_permission_update в TronPy."""
        payload: Dict[str, Any] = {
            "owner": self.owner.to_dict(),
            "actives": [act.to_dict() for act in self.actives],
        }
        if self.witness is not None:
            payload["witness"] = self.witness.to_dict()
        return payload

    @classmethod
    def from_tronpy_dict(cls, data: Dict[str, Any]) -> "AccountPermissions":
        """Парсит структуру из Tron.get_account_permission."""
        owner = Permission.from_dict(data["owner"], default_type=PermissionType.OWNER)

        witness = None
        if data.get("witness"):
            witness = Permission.from_dict(data["witness"], default_type=PermissionType.WITNESS)

        actives = []
        raw_actives = data.get("actives", [])
        for act_data in raw_actives:
            actives.append(Permission.from_dict(act_data, default_type=PermissionType.ACTIVE))

        return cls(owner=owner, witness=witness, actives=actives)
