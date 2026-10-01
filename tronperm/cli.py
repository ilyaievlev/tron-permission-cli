"""Консольный интерфейс (CLI) утилиты tronperm."""

from pathlib import Path
from typing import List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from tronperm.config import config
from tronperm.keys import (
    address_from_private_key,
    generate_keypair,
    load_private_key,
    read_keystore_address,
    save_keystore,
    validate_private_key,
    validate_tron_address,
)
from tronperm.services import (
    AccountAccessReport,
    AccountInspectionReport,
    PermissionsDiffReport,
    TransferPlan,
    add_key_to_permissions,
    check_account_access,
    execute_permission_update,
    execute_transfer,
    inspect_account,
    resolve_signer_addresses,
    simulate_permission_update,
    simulate_transfer,
)
from tronperm.tron.account import PERMISSION_UPDATE_FEE_TRX
from tronperm.tron.client import get_tron_client
from tronperm.tron.permissions import AccountPermissions, PermissionType
from tronperm.tron.tokens import DEFAULT_FEE_LIMIT_SUN

app = typer.Typer(help="tronperm — CLI для анализа и управления TRON Account Permissions", no_args_is_help=True)
key_app = typer.Typer(help="Генерация и локальное хранилище ключей", no_args_is_help=True)
perm_app = typer.Typer(help="Управление и симуляция permissions", no_args_is_help=True)
transfer_app = typer.Typer(help="Переводы TRX и USDT с мультиподписью", no_args_is_help=True)

app.add_typer(key_app, name="key")
app.add_typer(perm_app, name="permission")
app.add_typer(transfer_app, name="transfer")

console = Console()


def print_network_banner() -> None:
    """Выводит информацию о текущей сети TRON с предупреждением для Mainnet."""
    net = config.network.upper()
    if config.is_mainnet:
        console.print(
            Panel(
                Text(f"ВНИМАНИЕ: СЕТЬ TRON MAINNET! РЕАЛЬНЫЕ СРЕДСТВА!", justify="center", style="bold white on red"),
                border_style="red",
            )
        )
    else:
        console.print(f"[bold cyan]Сеть:[/bold cyan] {net} TESTNET")


def collect_signing_private_keys(key_files: Optional[List[Path]]) -> List[str]:
    """Собирает приватные ключи из .env и зашифрованных keystore-файлов."""
    signing_keys: List[str] = []
    seen_addresses: List[str] = []

    def _append(pk: str) -> None:
        addr = address_from_private_key(pk)
        if addr not in seen_addresses:
            signing_keys.append(pk)
            seen_addresses.append(addr)

    if config.default_owner_private_key:
        _append(validate_private_key(config.default_owner_private_key))
        console.print("[dim]Добавлен ключ из OWNER_PRIVATE_KEY[/dim]")

    if key_files:
        for kf in key_files:
            file_addr = read_keystore_address(kf)
            password = typer.prompt(f"Пароль для {kf.name} ({file_addr})", hide_input=True)
            pk = load_private_key(kf, password)
            derived = address_from_private_key(pk)
            if derived != file_addr:
                raise ValueError(f"Адрес в {kf} не совпадает с ключом после расшифровки")
            _append(pk)

    if not signing_keys:
        console.print("[dim]Введите hex приватного ключа (или укажите --key):[/dim]")
        raw_pk = typer.prompt("Private Key", hide_input=True)
        _append(validate_private_key(raw_pk))

    return signing_keys


def render_transfer_plan(plan: TransferPlan) -> None:
    """Показывает план перевода до подтверждения."""
    perm = plan.permission
    table = Table(title="План перевода", header_style="bold")
    table.add_column("Поле")
    table.add_column("Значение")
    table.add_row("Актив", plan.symbol)
    table.add_row("Откуда", plan.from_address)
    table.add_row("Куда", plan.to_address)
    table.add_row("Сумма", plan.amount_display)
    table.add_row("Баланс отправителя", plan.sender_balance_display)
    table.add_row(
        "Permission",
        f"{perm.type.value} #{perm.id} '{perm.permission_name}'",
    )
    table.add_row("Порог / доступный вес", f"{perm.threshold} / {plan.available_weight}")
    if plan.contract_address:
        table.add_row("Контракт TRC-20", plan.contract_address)
        table.add_row("fee_limit", f"{plan.fee_limit_sun / 1_000_000:.2f} TRX")
    console.print(table)
    console.print("[bold]Подписывающие адреса:[/bold]")
    for addr in plan.signer_addresses:
        in_perm = perm.get_key(addr) is not None
        mark = "[green]в permission[/green]" if in_perm else "[red]не в permission[/red]"
        console.print(f"  • [cyan]{addr}[/cyan] ({mark})")
    if plan.warnings:
        console.print()
        for warning in plan.warnings:
            console.print(f"  [bold yellow]⚠[/bold yellow] {warning}")
    console.print()


def render_account_permissions(report: AccountInspectionReport) -> None:
    """Красиво выводит структуру прав аккаунта через Rich таблицы."""
    console.print(f"\n[bold]Аккаунт:[/bold] [yellow]{report.address}[/yellow]")
    console.print(f"[bold]Баланс:[/bold] [green]{report.balance_trx:.4f} TRX[/green]\n")

    # Таблица Owner
    owner_table = Table(title=f"OWNER (id: {report.owner.id}, threshold: {report.owner.threshold})", header_style="bold magenta")
    owner_table.add_column("Адрес", style="cyan")
    owner_table.add_column("Вес", justify="right")
    for k in report.owner.keys:
        owner_table.add_row(k.address, str(k.weight))
    console.print(owner_table)
    console.print()

    # Таблицы Active
    for act in report.actives:
        act_table = Table(
            title=f"ACTIVE #{act.id} '{act.permission_name}' (threshold: {act.threshold})",
            header_style="bold blue",
        )
        act_table.add_column("Адрес", style="cyan")
        act_table.add_column("Вес", justify="right")
        for k in act.keys:
            act_table.add_row(k.address, str(k.weight))
        console.print(act_table)

        # Вывод разрешённых операций
        ops = act.allowed_operations
        if ops:
            ops_str = ", ".join(ops[:6])
            if len(ops) > 6:
                ops_str += f" ... (+{len(ops)-6} операций)"
            console.print(f"  [dim]Разрешенные операции ({len(ops)}):[/dim] {ops_str}")
        console.print(
            f"  [bold]Переводы TRX:[/bold] {'[green]YES[/green]' if act.can_transfer_trx else '[red]NO[/red]'}  |  "
            f"[bold]TRC-20 / Смарт-контракты:[/bold] {'[green]YES[/green]' if act.can_transfer_trc20 else '[red]NO[/red]'}  |  "
            f"[bold]Смена прав:[/bold] {'[yellow]YES[/yellow]' if act.can_modify_permissions else '[dim]NO[/dim]'}"
        )
        console.print()


def render_access_report(report: AccountAccessReport) -> None:
    """Отображает отчет о правах доступа ключей к аккаунту."""
    console.print(f"\n[bold]Целевой аккаунт:[/bold] [yellow]{report.account_address}[/yellow]")
    console.print("[bold]Предоставленные ключи/адреса:[/bold]")
    for s in report.provided_signers:
        console.print(f"  • [cyan]{s}[/cyan]")
    console.print()

    # Owner доступ
    o = report.owner
    o_status = "[bold green]YES[/bold green]" if o.has_access else "[bold red]NO[/bold red]"
    console.print(
        Panel(
            f"[bold]Порог (Threshold):[/bold] {o.threshold}\n"
            f"[bold]Доступный вес:[/bold]     {o.available_weight}\n"
            f"[bold]Доступ к Owner:[/bold]    {o_status}",
            title=f"OWNER (#{o.permission_id})",
            border_style="green" if o.has_access else "red",
        )
    )

    # Active доступы
    for a in report.actives:
        a_status = "[bold green]YES[/bold green]" if a.has_access else "[bold red]NO[/bold red]"
        trx_st = "[green]YES[/green]" if a.can_transfer_trx else "[red]NO[/red]"
        trc20_st = "[green]YES[/green]" if a.can_transfer_trc20 else "[red]NO[/red]"
        edit_st = "[yellow]YES[/yellow]" if a.can_modify_permissions else "[dim]NO[/dim]"

        console.print(
            Panel(
                f"[bold]Порог (Threshold):[/bold] {a.threshold}\n"
                f"[bold]Доступный вес:[/bold]     {a.available_weight}\n"
                f"[bold]Доступ к Active:[/bold]   {a_status}\n\n"
                f"  [bold]TRX transfer:[/bold]     {trx_st}\n"
                f"  [bold]TRC-20 transfer:[/bold]  {trc20_st}\n"
                f"  [bold]Permission edit:[/bold]  {edit_st}",
                title=f"ACTIVE #{a.permission_id} '{a.permission_name}'",
                border_style="green" if a.has_access else "dim",
            )
        )


def render_diff_report(diff: PermissionsDiffReport) -> None:
    """Выводит разницу между текущей и новой конфигурацией прав."""
    console.print(Panel("[bold]Сравнение конфигураций (DIFF)[/bold]", border_style="cyan"))

    def _render_single(d):
        table = Table(
            title=f"{d.permission_type.value.upper()} '{d.permission_name}' (Порог: {d.old_threshold} -> {d.new_threshold})",
            header_style="bold",
        )
        table.add_column("Статус", style="bold")
        table.add_column("Адрес")
        table.add_column("Вес (Было -> Стало)", justify="right")

        for k in d.key_diffs:
            if k.action == "added":
                table.add_row("[green]+ ДОБАВЛЕН[/green]", k.address, f"[green]+{k.new_weight}[/green]")
            elif k.action == "removed":
                table.add_row("[red]- УДАЛЕН[/red]", k.address, f"[red]-{k.old_weight}[/red]")
            elif k.action == "modified":
                table.add_row("[yellow]~ ИЗМЕНЕН[/yellow]", k.address, f"{k.old_weight} -> {k.new_weight}")
            else:
                table.add_row("[dim]  БЕЗ ИЗМ.[/dim]", k.address, f"{k.new_weight}")

        console.print(table)
        if d.added_operations:
            console.print(f"  [green]+ Добавлены операции:[/green] {', '.join(d.added_operations)}")
        if d.removed_operations:
            console.print(f"  [red]- Удалены операции:[/red] {', '.join(d.removed_operations)}")
        console.print()

    _render_single(diff.owner_diff)
    for act_d in diff.active_diffs:
        _render_single(act_d)

    if diff.warnings:
        console.print("[bold red]ПРЕДУПРЕЖДЕНИЯ БЕЗОПАСНОСТИ:[/bold red]")
        for w in diff.warnings:
            console.print(f"  [bold red]⚠[/bold red] {w}")
        console.print()


@app.command("permissions")
def permissions_cmd(
    address: Optional[str] = typer.Argument(
        None, help="Адрес TRON-аккаунта (по умолчанию из .env TRON_ACCOUNT)"
    ),
) -> None:
    """Получить и показать актуальные Owner и Active permissions аккаунта."""
    print_network_banner()
    try:
        report = inspect_account(address)
        render_account_permissions(report)
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")
        raise typer.Exit(code=1)


@app.command("check")
def check_cmd(
    account: Optional[str] = typer.Argument(
        None, help="Целевой аккаунт TRON (по умолчанию из .env TRON_ACCOUNT)"
    ),
    address: Optional[List[str]] = typer.Option(
        None, "--address", "-a", help="Адрес проверяемого ключа (можно передавать несколько раз)"
    ),
    key: Optional[List[Path]] = typer.Option(
        None, "--key", "-k", help="Путь к JSON-файлу keystore (можно передавать несколько раз)"
    ),
) -> None:
    """Проверить, достаточно ли предоставленных адресов/ключей для управления permissions."""
    print_network_banner()
    try:
        report = check_account_access(
            account_address=account,
            signer_addresses=address,
            key_files=key,
        )
        render_access_report(report)
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")
        raise typer.Exit(code=1)


@key_app.command("generate")
def key_generate_cmd(
    name: Optional[str] = typer.Option(
        None, "--name", "-n", help="Имя ключа (файл keys/<name>.json)"
    ),
    add_permission: bool = typer.Option(
        False, "--add-permission", help="Сразу подготовить добавление ключа в permissions аккаунта"
    ),
    account: Optional[str] = typer.Option(
        None, "--account", help="Целевой аккаунт для добавления (если включен --add-permission)"
    ),
    target_type: str = typer.Option(
        "owner", "--type", help="Куда добавить: 'owner' или 'active'"
    ),
    weight: int = typer.Option(
        1, "--weight", "-w", help="Вес нового ключа в разрешении"
    ),
    threshold: Optional[int] = typer.Option(
        None, "--threshold", "-t", help="Новый порог threshold (если требуется изменить)"
    ),
) -> None:
    """Сгенерировать новую пару TRON ключей и безопасно сохранить в keystore."""
    print_network_banner()

    # 1. Генерация ключа
    key = generate_keypair()
    console.print("\n[bold green]✓[/bold green] Новый TRON-ключ успешно сгенерирован!")
    console.print(f"[bold]TRON Address:[/bold] [yellow]{key.address}[/yellow]")
    console.print(f"[bold]Public Key:[/bold]   {key.public_key}\n")

    # 2. Запрос пароля для шифрования
    console.print("[dim]Введите пароль для шифрования файла ключа (AES-256-GCM):[/dim]")
    password = typer.prompt("Пароль", hide_input=True, confirmation_prompt=True)

    # 3. Сохранение в keys/
    file_name = name or f"key_{key.address[:8]}"
    if not file_name.endswith(".json"):
        file_name += ".json"
    file_path = config.keys_dir / file_name

    save_keystore(file_path, key.private_key, key.address, password)
    console.print(f"[bold green]✓[/bold green] Зашифрованный ключ сохранён в: [cyan]{file_path}[/cyan]\n")

    # 4. Если запрошено добавление в permissions
    if add_permission:
        target_account = account or config.default_account
        if not target_account:
            console.print("[bold red]Для --add-permission необходимо указать --account или задать TRON_ACCOUNT в .env[/bold red]")
            raise typer.Exit(code=1)

        p_type = PermissionType.OWNER if target_type.lower() == "owner" else PermissionType.ACTIVE
        _run_permission_update_flow(
            account_address=target_account,
            new_key_address=key.address,
            target_type=p_type,
            key_weight=weight,
            new_threshold=threshold,
            dry_run=False,
            generated_private_key=key.private_key,
        )


@perm_app.command("update")
def permission_update_cmd(
    account: Optional[str] = typer.Argument(
        None, help="Адрес аккаунта для смены прав (по умолчанию из .env)"
    ),
    add_address: Optional[str] = typer.Option(
        None, "--add-address", help="TRON-адрес для добавления"
    ),
    target_type: str = typer.Option(
        "owner", "--type", help="Тип разрешения: 'owner' или 'active'"
    ),
    weight: int = typer.Option(
        1, "--weight", "-w", help="Вес ключа"
    ),
    threshold: Optional[int] = typer.Option(
        None, "--threshold", "-t", help="Новый порог threshold"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Симуляция без отправки транзакции в блокчейн"
    ),
    key_files: Optional[List[Path]] = typer.Option(
        None, "--key", "-k", help="Файлы keystore подписывающих (можно несколько для мультиподписи)"
    ),
) -> None:
    """Безопасное обновление Owner/Active permissions аккаунта с симуляцией (dry-run)."""
    print_network_banner()

    target_account = account or config.default_account
    if not target_account:
        console.print("[bold red]Укажите адрес аккаунта или задайте TRON_ACCOUNT в .env[/bold red]")
        raise typer.Exit(code=1)

    if not add_address and threshold is None:
        console.print("[bold yellow]Укажите хотя бы одно действие: --add-address или --threshold[/bold yellow]")
        raise typer.Exit(code=1)

    p_type = PermissionType.OWNER if target_type.lower() == "owner" else PermissionType.ACTIVE
    _run_permission_update_flow(
        account_address=target_account,
        new_key_address=add_address,
        target_type=p_type,
        key_weight=weight,
        new_threshold=threshold,
        dry_run=dry_run,
        signing_key_files=key_files,
    )


def _run_permission_update_flow(
    account_address: str,
    new_key_address: Optional[str],
    target_type: PermissionType,
    key_weight: int,
    new_threshold: Optional[int],
    dry_run: bool,
    generated_private_key: Optional[str] = None,
    signing_key_files: Optional[List[Path]] = None,
) -> None:
    """Общий сценарий проверки, вывода diff, подтверждения и отправки транзакции обновления прав."""
    client = get_tron_client()
    clean_addr = validate_tron_address(account_address)

    # 1. Загружаем текущие права
    current_perms = inspect_account(clean_addr, client=client).permissions

    # 2. Формируем proposed permissions
    if new_key_address:
        proposed = add_key_to_permissions(
            current=current_perms,
            new_address=new_key_address,
            target_permission_type=target_type,
            key_weight=key_weight,
            new_threshold=new_threshold,
        )
    else:
        # Только смена порога
        if target_type == PermissionType.OWNER and new_threshold:
            new_owner = current_perms.owner.model_copy(update={"threshold": new_threshold})
            proposed = AccountPermissions(owner=new_owner, witness=current_perms.witness, actives=current_perms.actives)
        else:
            proposed = current_perms

    # 3. Симуляция (Dry-run)
    sim = simulate_permission_update(clean_addr, proposed, client=client)

    # 4. Отображаем DIFF и предупреждения
    render_diff_report(sim.diff)
    console.print(f"[bold]Баланс аккаунта:[/bold] {sim.current_balance_trx:.2f} TRX (Комиссия сети: {PERMISSION_UPDATE_FEE_TRX} TRX)")

    if dry_run:
        console.print("\n[bold yellow]--dry-run режим:[/bold yellow] Симуляция завершена. Транзакция не отправлялась.")
        return

    # 5. Проверка возможности продолжения
    if not sim.has_sufficient_fee:
        console.print(f"\n[bold red]ОШИБКА:[/bold red] Недостаточно TRX для оплаты комиссии ({PERMISSION_UPDATE_FEE_TRX} TRX). Отмена.")
        raise typer.Exit(code=1)

    if sim.diff.has_lockout_risk:
        console.print("\n[bold red]ВНИМАНИЕ: Обнаружен критический риск потери контроля над аккаунтом![/bold red]")

    # 6. Явное подтверждение от пользователя
    console.print("\n[bold]Для подтверждения отправки транзакции введите '[white]confirm[/white]':[/bold]")
    user_input = typer.prompt("Подтверждение").strip()
    if user_input != "confirm":
        console.print("[yellow]Операция отменена пользователем.[/yellow]")
        return

    # 7. Получение ключей для подписи (для 2-of-2 передайте несколько --key)
    signing_keys: List[str] = []
    if generated_private_key:
        signing_keys.append(generated_private_key)
    signing_keys.extend(collect_signing_private_keys(signing_key_files))

    unique_keys: List[str] = []
    seen_addrs: List[str] = []
    for pk in signing_keys:
        addr = address_from_private_key(pk)
        if addr not in seen_addrs:
            unique_keys.append(pk)
            seen_addrs.append(addr)

    # 8. Отправка и подтверждение в блокчейне
    with console.status("[bold green]Отправка транзакции и ожидание подтверждения в блоке..."):
        try:
            txid, receipt, updated_perms = execute_permission_update(
                account_address=clean_addr,
                proposed_permissions=proposed,
                signing_private_keys=unique_keys,
                client=client,
            )
        except Exception as e:
            console.print(f"\n[bold red]Ошибка при отправке транзакции:[/bold red] {e}")
            raise typer.Exit(code=1)

    console.print(f"\n[bold green]✓ Права успешно обновлены в блокчейне![/bold green]")
    console.print(f"[bold]TXID:[/bold] [cyan]{txid}[/cyan]\n")

    # 9. Финальный вывод актуального состояния
    console.print("[bold]Новое подтверждённое состояние аккаунта:[/bold]")
    render_account_permissions(inspect_account(clean_addr, client=client))


def _run_transfer_flow(
    asset: str,
    to_address: str,
    amount: str,
    from_address: Optional[str],
    key_files: Optional[List[Path]],
    permission_id: Optional[int],
    dry_run: bool,
    contract: Optional[str] = None,
    fee_limit_sun: int = DEFAULT_FEE_LIMIT_SUN,
) -> None:
    """Общий сценарий перевода TRX или USDT с мультиподписью."""
    if not key_files and not config.default_owner_private_key:
        console.print("[bold red]Укажите хотя бы один --key файл keystore для подписи[/bold red]")
        raise typer.Exit(code=1)

    signer_addresses = resolve_signer_addresses(key_files=key_files)
    if config.default_owner_private_key:
        env_addr = address_from_private_key(config.default_owner_private_key)
        if env_addr not in signer_addresses:
            signer_addresses.append(env_addr)

    try:
        plan = simulate_transfer(
            from_address=from_address,
            to_address=to_address,
            amount=amount,
            asset=asset,
            signer_addresses=signer_addresses,
            permission_id=permission_id,
            contract_address=contract,
            fee_limit_sun=fee_limit_sun,
        )
    except Exception as e:
        console.print(f"[bold red]Ошибка:[/bold red] {e}")
        raise typer.Exit(code=1)

    render_transfer_plan(plan)

    if dry_run:
        console.print("[bold yellow]--dry-run режим:[/bold yellow] Симуляция завершена. Транзакция не отправлялась.")
        return

    console.print("[bold]Для подтверждения отправки транзакции введите '[white]confirm[/white]':[/bold]")
    user_input = typer.prompt("Подтверждение").strip()
    if user_input != "confirm":
        console.print("[yellow]Операция отменена пользователем.[/yellow]")
        return

    try:
        signing_keys = collect_signing_private_keys(key_files)
        with console.status("[bold green]Подпись, отправка и ожидание подтверждения..."):
            txid, _receipt = execute_transfer(plan, signing_keys)
    except Exception as e:
        console.print(f"\n[bold red]Ошибка при отправке перевода:[/bold red] {e}")
        raise typer.Exit(code=1)

    console.print(f"\n[bold green]✓ Перевод {plan.amount_display} отправлен[/bold green]")
    console.print(f"[bold]TXID:[/bold] [cyan]{txid}[/cyan]")


@transfer_app.command("trx")
def transfer_trx_cmd(
    to_address: str = typer.Argument(..., help="Адрес получателя TRX"),
    amount: str = typer.Option(..., "--amount", "-n", help="Сумма в TRX, например 1.5"),
    from_address: Optional[str] = typer.Option(
        None, "--from", "-f", help="Аккаунт-отправитель (по умолчанию TRON_ACCOUNT)"
    ),
    key_files: Optional[List[Path]] = typer.Option(
        None, "--key", "-k", help="Keystore-файлы подписывающих (для 2-of-2 укажите оба)"
    ),
    permission_id: Optional[int] = typer.Option(
        None, "--permission-id", "-p", help="0 = Owner, 2+ = Active. Если не задан — выбирается автоматически"
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Только симуляция, без broadcast"),
) -> None:
    """Отправить TRX с мультиподписью Owner/Active permission."""
    print_network_banner()
    _run_transfer_flow(
        asset="trx",
        to_address=to_address,
        amount=amount,
        from_address=from_address,
        key_files=key_files,
        permission_id=permission_id,
        dry_run=dry_run,
    )


@transfer_app.command("usdt")
def transfer_usdt_cmd(
    to_address: str = typer.Argument(..., help="Адрес получателя USDT"),
    amount: str = typer.Option(..., "--amount", "-n", help="Сумма в USDT, например 10.5"),
    from_address: Optional[str] = typer.Option(
        None, "--from", "-f", help="Аккаунт-отправитель (по умолчанию TRON_ACCOUNT)"
    ),
    key_files: Optional[List[Path]] = typer.Option(
        None, "--key", "-k", help="Keystore-файлы подписывающих (для 2-of-2 укажите оба)"
    ),
    permission_id: Optional[int] = typer.Option(
        None, "--permission-id", "-p", help="0 = Owner, 2+ = Active. Если не задан — выбирается автоматически"
    ),
    contract: Optional[str] = typer.Option(
        None, "--contract", help="Адрес TRC-20 контракта (по умолчанию USDT текущей сети)"
    ),
    fee_limit: float = typer.Option(
        DEFAULT_FEE_LIMIT_SUN / 1_000_000,
        "--fee-limit",
        help="Максимальная комиссия за смарт-контракт в TRX",
    ),
    dry_run: bool = typer.Option(False, "--dry-run", help="Только симуляция, без broadcast"),
) -> None:
    """Отправить USDT (TRC-20) с мультиподписью Owner/Active permission."""
    print_network_banner()
    _run_transfer_flow(
        asset="usdt",
        to_address=to_address,
        amount=amount,
        from_address=from_address,
        key_files=key_files,
        permission_id=permission_id,
        dry_run=dry_run,
        contract=contract,
        fee_limit_sun=int(fee_limit * 1_000_000),
    )
