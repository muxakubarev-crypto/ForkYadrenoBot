"""
Локальный асинхронный ИИ-агент на базе DeepSeek API (OpenAI-совместимый).

Предоставляет инструменты (Function Calling / Tools):
- read_file_content       — чтение файлов бота
- modify_file_content     — перезапись / правка кода
- restart_bot_process     — перезапуск systemd-службы
- execute_server_command  — диагностика сервера (allowlist + deny-list)

Безопасность:
- Все пути валидируются через _resolve_tool_path (не выходят за PROJECT_ROOT)
- Shell-команды проверяются deny-листом опасных паттернов и allowlist префиксов
- Полный аудит каждого tool_call в лог
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from openai import AsyncOpenAI

from config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_PROXY

logger = logging.getLogger(__name__)

# Callback для прогресса: handler передаёт async-функцию, агент дёргает её с описанием шага
ProgressCallback = Callable[[str], Awaitable[None]]

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# ---------------------------------------------------------------------------
# Deny-list опасных shell-паттернов (унаследовано из старого yadreno_admin.py)
# ---------------------------------------------------------------------------
_DANGEROUS_SHELL_PATTERNS: tuple[tuple[str, str], ...] = (
    (
        r"(^|[;&|]\s*)(sudo\s+)?rm\s+([^\n;&|]*\s)?-(?=[^\s\n;&|]*r)(?=[^\s\n;&|]*f)[^\s\n;&|]*\s+(?:-[^\s\n;&|]+\s+)*(--\s+)?(/|\*/|/\*|~|\$HOME)(\s|$)",
        "опасное рекурсивное удаление",
    ),
    (
        r"\bmkfs(\.[a-z0-9_-]+)?\b",
        "форматирование файловой системы",
    ),
    (
        r"\bdd\b[^\n;&|]*\bof\s*=\s*/dev/",
        "прямая запись dd в /dev",
    ),
    (
        r":\s*\(\s*\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:",
        "fork bomb",
    ),
    (
        r"\b(chmod|chown|chgrp)\b[^\n;&|]*\s-[^\n;&|]*R[^\n;&|]*(\s/|\s/\*)",
        "рекурсивная смена прав/владельца от корня",
    ),
    (
        r"\b(curl|wget)\b[^\n]*(\|\s*(sudo\s+)?(ba)?sh\b)",
        "pipe curl/wget в shell",
    ),
)

# ---------------------------------------------------------------------------
# Allowlist безопасных диагностических команд (только read-only)
# ---------------------------------------------------------------------------
_ALLOWED_COMMAND_PREFIXES: tuple[str, ...] = (
    "free",
    "df",
    "uptime",
    "top -bn1",
    "ps ",
    "ps aux",
    "who",
    "w ",
    "last",
    "hostnamectl",
    "systemctl status ",
    "systemctl list-units",
    "systemctl is-active ",
    "systemctl is-enabled ",
    "journalctl -u yadreno-vpn --no-pager -n",
    "journalctl -xe --no-pager -n",
    "journalctl --no-pager -n",
    "ip addr",
    "ip link",
    "ip route",
    "ss -tlnp",
    "ss -tln",
    "netstat -tlnp",
    "netstat -tln",
    "curl -sS ",
    "curl -s ",
    "ping -c ",
    "cat /proc/",
    "lsblk",
    "lscpu",
    "lsmem",
    "du -sh ",
    "du -h --max-depth=",
    "docker ps",
    "docker stats --no-stream",
    "tail -n ",
    "head -n ",
    "uname -a",
    "iostat",
    "vmstat",
    "cat /etc/os-release",
    "cat /etc/hostname",
    "cat /root/YadrenoVPN/logs/bot.log",
    "echo",
)


class DeepSeekAgentError(RuntimeError):
    """Ошибка при взаимодействии с DeepSeek API или исполнении tool_call."""


def _resolve_tool_path(raw_path: str) -> Path:
    """
    Преобразует путь из tool_call в абсолютный путь внутри PROJECT_ROOT.

    Выбрасывает DeepSeekAgentError, если путь пытается выйти за пределы проекта.
    """
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    resolved = path.resolve()

    # Защита от выхода за PROJECT_ROOT
    try:
        resolved.relative_to(PROJECT_ROOT)
    except ValueError:
        raise DeepSeekAgentError(
            f"Путь {raw_path!r} выходит за пределы PROJECT_ROOT ({PROJECT_ROOT})"
        )

    return resolved


def _reject_dangerous_shell(command: str) -> None:
    """Отклоняет катастрофически опасные shell-команды."""
    for pattern, reason in _DANGEROUS_SHELL_PATTERNS:
        if re.search(pattern, command, flags=re.IGNORECASE | re.MULTILINE):
            raise DeepSeekAgentError(
                f"Опасная shell-команда отклонена: {reason}"
            )


# ---------------------------------------------------------------------------
# Создание клиента AsyncOpenAI
# ---------------------------------------------------------------------------
def _build_client() -> AsyncOpenAI:
    """Собирает AsyncOpenAI-клиент с учётом прокси."""
    kwargs: dict[str, Any] = {
        "api_key": DEEPSEEK_API_KEY,
        "base_url": DEEPSEEK_BASE_URL,
    }

    if DEEPSEEK_PROXY:
        import httpx
        kwargs["http_client"] = httpx.AsyncClient(proxy=DEEPSEEK_PROXY)
        logger.info("DeepSeek Agent: используем прокси %s", DEEPSEEK_PROXY)

    return AsyncOpenAI(**kwargs)


# ---------------------------------------------------------------------------
# Системный промпт
# ---------------------------------------------------------------------------
SYSTEM_PROMPT_EXEC = """Ты — автономный ИИ-администратор VPN-бота Yadreno VPN в РЕЖИМЕ ИСПОЛНЕНИЯ.

КРИТИЧЕСКИ ВАЖНО: Ты НИКОГДА не задаёшь уточняющих вопросов, КРОМЕ случая полной неопределённости.

РЕЖИМЫ РАБОТЫ (НЕ СМЕШИВАЙ ИХ):

=== РЕЖИМ «КОД» (задача про кнопки/файлы/код) ===
АЛГОРИТМ — РОВНО 2 ШАГА:
Шаг 1: read_file_content. Прочитай ТОЛЬКО нужный файл (не больше одного).
Шаг 2: patch_file_content для точечной правки. Скопируй фрагмент ОДИН-В-ОДИН из результата Шага 1 как search. Добавь новые кнопки/строки в replace.
ВСЁ. НИКАКИХ ДРУГИХ ИНСТРУМЕНТОВ. НЕ вызывай execute_server_command. НЕ используй modify_file_content для существующих файлов.

ПРИМЕР patch_file_content (добавить 2 кнопки в меню):
search = фрагмент из read_file_content, например:
  "builder.row(
      InlineKeyboardButton(text=\"🔑 Мои ключи\", callback_data=\"my_keys\"),
      InlineKeyboardButton(text=\"💳 Купить ключ\", callback_data=\"buy_key\")
  )"
replace = тот же фрагмент + новые кнопки ПЕРЕД ним:
  "builder.row(
      InlineKeyboardButton(text=\"📜 Политика\", callback_data=\"privacy_policy\"),
      InlineKeyboardButton(text=\"📋 Соглашение\", callback_data=\"terms_of_service\")
  )
  builder.row(
      InlineKeyboardButton(text=\"🔑 Мои ключи\", callback_data=\"my_keys\"),
      InlineKeyboardButton(text=\"💳 Купить ключ\", callback_data=\"buy_key\")
  )"

ГДЕ ЧТО:
- «Главное меню» / «здесь» / «меню пользователя» / «под /start» / «в этом меню»:
  → bot/keyboards/user.py → функция main_menu_kb() (вставь кнопки после builder = InlineKeyboardBuilder())
- «Админ-панель» / «меню администратора» / «меню админки»:
  → bot/keyboards/admin_misc.py → admin_main_menu_kb()
- Новый файл (не существует) → используй modify_file_content

=== РЕЖИМ «ДИАГНОСТИКА» (задача про сервер/логи/сеть/диски) ===
execute_server_command: free -h, df -h, uptime, ps aux --sort=-%mem | head -10, journalctl, ip addr, ss -tlnp, lsblk

ЗАПРЕЩЕНО: вопросы, restart, чтение >1 файла, смешивание режимов.
ОТВЕТ: «✅ Файл X изменён: [что].» / «❌ ОШИБКА: [причина]»"""

SYSTEM_PROMPT_DIALOG = """Ты — ИИ-администратор VPN-бота Yadreno VPN.
Ты общаешься с администратором сервера в режиме диалога.

Доступные инструменты:
1. **read_file_content** — читать файлы исходного кода бота
2. **patch_file_content** — точечно заменять фрагмент кода (не требует перезаписи всего файла)
3. **modify_file_content** — перезаписывать файл целиком (только для НОВЫХ файлов)
4. **restart_bot_process** — перезапускать systemd-службу бота (НЕ вызывай сам — администратор перезапустит)
5. **execute_server_command** — выполнить диагностическую команду на сервере (free, df, uptime, ps, top, journalctl, ss, docker ps и др.)

Правила диалогового режима:
- Если задача непонятна — задай ОДИН уточняющий вопрос и жди ответа.
- Если задача ясна — сразу выполняй через инструменты, не переспрашивай.
- Перед изменением существующего файла: read_file_content → patch_file_content (скопируй фрагмент ОДИН-В-ОДИН как search).
- Для нового файла используй modify_file_content.
- Кнопки главного меню: bot/keyboards/admin_misc.py (admin_main_menu_kb).
- Пользовательские кнопки: bot/keyboards/user.py.
- Обработчики: bot/handlers/.
- НЕ вызывай restart_bot_process после изменений.
- Для диагностики сервера используй execute_server_command с командами: free -h, df -h, uptime, ps aux, ip addr, ss -tlnp, journalctl.
- Отвечай на русском языке, кратко."""


# ---------------------------------------------------------------------------
# Определения инструментов (OpenAI Function Calling формат)
# ---------------------------------------------------------------------------
TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file_content",
            "description": "Читает содержимое файла внутри проекта бота.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Путь к файлу относительно корня проекта, например 'bot/handlers/user/start.py'",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Максимальное число строк для чтения (по умолчанию 500)",
                        "default": 500,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "modify_file_content",
            "description": "Полностью перезаписывает содержимое файла. Используй ТОЛЬКО для создания НОВЫХ файлов. Для точечных правок существующих файлов используй patch_file_content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Путь к файлу относительно корня проекта",
                    },
                    "content": {
                        "type": "string",
                        "description": "ПОЛНОЕ новое содержимое файла",
                    },
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "patch_file_content",
            "description": "Точечно заменяет фрагмент кода в файле. Ищет точное совпадение search и заменяет на replace. Используй для добавления кнопок, изменения функций, небольших правок. НЕ требует перезаписывать весь файл. Алгоритм: сначала read_file_content, затем скопируй уникальный фрагмент из прочитанного как search, напиши замену как replace.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Путь к файлу относительно корня проекта, например 'bot/keyboards/user.py'",
                    },
                    "search": {
                        "type": "string",
                        "description": "Точный фрагмент кода (3-10 строк), который нужно найти и заменить. Копируй ОДИН-В-ОДИН из результата read_file_content — те же отступы, те же переносы строк. Фрагмент должен быть УНИКАЛЬНЫМ в файле.",
                    },
                    "replace": {
                        "type": "string",
                        "description": "Новый код для замены найденного фрагмента. Например, тот же код + новые кнопки перед ним или после него.",
                    },
                },
                "required": ["path", "search", "replace"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "restart_bot_process",
            "description": "Перезапускает systemd-службу VPN-бота через systemctl restart.",
            "parameters": {
                "type": "object",
                "properties": {
                    "service_name": {
                        "type": "string",
                        "description": "Имя systemd-службы для перезапуска (по умолчанию 'yadreno-vpn')",
                        "default": "yadreno-vpn",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_server_command",
            "description": "Выполняет read-only диагностическую команду на сервере (free, df, uptime, ps, top, ip, ss, journalctl и др.). Только безопасные команды.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Shell-команда для диагностики. Примеры: 'free -h', 'df -h', 'uptime', 'ps aux --sort=-%mem | head -10', 'ip addr', 'ss -tlnp', 'journalctl -u yadreno-vpn --no-pager -n 30', 'docker ps', 'lscpu', 'cat /proc/meminfo'",
                    },
                },
                "required": ["command"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Исполнение tool_call
# ---------------------------------------------------------------------------
async def _read_file_content(path: str, max_lines: int = 2000) -> str:
    """Читает файл и возвращает его содержимое."""
    resolved = _resolve_tool_path(path)
    if not resolved.is_file():
        return f"ОШИБКА: файл не найден — {resolved}"

    try:
        content = await asyncio.to_thread(resolved.read_text, encoding="utf-8")
        lines = content.split("\n")
        total_lines = len(lines)
        if total_lines > max_lines:
            truncated = "\n".join(lines[:max_lines])
            return (
                f"=== {path} (строки 1-{max_lines} из {total_lines}) ===\n"
                f"{truncated}\n"
                f"... (обрезано, всего {total_lines} строк. "
                f"Используй max_lines чтобы прочитать больше)"
            )
        return f"=== {path} (всего {total_lines} строк) ===\n{content}"
    except UnicodeDecodeError:
        return f"ОШИБКА: не удалось прочитать {resolved} как UTF-8 (возможно бинарный файл)"
    except Exception as e:
        return f"ОШИБКА чтения {resolved}: {e}"


async def _modify_file_content(path: str, content: str) -> str:
    """Перезаписывает файл полностью (для создания новых файлов)."""
    resolved = _resolve_tool_path(path)

    try:
        resolved.parent.mkdir(parents=True, exist_ok=True)
        await asyncio.to_thread(resolved.write_text, content, encoding="utf-8")
        logger.info(
            "DeepSeek Agent tool: modify_file_content path=%s size=%d",
            resolved,
            len(content),
        )
        return f"Файл {path} успешно перезаписан ({len(content)} байт)."
    except Exception as e:
        return f"ОШИБКА записи {resolved}: {e}"


async def _patch_file_content(path: str, search: str, replace: str) -> str:
    """
    Точечная замена фрагмента кода в файле.
    
    Ищет точное совпадение search и заменяет его на replace.
    Нормализует переводы строк (\\r\\n -> \\n) для кроссплатформенности.
    Возвращает ошибку, если фрагмент не найден или найден более одного раза.
    """
    resolved = _resolve_tool_path(path)
    
    if not resolved.is_file():
        return f"ОШИБКА: файл не найден — {resolved}"
    
    # Нормализуем переводы строк для кроссплатформенности
    search_normalized = search.replace("\r\n", "\n")
    replace_normalized = replace.replace("\r\n", "\n")
    
    try:
        original_content = await asyncio.to_thread(resolved.read_text, encoding="utf-8")
        content_normalized = original_content.replace("\r\n", "\n")
        
        # Проверяем, что search встречается ровно один раз
        count = content_normalized.count(search_normalized)
        if count == 0:
            # Пытаемся найти с \t как пробелами и наоборот (помощь модели)
            return (
                f"ОШИБКА patch_file_content: указанный фрагмент НЕ НАЙДЕН в {path}.\n"
                f"Возможные причины:\n"
                f"- Не совпадают отступы (табы vs пробелы). Скопируй фрагмент ТОЧНО из read_file_content.\n"
                f"- Фрагмент не уникален или искажён.\n"
                f"СОВЕТ: прочитай файл ещё раз через read_file_content с max_lines побольше "
                f"и скопируй нужный фрагмент ОДИН-В-ОДИН как search."
            )
        elif count > 1:
            # Показываем контекст для каждого вхождения
            lines_info = []
            for idx, _ in enumerate(range(count)):
                pos = content_normalized.index(search_normalized)
                line_num = content_normalized[:pos].count("\n") + 1
                snippet = search_normalized[:60].replace("\n", "\\n")
                lines_info.append(f"  строка ~{line_num}: ...{snippet}...")
                content_normalized = content_normalized.replace(
                    search_normalized, "<<<FOUND>>>", 1
                )
            return (
                f"ОШИБКА patch_file_content: фрагмент найден {count} раз(а) в {path}.\n"
                f"Фрагмент должен быть УНИКАЛЬНЫМ. Найден на строках:\n"
                + "\n".join(lines_info[:5]) +
                "\nСОВЕТ: добавь больше контекстных строк в search, чтобы сделать его уникальным."
            )
        
        # Восстанавливаем нормализованный контент для замены
        content_normalized = original_content.replace("\r\n", "\n")
        new_content = content_normalized.replace(search_normalized, replace_normalized, 1)
        
        await asyncio.to_thread(resolved.write_text, new_content, encoding="utf-8")
        
        logger.info(
            "DeepSeek Agent tool: patch_file_content path=%s search_len=%d replace_len=%d",
            resolved,
            len(search_normalized),
            len(replace_normalized),
        )
        
        return (
            f"Файл {path} успешно изменён (patch).\n"
            f"Заменено {len(search_normalized)} -> {len(replace_normalized)} символов."
        )
    except Exception as e:
        return f"ОШИБКА patch_file_content {resolved}: {e}"


async def _restart_bot_process(service_name: str = "yadreno-vpn") -> str:
    """Перезапускает systemd-службу."""
    # Защита: разрешены только известные имена служб
    allowed_services = {"yadreno-vpn", "yadreno-vpn.service"}
    if service_name not in allowed_services:
        return (
            f"ОШИБКА: перезапуск службы {service_name!r} запрещён. "
            f"Разрешены: {', '.join(sorted(allowed_services))}"
        )

    # Проверка deny-list
    _reject_dangerous_shell(f"systemctl restart {service_name}")

    try:
        if os.name == "nt":
            return "ОШИБКА: systemctl недоступен на Windows. Перезапустите бота вручную."

        # Fire-and-forget: не ждём завершения, т.к. systemctl restart убьёт ЭТОТ процесс
        subprocess.Popen(
            ["systemctl", "restart", service_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        logger.info(
            "DeepSeek Agent tool: restart_bot_process service=%s triggered (fire-and-forget)",
            service_name,
        )
        return f"Служба {service_name} перезапускается..."
    except FileNotFoundError:
        return "ОШИБКА: systemctl не найден в системе"
    except Exception as e:
        return f"ОШИБКА перезапуска {service_name}: {e}"


async def _execute_server_command(command: str) -> str:
    """Выполняет безопасную диагностическую команду (allowlist + deny-list)."""
    command = command.strip()
    if not command:
        return "ОШИБКА: пустая команда"

    # Слой 1: allowlist префиксов
    allowed = False
    for prefix in _ALLOWED_COMMAND_PREFIXES:
        if command.startswith(prefix) or command == prefix:
            allowed = True
            break
    if not allowed:
        return (
            f"ОШИБКА: команда запрещена.\n"
            f"Разрешённые префиксы: {', '.join(_ALLOWED_COMMAND_PREFIXES[:10])}..."
        )

    # Слой 2: deny-list опасных паттернов
    try:
        _reject_dangerous_shell(command)
    except DeepSeekAgentError as e:
        return f"ОШИБКА: {e}"

    # Слой 3: выполнение с таймаутом
    try:
        if os.name == "nt":
            return "ОШИБКА: выполнение команд недоступно на Windows."

        process = await asyncio.create_subprocess_shell(
            command,
            cwd="/tmp",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
        output = (stdout or b"").decode("utf-8", errors="replace")
        if stderr:
            output += "\n[STDERR]\n" + (stderr or b"").decode("utf-8", errors="replace")

        if process.returncode != 0:
            output += f"\n[exit_code={process.returncode}]"

        # Cap output
        if len(output) > 3000:
            output = output[:3000] + f"\n... (обрезано, всего {len(output)} символов)"

        return output or "(пустой вывод)"
    except asyncio.TimeoutError:
        try:
            process.kill()
        except Exception:
            pass
        return "ОШИБКА: таймаут команды (15 сек)"
    except FileNotFoundError:
        return "ОШИБКА: команда не найдена в системе"
    except Exception as e:
        return f"ОШИБКА выполнения: {e}"


async def _execute_tool_call(tool_name: str, arguments: dict[str, Any]) -> str:
    """Диспетчер: исполняет tool_call и возвращает строку-результат."""
    # Логируем аргументы: скрываем content (слишком длинный), но показываем search/replace
    log_args = {
        k: (v[:100] + "..." if isinstance(v, str) and len(v) > 100 else v)
        for k, v in arguments.items()
    }
    logger.info(
        "DeepSeek Agent tool_call: tool=%s args=%s",
        tool_name,
        log_args,
    )

    if tool_name == "read_file_content":
        path = str(arguments.get("path", "")).strip()
        max_lines = int(arguments.get("max_lines", 500))
        if not path:
            return "ОШИБКА: не указан path для read_file_content"
        return await _read_file_content(path, max_lines=max_lines)

    elif tool_name == "modify_file_content":
        path = str(arguments.get("path", "")).strip()
        content = str(arguments.get("content", ""))
        if not path:
            return "ОШИБКА: не указан path для modify_file_content"
        return await _modify_file_content(path, content)

    elif tool_name == "patch_file_content":
        path = str(arguments.get("path", "")).strip()
        search = str(arguments.get("search", ""))
        replace = str(arguments.get("replace", ""))
        if not path:
            return "ОШИБКА: не указан path для patch_file_content"
        if not search:
            return "ОШИБКА: не указан search для patch_file_content. Скопируй уникальный фрагмент из read_file_content."
        return await _patch_file_content(path, search, replace)

    elif tool_name == "restart_bot_process":
        service_name = str(arguments.get("service_name", "yadreno-vpn")).strip()
        return await _restart_bot_process(service_name)

    elif tool_name == "execute_server_command":
        command = str(arguments.get("command", "")).strip()
        if not command:
            return "ОШИБКА: не указана команда для execute_server_command"
        return await _execute_server_command(command)

    else:
        return f"ОШИБКА: неизвестный инструмент {tool_name!r}"


# ---------------------------------------------------------------------------
# Основной цикл диалога
# ---------------------------------------------------------------------------


async def run_dialog(
    user_message: str,
    system_prompt: str | None = None,
    progress_callback: ProgressCallback | None = None,
) -> tuple[str, list[str]]:
    """
    Отправляет сообщение модели DeepSeek и выполняет полный цикл
    запрос → tool_calls → ответ (с повторами при необходимости).

    НИКОГДА не вызывает restart_bot_process внутри — это делает handler после ответа.

    Args:
        user_message: Текст задачи от администратора.
        system_prompt: Системный промпт. Если None — используется SYSTEM_PROMPT_EXEC.
        progress_callback: async-коллбэк для показа прогресса админу.

    Returns:
        (финальный_текст, список_изменённых_файлов)

    Raises:
        DeepSeekAgentError при ошибках API.
    """
    async def _progress(msg: str) -> None:
        if progress_callback:
            try:
                await progress_callback(msg)
            except Exception:
                pass

    if not DEEPSEEK_API_KEY:
        raise DeepSeekAgentError(
            "DEEPSEEK_API_KEY не задан. Добавьте ключ в .env или config.py."
        )

    client = _build_client()
    model = DEEPSEEK_MODEL

    prompt = system_prompt if system_prompt is not None else SYSTEM_PROMPT_EXEC

    # Классификация задачи -> фильтрация инструментов
    msg_lower = user_message.lower()
    CODE_KW = ("кнопк", "добав", "меню", "измен", "файл", "код", "исправ",
               "перепиш", "сделай", "создай", "удали", "поправ", "прав",
               "убери", "замени", "переименуй", "отредактируй", "напиши",
               "запиши", "вставь", "перемести", "картинк", "изображен",
               "текст", "ссылк", "команд")
    DIAG_KW = ("сервер", "лог", "состоян", "покаж", "провер", "статус",
               "диск", "память", "ram", "cpu", "процесс", "порт", "сет",
               "ip", "трафик", "нагрузк", "место", "свободно", "занято",
               "контейнер", "docker", "журнал")
    is_code = any(kw in msg_lower for kw in CODE_KW)
    is_diag = any(kw in msg_lower for kw in DIAG_KW)
    if is_code and not is_diag:
        # В code-режиме оставляем read, patch, modify (для новых файлов), restart
        # НЕ даём execute_server_command
        active_tools = [t for t in TOOLS if t["function"]["name"] != "execute_server_command"]
    elif is_diag and not is_code:
        # В diag-режиме оставляем read, execute_server_command
        # НЕ даём modify_file_content и patch_file_content
        active_tools = [t for t in TOOLS if t["function"]["name"] not in ("modify_file_content", "patch_file_content")]
    else:
        active_tools = TOOLS

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": user_message},
    ]

    modified_files: list[str] = []
    max_tool_rounds = 10
    rounds_without_modify = 0
    EARLY_ABORT_AFTER = 4

    for _round in range(max_tool_rounds):
        # Ранний abort или forced modify / forced patch
        if rounds_without_modify == 2:
            messages.append({
                "role": "system",
                "content": (
                    "ТЫ УЖЕ ПРОЧИТАЛ ФАЙЛ. НЕМЕДЛЕННО ВЫЗОВИ patch_file_content. "
                    "Скопируй уникальный фрагмент из результата read_file_content как search, "
                    "напиши замену с новыми кнопками как replace. "
                    "НЕ читай другие файлы. НЕ вызывай execute_server_command. "
                    "ТОЛЬКО patch_file_content СЕЙЧАС."
                ),
            })
        elif rounds_without_modify >= EARLY_ABORT_AFTER:
            raise DeepSeekAgentError(
                f"Не удалось найти файл для изменения за {rounds_without_modify} раундов. "
                f"Уточните задачу: какой именно файл или экран нужно изменить?"
            )

        round_num = _round + 1
        await _progress(f"📡 Раунд {round_num}/{max_tool_rounds}: DeepSeek думает...")

        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=active_tools,
                tool_choice="auto",
                temperature=0.3,
                max_tokens=4096,
                extra_body={"thinking": {"type": "disabled"}},
            )
        except Exception as e:
            raise DeepSeekAgentError(f"Ошибка DeepSeek API: {e}") from e

        choice = response.choices[0]
        finish_reason = choice.finish_reason

        # Если модель вернула финальный текст
        if finish_reason == "stop" and choice.message.content:
            return choice.message.content, modified_files

        # Если модель хочет вызвать инструмент
        if finish_reason == "tool_calls" or choice.message.tool_calls:
            reasoning = getattr(choice.message, "reasoning_content", None)

            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": choice.message.content,
                "tool_calls": [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ],
            }
            if reasoning:
                assistant_msg["reasoning_content"] = reasoning
            messages.append(assistant_msg)

            # Исполняем каждый tool_call
            has_modify_this_round = False
            for tc in choice.message.tool_calls:
                import json
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                tool_name = tc.function.name
                path_hint = str(args.get("path", "")) if "path" in args else ""
                cmd_hint = str(args.get("command", "")) if "command" in args else ""

                if tool_name == "read_file_content":
                    await _progress(f"📖 Читаю {path_hint}...")
                elif tool_name == "modify_file_content":
                    await _progress(f"✏️ Перезаписываю {path_hint}...")
                elif tool_name == "patch_file_content":
                    await _progress(f"🔧 Патчу {path_hint}...")
                elif tool_name == "restart_bot_process":
                    await _progress("⚠️ Перезапуск отложен (сделаю после ответа)")
                elif tool_name == "execute_server_command":
                    await _progress(f"⚙️ Выполняю: {cmd_hint[:80]}...")

                result_text = await _execute_tool_call(tool_name, args)

                # Отслеживаем изменённые файлы и успешность modify/patch
                if tool_name in ("modify_file_content", "patch_file_content") and not result_text.startswith("ОШИБКА"):
                    resolved_path = str(args.get("path", ""))
                    if resolved_path:
                        if resolved_path not in modified_files:
                            modified_files.append(resolved_path)
                        has_modify_this_round = True  # ТОЛЬКО после реального успеха

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

            # Сброс или инкремент счётчика
            if has_modify_this_round:
                rounds_without_modify = 0
            else:
                rounds_without_modify += 1

            # Если файл был изменён — немедленно выходим с сообщением
            if modified_files:
                files_list = ", ".join(modified_files)
                return f"✅ Файл {files_list} изменён: кнопки добавлены.", modified_files

            continue

        # Другие причины завершения
        if choice.message.content:
            return choice.message.content, modified_files

        raise DeepSeekAgentError(
            f"Неожиданный finish_reason: {finish_reason}"
        )

    raise DeepSeekAgentError(
        f"Достигнут лимит tool_call раундов ({max_tool_rounds})"
    )
