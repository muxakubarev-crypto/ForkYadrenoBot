"""
Локальный асинхронный ИИ-агент на базе DeepSeek API (OpenAI-совместимый).

Предоставляет инструменты (Function Calling / Tools):
- read_file_content       — чтение файлов бота
- modify_file_content     — полная перезапись файла (только для новых)
- patch_file_content      — точечная замена фрагмента в существующем файле
- get_page_buttons        — чтение АКТУАЛЬНЫХ кнопок страницы из БД (мёрж default+custom)
- update_page_buttons     — прямая запись кнопок страницы в БД (таблица pages, мгновенно)
- restart_bot_process     — перезапуск systemd-службы (fire-and-forget)
- execute_server_command  — диагностика сервера (allowlist + deny-list)

Безопасность:
- Все пути валидируются через _resolve_tool_path (не выходят за PROJECT_ROOT)
- Shell-команды проверяются deny-листом опасных паттернов и allowlist префиксов
- update_page_buttons валидирует структуру кнопок и существование page_key
- Полный аудит каждого tool_call в лог
"""
from __future__ import annotations

import asyncio
import json
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

=== КОНТЕКСТ ЭКРАНА АДМИНА ===
В начале задачи может быть строка [CONTEXT] current_page_key='<key>' — это значит
админ сейчас стоит на этой странице бота. Используй её так:
- Слова «здесь», «сюда», «тут», «туда», «это меню», «эта страница», «вот тут»,
  «у меня сейчас», «текущий экран» → page_key = current_page_key.
- Если в задаче явно не указан page_key или название страницы — DEFAULT page_key =
  current_page_key. Не спрашивай и не угадывай по тексту задачи.
- Если current_page_key НЕ задан и в задаче нет упоминания страницы — используй 'main'.
- Поддерживаемые page_key: 'main', 'help', 'trial', 'prepayment', 'referral', 'key_delivery'.

РЕЖИМЫ РАБОТЫ (НЕ СМЕШИВАЙ ИХ):

=== РЕЖИМ «КОД» (задача про кнопки/файлы/код) ===

ВАЖНО ПРО АРХИТЕКТУРУ КНОПОК:
Главное меню (/start) и страница помощи рендерятся ИЗ БАЗЫ ДАННЫХ (таблица pages),
а НЕ из bot/keyboards/user.py и НЕ из database/migrations.py. Файл user.py УСТАРЕЛ.
Файл migrations.py содержит ТОЛЬКО ДЕФОЛТЫ — там НЕТ кнопок, которые админ добавлял
ранее через /ai. Если ты прочитаешь migrations.py и передашь его список в
update_page_buttons — ты ЗАТРЁШЬ все ранее добавленные кнопки. Это БАГ.
ПРАВИЛЬНЫЙ источник текущих кнопок — get_page_buttons(page_key).

ВЕТКА А: «кнопки страницы пользователя» (главное меню, help, любая страница из таблицы pages)
АЛГОРИТМ — РОВНО 2 ШАГА:
Шаг 1: get_page_buttons(page_key=<ключ>).
       Получи АКТУАЛЬНЫЙ список текущих кнопок из БД (мёрж default + custom). Это то,
       что пользователь сейчас видит на экране.
Шаг 2: update_page_buttons(page_key=<ключ>, buttons=[...]).
       Передай ПОЛНЫЙ список: ВСЕ кнопки из Шага 1 + твои добавления/изменения.
       Если задача «добавь кнопку X» — добавь X к списку из Шага 1, ничего не убирая.
       Если задача «удали кнопку X» — убери из списка из Шага 1 только X, остальные оставь.
       Если задача «замени X на Y» — замени только X.

КАТЕГОРИЧЕСКИ ЗАПРЕЩЕНО в ВЕТКЕ А:
- Вызывать read_file_content('database/migrations.py') для получения текущих кнопок.
  Это даст ДЕФОЛТЫ, а не реальное состояние. Используй get_page_buttons.
- Вызывать patch_file_content или modify_file_content для database/migrations.py.
  Изменения не применятся (нужна миграция). Используй update_page_buttons.

ГДЕ КАКОЙ page_key:
- «главное меню» / «меню пользователя» / «под /start» / «здесь» / «внизу к боту» → page_key='main'
- «страница помощи» / «справка» / «/help»                                        → page_key='help'

ФОРМАТ КНОПКИ:
{
  "id": "btn_privacy",                       // уникальный, латиница+подчёркивание
  "label": "📜 Политика конфиденциальности",  // текст с эмодзи
  "row": 0, "col": 0,                        // позиция в сетке (0 или 1 в col)
  "action_type": "url",                      // "internal" | "url" | "system"
  "action_value": "https://example.com/...", // URL для url, имя cmd_* для internal
  "color": "secondary",
  "is_hidden": false
}

ПРИМЕР (задача «добавь кнопку Тест https://example.com в конец главного меню»):
1) Вызвал get_page_buttons('main') — получил 7 кнопок (например, дефолтные + добавленные ранее btn_privacy, btn_terms).
2) Вычислил max(row) среди них (например, 3) → новая кнопка пойдёт на row=4.
3) Вызвал update_page_buttons('main', buttons=[
     <... все 7 кнопок из Шага 1 БЕЗ ИЗМЕНЕНИЙ ...>,
     {"id":"btn_test","label":"🧪 Тест","row":4,"col":0,"action_type":"url","action_value":"https://example.com","color":"secondary","is_hidden":false}
   ])

ВЕТКА Б: «кнопки админ-панели» или «другой Python-код»
АЛГОРИТМ — РОВНО 2 ШАГА:
Шаг 1: read_file_content нужного файла (только одного).
Шаг 2: patch_file_content — скопируй фрагмент ОДИН-В-ОДИН из Шага 1 как search, добавь правки в replace.
ГДЕ ЧТО:
- «админ-панель» / «меню администратора» → bot/keyboards/admin_misc.py → admin_main_menu_kb()
- Новый файл (не существует) → modify_file_content

ЗАПРЕЩЕНО ВО ВСЕХ РЕЖИМАХ: execute_server_command, restart_bot_process, чтение >1 файла, смешивание ветки А и Б.

=== РЕЖИМ «ДИАГНОСТИКА» (задача про сервер/логи/сеть/диски) ===
execute_server_command: free -h, df -h, uptime, ps aux --sort=-%mem | head -10, journalctl, ip addr, ss -tlnp, lsblk

ЗАПРЕЩЕНО: вопросы, restart, чтение >1 файла, смешивание режимов.
ОТВЕТ: «✅ Кнопки страницы 'X' обновлены.» / «✅ Файл X изменён: [что].» / «❌ ОШИБКА: [причина]»"""

SYSTEM_PROMPT_DIALOG = """Ты — ИИ-администратор VPN-бота Yadreno VPN.
Ты общаешься с администратором сервера в режиме диалога.

КОНТЕКСТ ЭКРАНА АДМИНА:
В начале сообщения может быть строка [CONTEXT] current_page_key='<key>' — это значит
админ сейчас стоит на этой странице бота. Слова «здесь», «сюда», «тут», «это меню»,
«эта страница» относятся к ней. Если page_key явно не упомянут — используй
current_page_key как default. Если контекста нет и страница не упомянута — 'main'.
Поддерживаемые page_key: 'main', 'help', 'trial', 'prepayment', 'referral', 'key_delivery'.

Доступные инструменты:
1. **read_file_content** — читать файлы исходного кода бота
2. **patch_file_content** — точечно заменять фрагмент кода (не требует перезаписи всего файла)
3. **modify_file_content** — перезаписывать файл целиком (только для НОВЫХ файлов)
4. **get_page_buttons** — прочитать АКТУАЛЬНЫЕ кнопки страницы из БД (мёрж default + custom)
5. **update_page_buttons** — НАПРЯМУЮ записать кнопки страницы в БД (page_key + полный список кнопок). ИЗМЕНЕНИЯ ВИДНЫ МГНОВЕННО, перезапуск не нужен.
6. **restart_bot_process** — перезапускать systemd-службу бота (НЕ вызывай сам — администратор перезапустит)
7. **execute_server_command** — выполнить диагностическую команду на сервере (free, df, uptime, ps, top, journalctl, ss, docker ps и др.)

АРХИТЕКТУРА КНОПОК (ВАЖНО):
- Главное меню (/start), страница помощи и пр. рендерятся из БД (таблица pages), а НЕ из bot/keyboards/user.py.
- Файл bot/keyboards/user.py и функция main_menu_kb() УСТАРЕЛИ — НЕ редактируй их для главного меню.
- database/migrations.py содержит ТОЛЬКО ДЕФОЛТНЫЕ кнопки и НЕ показывает то, что админ добавлял через /ai. Никогда не используй его как источник «текущих кнопок».
- Источник истины для текущих кнопок — get_page_buttons(page_key).

Правила диалогового режима:
- Если задача непонятна — задай ОДИН уточняющий вопрос и жди ответа.
- Если задача ясна — сразу выполняй через инструменты, не переспрашивай.
- ДЛЯ КНОПОК ГЛАВНОГО МЕНЮ И ДРУГИХ СТРАНИЦ pages:
  1) get_page_buttons(page_key='main' или 'help') — получи АКТУАЛЬНЫЙ список того, что сейчас на экране.
  2) update_page_buttons(page_key, buttons=[...]) — передай ВСЕ кнопки из шага 1 + твои изменения. Не теряй существующие!
  Семантика задач:
   • «добавь X» → возьми список из get_page_buttons и допиши X (новый row).
   • «удали X» → возьми список и убери только X, остальные оставь.
   • «замени X на Y» → замени только X.
  ЗАПРЕЩЕНО для этой задачи читать database/migrations.py — там устаревшие дефолты.
- Для других правок кода: read_file_content → patch_file_content (скопируй фрагмент ОДИН-В-ОДИН как search).
- Для нового файла используй modify_file_content.
- Админ-панель: bot/keyboards/admin_misc.py → admin_main_menu_kb().
- Обработчики: bot/handlers/.
- НЕ вызывай restart_bot_process после изменений.
- Для диагностики сервера используй execute_server_command: free -h, df -h, uptime, ps aux, ip addr, ss -tlnp, journalctl.
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
            "name": "get_page_buttons",
            "description": (
                "Возвращает АКТУАЛЬНЫЙ список кнопок страницы из БД — РОВНО ТО, что сейчас "
                "видит пользователь на экране (мёрж buttons_default + buttons_custom). "
                "ОБЯЗАТЕЛЬНО вызывай ЭТО перед update_page_buttons, чтобы не затереть "
                "кнопки, ранее добавленные админом. "
                "НЕ читай для этой задачи database/migrations.py через read_file_content — "
                "там только дефолты, без последних правок админа."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {
                        "type": "string",
                        "description": "Ключ страницы: 'main' = главное меню /start, 'help' = справка.",
                    },
                },
                "required": ["page_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_page_buttons",
            "description": (
                "Обновляет кнопки страницы в базе данных (таблица pages, поле buttons_custom). "
                "Изменения видны мгновенно, БЕЗ перезапуска бота. "
                "ИСПОЛЬЗУЙ ЭТО для добавления/изменения кнопок главного меню (page_key='main'), "
                "страницы помощи (page_key='help') и других страниц из таблицы pages. "
                "НЕ редактируй для этого файлы bot/keyboards/user.py или database/migrations.py — "
                "главное меню рендерится из БД, а не из кода. "
                "Передавай ПОЛНЫЙ список кнопок (новые + существующие). Для добавления новых кнопок "
                "к существующим — сначала прочитай database/migrations.py чтобы узнать дефолтные кнопки, "
                "потом передай полный список (новые + все старые, с обновлёнными row/col при необходимости)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {
                        "type": "string",
                        "description": "Ключ страницы. 'main' = главный экран /start, 'help' = справка. Смотри database/migrations.py для других ключей.",
                    },
                    "buttons": {
                        "type": "array",
                        "description": (
                            "ПОЛНЫЙ список кнопок страницы. Каждая кнопка — объект со следующими полями: "
                            "id (str, уникальный), label (str, текст с эмодзи), row (int, ряд от 0), "
                            "col (int, колонка 0 или 1), action_type (str: 'internal' | 'url' | 'system'), "
                            "action_value (str: callback-имя для internal, URL для url), "
                            "color (str, обычно 'secondary'), is_hidden (bool, обычно false)."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "id": {"type": "string"},
                                "label": {"type": "string"},
                                "row": {"type": "integer"},
                                "col": {"type": "integer"},
                                "action_type": {
                                    "type": "string",
                                    "enum": ["internal", "url", "system"],
                                },
                                "action_value": {"type": "string"},
                                "color": {"type": "string"},
                                "is_hidden": {"type": "boolean"},
                            },
                            "required": ["id", "label", "row", "col", "action_type", "action_value"],
                        },
                    },
                },
                "required": ["page_key", "buttons"],
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


_REQUIRED_BUTTON_FIELDS = ("id", "label", "row", "col", "action_type", "action_value")
_ALLOWED_ACTION_TYPES = {"internal", "url", "system"}


async def _get_page_buttons(page_key: str) -> str:
    """
    Возвращает АКТУАЛЬНЫЙ итоговый список кнопок страницы (default + custom merged).

    Это то, что пользователь сейчас видит на экране. Используется моделью ПЕРЕД
    update_page_buttons, чтобы не потерять ранее добавленные админом кастомные кнопки.
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА get_page_buttons: не указан page_key"

    try:
        from bot.utils.page_renderer import get_page_data
    except Exception as e:
        return f"ОШИБКА get_page_buttons: не удалось импортировать page_renderer: {e}"

    try:
        data = await asyncio.to_thread(get_page_data, page_key)
    except Exception as e:
        return f"ОШИБКА get_page_buttons: чтение БД не удалось: {e}"

    if not data:
        return (
            f"ОШИБКА get_page_buttons: страница с page_key={page_key!r} не найдена в таблице pages."
        )

    buttons = data.get("buttons", []) or []

    logger.info(
        "DeepSeek Agent tool: get_page_buttons page_key=%s buttons=%d",
        page_key,
        len(buttons),
    )

    return (
        f"=== Актуальные кнопки страницы '{page_key}' (всего {len(buttons)} шт.) ===\n"
        f"Это то, что СЕЙЧАС видит пользователь (мёрж default + custom).\n"
        f"При вызове update_page_buttons передай этот список ПОЛНОСТЬЮ + свои изменения.\n\n"
        f"{json.dumps(buttons, ensure_ascii=False, indent=2)}\n"
        f"=== КОНЕЦ ==="
    )


def _normalize_button(btn: Any, idx: int) -> dict:
    """
    Валидирует и нормализует одну кнопку. Кидает DeepSeekAgentError на ошибках.
    """
    if not isinstance(btn, dict):
        raise DeepSeekAgentError(
            f"кнопка #{idx} должна быть объектом (dict), получено: {type(btn).__name__}"
        )

    missing = [f for f in _REQUIRED_BUTTON_FIELDS if f not in btn]
    if missing:
        raise DeepSeekAgentError(
            f"кнопка #{idx} (id={btn.get('id')!r}) не содержит обязательные поля: {', '.join(missing)}"
        )

    action_type = str(btn["action_type"]).strip()
    if action_type not in _ALLOWED_ACTION_TYPES:
        raise DeepSeekAgentError(
            f"кнопка #{idx} (id={btn.get('id')!r}): action_type={action_type!r} недопустим. "
            f"Разрешено: {sorted(_ALLOWED_ACTION_TYPES)}"
        )

    normalized = {
        "id": str(btn["id"]).strip(),
        "label": str(btn["label"]),
        "color": str(btn.get("color", "secondary")),
        "row": int(btn["row"]),
        "col": int(btn["col"]),
        "is_hidden": bool(btn.get("is_hidden", False)),
        "action_type": action_type,
        "action_value": str(btn["action_value"]),
    }
    if not normalized["id"]:
        raise DeepSeekAgentError(f"кнопка #{idx}: поле id не может быть пустым")
    return normalized


async def _update_page_buttons(page_key: str, buttons: Any) -> str:
    """
    Прямая запись кнопок страницы в БД (поле buttons_custom).

    Изменения видны мгновенно — рендер главного меню читает pages.buttons_custom при
    каждом /start. Перезапуск бота не требуется.
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА update_page_buttons: не указан page_key"

    if not isinstance(buttons, list):
        return (
            "ОШИБКА update_page_buttons: параметр buttons должен быть массивом (list), "
            f"получено: {type(buttons).__name__}"
        )

    try:
        normalized = [_normalize_button(b, i) for i, b in enumerate(buttons)]
    except DeepSeekAgentError as e:
        return f"ОШИБКА update_page_buttons: {e}"

    # Проверка уникальности id
    seen_ids: set[str] = set()
    duplicates: list[str] = []
    for b in normalized:
        if b["id"] in seen_ids:
            duplicates.append(b["id"])
        seen_ids.add(b["id"])
    if duplicates:
        return (
            f"ОШИБКА update_page_buttons: дублирующиеся id кнопок: {', '.join(sorted(set(duplicates)))}. "
            "Каждая кнопка должна иметь УНИКАЛЬНЫЙ id."
        )

    try:
        buttons_json = json.dumps(normalized, ensure_ascii=False)
    except (TypeError, ValueError) as e:
        return f"ОШИБКА update_page_buttons: не удалось сериализовать buttons в JSON: {e}"

    try:
        from database.db_pages import get_page, update_page_custom
    except Exception as e:
        return f"ОШИБКА update_page_buttons: не удалось импортировать database.db_pages: {e}"

    # Проверим, что страница существует
    existing = await asyncio.to_thread(get_page, page_key)
    if not existing:
        return (
            f"ОШИБКА update_page_buttons: страница с page_key={page_key!r} не найдена в таблице pages. "
            "Доступные ключи смотри в database/migrations.py (словарь page_defaults)."
        )

    try:
        await asyncio.to_thread(update_page_custom, page_key, buttons=buttons_json)
    except Exception as e:
        return f"ОШИБКА update_page_buttons: запись в БД не удалась: {e}"

    logger.info(
        "DeepSeek Agent tool: update_page_buttons page_key=%s buttons=%d",
        page_key,
        len(normalized),
    )

    return (
        f"Кнопки страницы '{page_key}' обновлены ({len(normalized)} шт.). "
        "Изменения видны мгновенно, перезапуск НЕ требуется."
    )


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

    elif tool_name == "get_page_buttons":
        page_key = str(arguments.get("page_key", "")).strip()
        if not page_key:
            return "ОШИБКА: не указан page_key для get_page_buttons"
        return await _get_page_buttons(page_key)

    elif tool_name == "update_page_buttons":
        page_key = str(arguments.get("page_key", "")).strip()
        buttons = arguments.get("buttons")
        if not page_key:
            return "ОШИБКА: не указан page_key для update_page_buttons"
        if buttons is None:
            return "ОШИБКА: не указан buttons для update_page_buttons (передай полный список кнопок)"
        return await _update_page_buttons(page_key, buttons)

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
    current_page_key: Optional[str] = None,
) -> tuple[str, list[str]]:
    """
    Отправляет сообщение модели DeepSeek и выполняет полный цикл
    запрос → tool_calls → ответ (с повторами при необходимости).

    Args:
        user_message: текст задачи от админа.
        system_prompt: системный промпт; если None — используется SYSTEM_PROMPT_EXEC.
        progress_callback: async-коллбэк для шагов в Telegram.
        current_page_key: ключ страницы pages, на которой админ был последний раз
            (читается через bot.services.page_context.get_page_context). Если задан,
            добавляется в начало пользовательского сообщения и модель использует его
            как default для get_page_buttons / update_page_buttons.

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
        # В code-режиме: read, patch, modify (для новых файлов), restart, update_page_buttons
        # НЕ даём execute_server_command
        active_tools = [t for t in TOOLS if t["function"]["name"] != "execute_server_command"]
    elif is_diag and not is_code:
        # В diag-режиме: read, execute_server_command
        # НЕ даём modify_file_content, patch_file_content, update_page_buttons, get_page_buttons
        active_tools = [
            t for t in TOOLS
            if t["function"]["name"] not in (
                "modify_file_content",
                "patch_file_content",
                "get_page_buttons",
                "update_page_buttons",
            )
        ]
    else:
        active_tools = TOOLS

    # Подмешиваем контекст экрана админа, если он передан.
    # Это сильнее всего помогает модели понять «здесь/сюда/тут» в командах вроде
    # «/ai добавь сюда кнопку» — она увидит current_page_key и подставит его как default.
    page_context_key = (current_page_key or "").strip()
    if page_context_key:
        contextualized_user_message = (
            f"[CONTEXT] current_page_key='{page_context_key}'\n"
            f"(Админ сейчас находится на этой странице бота. Слова "
            f"«здесь», «сюда», «тут», «туда», «это меню», «эта страница» "
            f"относятся к ней. Если в задаче явный page_key не указан — "
            f"используй current_page_key как default.)\n\n"
            f"ЗАДАЧА: {user_message}"
        )
    else:
        contextualized_user_message = user_message

    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": contextualized_user_message},
    ]

    modified_files: list[str] = []
    db_updated_pages: list[str] = []
    max_tool_rounds = 10
    rounds_without_modify = 0
    EARLY_ABORT_AFTER = 4

    for _round in range(max_tool_rounds):
        # Ранний abort или forced modify / forced patch
        if rounds_without_modify == 2:
            messages.append({
                "role": "system",
                "content": (
                    "ТЫ УЖЕ ПРОЧИТАЛ ДАННЫЕ. НЕМЕДЛЕННО ВЫЗОВИ ИНСТРУМЕНТ ЗАПИСИ.\n"
                    "- Если задача про кнопки страниц (главное меню, help и т.п.):\n"
                    "  1) Если ещё не вызвал get_page_buttons(page_key) — вызови ПРЯМО СЕЙЧАС.\n"
                    "  2) Затем update_page_buttons с ПОЛНЫМ списком (все кнопки из get_page_buttons + твои изменения).\n"
                    "  НЕ читай database/migrations.py — там устаревшие дефолты, использование затрёт правки админа.\n"
                    "  НЕ редактируй migrations.py через patch_file_content.\n"
                    "- Если задача про другой код — ВЫЗОВИ patch_file_content. "
                    "Скопируй уникальный фрагмент из read_file_content как search, "
                    "напиши замену как replace.\n"
                    "НЕ читай другие файлы. НЕ вызывай execute_server_command. "
                    "СДЕЛАЙ ЗАПИСЬ СЕЙЧАС."
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
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                tool_name = tc.function.name
                path_hint = str(args.get("path", "")) if "path" in args else ""
                cmd_hint = str(args.get("command", "")) if "command" in args else ""
                page_hint = str(args.get("page_key", "")) if "page_key" in args else ""

                if tool_name == "read_file_content":
                    await _progress(f"📖 Читаю {path_hint}...")
                elif tool_name == "modify_file_content":
                    await _progress(f"✏️ Перезаписываю {path_hint}...")
                elif tool_name == "patch_file_content":
                    await _progress(f"🔧 Патчу {path_hint}...")
                elif tool_name == "get_page_buttons":
                    await _progress(f"🔍 Читаю актуальные кнопки страницы '{page_hint}' из БД...")
                elif tool_name == "update_page_buttons":
                    btns = args.get("buttons")
                    btn_count = len(btns) if isinstance(btns, list) else "?"
                    await _progress(f"🎛️ Обновляю кнопки страницы '{page_hint}' в БД ({btn_count} шт.)...")
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

                # Отслеживаем DB-обновления — отдельно от файлов, чтобы НЕ сработал auto-restart
                if tool_name == "update_page_buttons" and not result_text.startswith("ОШИБКА"):
                    if page_hint and page_hint not in db_updated_pages:
                        db_updated_pages.append(page_hint)
                    has_modify_this_round = True

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

            # Если кнопки в БД обновлены — выходим сразу. modified_files оставляем пустым,
            # чтобы handler НЕ перезапускал бота: страницы рендерятся из БД на лету.
            if db_updated_pages:
                pages_list = ", ".join(f"'{p}'" for p in db_updated_pages)
                return (
                    f"✅ Кнопки страницы {pages_list} обновлены в БД. "
                    f"Изменения видны мгновенно — отправь /start, чтобы их увидеть.",
                    modified_files,
                )

            # Если файл был изменён — немедленно выходим с сообщением (handler сам перезапустит бота).
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
