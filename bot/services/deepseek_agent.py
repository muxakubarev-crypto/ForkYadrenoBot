"""
Локальный асинхронный ИИ-агент на базе DeepSeek API (OpenAI-совместимый).

Предоставляет инструменты (Function Calling / Tools):
- read_file_content       — чтение файлов бота
- modify_file_content     — полная перезапись файла (только для новых)
- patch_file_content      — точечная замена фрагмента в существующем файле
- get_page_buttons        — кнопки страницы (visible+hidden раздельно)
- get_page_content        — текст+картинка+счётчик кнопок страницы
- delete_page_button      — атомарно скрыть/удалить одну кнопку
- add_page_button         — атомарно добавить или вернуть одну кнопку
- update_page_button      — атомарно изменить поля одной кнопки
- update_page_buttons     — массовая перезапись списка кнопок (редко)
- update_page_text / reset_page_text   — текст страницы
- update_page_image / reset_page_image — картинка страницы (file_id или URL)
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

ВЕТКА А: «кнопки страницы пользователя» (main, help, trial, prepayment, referral, key_delivery)

ПРИОРИТЕТ: для ОПЕРАЦИИ С ОДНОЙ КНОПКОЙ используй АТОМАРНЫЕ tools.
Они инкрементальны, не теряют ранее изменённые кнопки, не путаются.
МАССОВЫЕ изменения (передать сразу новый список) — только через update_page_buttons.

АЛГОРИТМ — РОВНО 2 ШАГА:
Шаг 1: get_page_buttons(page_key=<ключ>).
       Вывод явно разделён на «Видимые» и «Скрытые». Если кнопка УЖЕ в «Скрытые» —
       НЕ пытайся её удалять ещё раз, она уже скрыта.
Шаг 2: ОДИН атомарный tool по операции:
       • «удали/убери кнопку X»     → delete_page_button(page_key, button_id='btn_X')
       • «добавь кнопку X»          → add_page_button(page_key, button={id, label, row, col, action_type, action_value, ...})
       • «верни обратно кнопку X»   → add_page_button с теми же полями, что у X в default
                                       (или update_page_button(page_key, button_id, is_hidden=False))
       • «измени label/url/позицию» → update_page_button(page_key, button_id, label=..., action_value=..., row=..., col=...)
       • «спрячь без удаления»      → update_page_button(page_key, button_id, is_hidden=True)
       МАССОВО (редко): update_page_buttons(page_key, buttons=[...полный список...], hide_default_ids=[...])

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

ПРИМЕР 1 — добавление («добавь кнопку Тест https://example.com в главное меню»):
1) get_page_buttons('main') → видимых 5 кнопок, max(row) среди них = 2 → новая на row=3.
2) add_page_button('main', button={
     "id":"btn_test","label":"🧪 Тест","row":3,"col":0,
     "action_type":"url","action_value":"https://example.com",
     "color":"secondary","is_hidden":false
   })

ПРИМЕР 2 — удаление кнопки («убери кнопку Поддержка со страницы справки»):
1) get_page_buttons('help') → видимые: ['btn_news','btn_support','btn_back_main']. ОК, btn_support есть.
2) delete_page_button('help', button_id='btn_support')
   Готово. Один tool, одно действие. НЕ вызывай update_page_buttons.

ПРИМЕР 3 — изменение поля («поменяй ссылку у кнопки Канал на https://t.me/new»):
1) get_page_buttons('main') → найди id канала, например 'btn_channel'.
2) update_page_button('main', button_id='btn_channel', action_value='https://t.me/new')

ПРИМЕР 4 — «верни кнопку поддержки обратно»:
1) get_page_buttons('help') → btn_support в «Скрытые».
2) update_page_button('help', button_id='btn_support', is_hidden=False)

=== ТЕКСТ И КАРТИНКИ СТРАНИЦ ===
Аналогично кнопкам — отдельные tools для каждой операции:
• «измени/перепиши текст» → update_page_text(page_key, text='новый HTML-текст')
• «сбрось/верни дефолтный текст» → reset_page_text(page_key)
• «поставь картинку», «обнови фото» → update_page_image(page_key, image='<file_id или URL>')
  ВАЖНО: если в [CONTEXT] есть pending_image_file_id — используй именно его (админ только
  что прислал фото). Не выдумывай file_id.
• «убери картинку» → reset_page_image(page_key)
• «что сейчас на странице» / нужно понять состояние → get_page_content(page_key)

ПРИМЕР 5 — «поставь сюда эту картинку» (контекст: current_page_key='main', pending_image_file_id='AgACAg...'):
1) update_page_image('main', image='AgACAg...')   # используешь file_id из [CONTEXT]

ПРИМЕР 6 — «измени текст справки на ...»:
1) update_page_text('help', text='<b>Помощь</b>\n\nНовый текст...')

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
2. **patch_file_content** — точечно заменять фрагмент кода
3. **modify_file_content** — перезаписывать файл целиком (только для НОВЫХ файлов)
4. **get_page_buttons** — кнопки страницы (visible/hidden раздельно)
5. **get_page_content** — текст+картинка+счётчик кнопок страницы (читай ПЕРЕД правкой)
6. **delete_page_button** — атомарно скрыть ОДНУ кнопку
7. **add_page_button** — атомарно добавить/вернуть ОДНУ кнопку
8. **update_page_button** — атомарно изменить поля ОДНОЙ кнопки
9. **update_page_buttons** — массовая перезапись (редко)
10. **update_page_text** / **reset_page_text** — текст страницы
11. **update_page_image** / **reset_page_image** — картинка страницы (file_id из [CONTEXT].pending_image_file_id или URL)
12. **restart_bot_process** — рестарт службы (НЕ вызывай сам)
13. **execute_server_command** — диагностика сервера

АРХИТЕКТУРА КНОПОК (ВАЖНО):
- Главное меню (/start), страница помощи и пр. рендерятся из БД (таблица pages), а НЕ из bot/keyboards/user.py.
- Файл bot/keyboards/user.py и функция main_menu_kb() УСТАРЕЛИ — НЕ редактируй их для главного меню.
- database/migrations.py содержит ТОЛЬКО ДЕФОЛТНЫЕ кнопки и НЕ показывает то, что админ добавлял через /ai. Никогда не используй его как источник «текущих кнопок».
- Источник истины для текущих кнопок — get_page_buttons(page_key).

Правила диалогового режима:
- Если задача непонятна — задай ОДИН уточняющий вопрос и жди ответа.
- Если задача ясна — сразу выполняй через инструменты, не переспрашивай.
- ДЛЯ КНОПОК ГЛАВНОГО МЕНЮ И ДРУГИХ СТРАНИЦ pages:
  Используй АТОМАРНЫЕ tools — каждый делает одну вещь и не теряет ранее изменённые кнопки:
   1) Сначала get_page_buttons(page_key) — узнай актуальные id, увидь visible/hidden.
   2) Дальше ОДИН atomic tool:
      • «удали X»            → delete_page_button(page_key, button_id='btn_X')
      • «добавь X»           → add_page_button(page_key, button={...})
      • «измени label/url X» → update_page_button(page_key, button_id, label=..., action_value=...)
      • «верни кнопку X»     → update_page_button(page_key, button_id, is_hidden=False)
  update_page_buttons (массовая перезапись) — только для редких batch-задач.
  ЗАПРЕЩЕНО читать database/migrations.py — там устаревшие дефолты.
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
            "name": "get_page_content",
            "description": (
                "Возвращает полное содержимое страницы: текст, картинку (есть/нет, источник), "
                "количество видимых/скрытых кнопок. Используй ПЕРЕД любой правкой страницы, "
                "чтобы понять текущее состояние."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string"},
                },
                "required": ["page_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_page_text",
            "description": (
                "Меняет текст страницы (поле text_custom в БД). Поддерживает HTML aiogram: "
                "<b>, <i>, <u>, <s>, <code>, <a href='...'>, <tg-emoji emoji-id='...'>. "
                "Можно использовать плейсхолдеры типа %тарифы%, %дней%, {keyname} — они "
                "подставятся при рендере. Изменения видны мгновенно."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string"},
                    "text": {
                        "type": "string",
                        "description": "Новый текст. До 4000 символов. HTML aiogram поддерживается.",
                    },
                },
                "required": ["page_key", "text"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reset_page_text",
            "description": "Сбрасывает кастомный текст страницы: рендер вернётся к дефолтному тексту.",
            "parameters": {
                "type": "object",
                "properties": {"page_key": {"type": "string"}},
                "required": ["page_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_page_image",
            "description": (
                "Меняет картинку страницы (поле image_custom). Принимает либо Telegram file_id "
                "(длинный токен из 30+ символов без пробелов), либо URL (http(s)://...). "
                "ВАЖНО: если в [CONTEXT] есть pending_image_file_id — используй именно его "
                "(админ только что прислал фото). Изменения видны мгновенно."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string"},
                    "image": {
                        "type": "string",
                        "description": "Telegram file_id или URL картинки.",
                    },
                },
                "required": ["page_key", "image"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "reset_page_image",
            "description": "Сбрасывает кастомную картинку страницы.",
            "parameters": {
                "type": "object",
                "properties": {"page_key": {"type": "string"}},
                "required": ["page_key"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "delete_page_button",
            "description": (
                "АТОМАРНО удаляет (скрывает) ОДНУ кнопку страницы по её id. "
                "Это инструмент №1 для задач «удали кнопку X», «убери кнопку X». "
                "Безопасен: не трогает другие кнопки и не теряет ранее скрытые. "
                "Работает и с дефолтными кнопками — добавляет tombstone-запись "
                "с is_hidden=true. Сначала вызови get_page_buttons чтобы узнать "
                "id кнопки, которую хочешь удалить."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string", "description": "Ключ страницы pages"},
                    "button_id": {"type": "string", "description": "id кнопки (например 'btn_support')"},
                },
                "required": ["page_key", "button_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "add_page_button",
            "description": (
                "АТОМАРНО добавляет ОДНУ кнопку на страницу (или возвращает скрытую: "
                "если кнопка с таким id уже есть — заменит её, фактически снимая is_hidden). "
                "Не трогает остальные кнопки. Используй для задач «добавь кнопку X», "
                "«верни обратно кнопку X»."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string"},
                    "button": {
                        "type": "object",
                        "description": "Один объект кнопки",
                        "properties": {
                            "id": {"type": "string"},
                            "label": {"type": "string"},
                            "row": {"type": "integer"},
                            "col": {"type": "integer"},
                            "action_type": {"type": "string", "enum": ["internal", "url", "system"]},
                            "action_value": {"type": "string"},
                            "color": {"type": "string"},
                            "is_hidden": {"type": "boolean"},
                        },
                        "required": ["id", "label", "row", "col", "action_type", "action_value"],
                    },
                },
                "required": ["page_key", "button"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_page_button",
            "description": (
                "АТОМАРНО меняет поля ОДНОЙ кнопки (label, action_value, row, col, is_hidden, color, action_type). "
                "Не трогает другие кнопки. Используй для задач «измени текст кнопки X», "
                "«поменяй ссылку у X», «перенеси X в другой ряд», «спрячь X», «верни X»."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "page_key": {"type": "string"},
                    "button_id": {"type": "string"},
                    "label": {"type": "string"},
                    "action_type": {"type": "string", "enum": ["internal", "url", "system"]},
                    "action_value": {"type": "string"},
                    "row": {"type": "integer"},
                    "col": {"type": "integer"},
                    "is_hidden": {"type": "boolean"},
                    "color": {"type": "string"},
                },
                "required": ["page_key", "button_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_page_buttons",
            "description": (
                "Обновляет кнопки страницы в базе данных (таблица pages, поле buttons_custom). "
                "Изменения видны мгновенно, БЕЗ перезапуска бота.\n"
                "Используй для любой операции с кнопками страниц main/help/trial/prepayment/referral/key_delivery: "
                "добавить, изменить label/ссылку, перенести, СКРЫТЬ.\n"
                "Передавай ПОЛНЫЙ список кнопок страницы в buttons (бери актуальный список через get_page_buttons).\n"
                "ВАЖНО ПРО УДАЛЕНИЕ ДЕФОЛТНЫХ КНОПОК: "
                "просто опустить кнопку в buttons НЕ удалит её — рендер всё равно возьмёт её из дефолтов. "
                "Чтобы убрать дефолтную кнопку с экрана: "
                "либо передай её id в hide_default_ids, либо включи её в buttons с is_hidden=true."
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
                            "ПОЛНЫЙ список кнопок страницы (включая и видимые, и скрытые с is_hidden=true). "
                            "Каждая кнопка — объект с полями: "
                            "id (str, уникальный), label (str, текст с эмодзи), row (int, ряд от 0), "
                            "col (int, колонка 0 или 1), action_type (str: 'internal' | 'url' | 'system'), "
                            "action_value (str: callback-имя для internal, URL для url), "
                            "color (str, обычно 'secondary'), is_hidden (bool; true чтобы скрыть, "
                            "в т.ч. дефолтную кнопку)."
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
                    "hide_default_ids": {
                        "type": "array",
                        "description": (
                            "Опциональный список id ДЕФОЛТНЫХ кнопок, которые нужно скрыть. "
                            "Шорткат для удаления: вместо того чтобы добавлять кнопку в buttons "
                            "со всеми полями и is_hidden=true, просто перечисли её id здесь. "
                            "Используй когда задача — «убери/удали кнопку X». "
                            "При этом buttons может быть пустым массивом."
                        ),
                        "items": {"type": "string"},
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

    Делит вывод на «Видимые» и «Скрытые» — чтобы модель ясно видела, что её
    предыдущее скрытие сработало. Раньше скрытые кнопки попадали в общий
    список и модель думала, что она не удалила кнопку.
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
    visible = [b for b in buttons if not b.get("is_hidden")]
    hidden = [b for b in buttons if b.get("is_hidden")]
    visible_ids = [b.get("id") for b in visible]
    hidden_ids = [b.get("id") for b in hidden]

    logger.info(
        "DeepSeek Agent tool: get_page_buttons page_key=%s visible=%d hidden=%d",
        page_key, len(visible), len(hidden),
    )

    out = [
        f"=== Кнопки страницы '{page_key}' ===",
        f"Видимых (пользователь их видит): {len(visible)}. id: {visible_ids}",
        f"Скрытых (is_hidden=true, не отображаются): {len(hidden)}. id: {hidden_ids}",
        "",
        f"--- ВИДИМЫЕ КНОПКИ ({len(visible)}) ---",
        json.dumps(visible, ensure_ascii=False, indent=2),
    ]
    if hidden:
        out.extend([
            "",
            f"--- СКРЫТЫЕ КНОПКИ ({len(hidden)}) ---",
            json.dumps(hidden, ensure_ascii=False, indent=2),
            "",
            "Скрытые кнопки уже не отображаются. Не пытайся их «удалить ещё раз».",
        ])
    out.append("=== КОНЕЦ ===")
    return "\n".join(out)


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


async def _load_custom_buttons(page_key: str) -> tuple[list[dict], dict | None]:
    """
    Загружает текущий buttons_custom страницы как python-list.
    Возвращает (custom_list, page_row). Если page_row=None — страницы не существует.
    Если поле buttons_custom пусто или None — возвращается пустой list.
    """
    from database.db_pages import get_page
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return [], None
    raw = page_row.get("buttons_custom")
    if not raw:
        return [], page_row
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed, page_row
    except (json.JSONDecodeError, TypeError):
        pass
    return [], page_row


async def _save_custom_buttons(page_key: str, buttons: list[dict]) -> None:
    """Сериализует и пишет buttons_custom в БД (через update_page_custom)."""
    from database.db_pages import update_page_custom
    buttons_json = json.dumps(buttons, ensure_ascii=False)
    await asyncio.to_thread(update_page_custom, page_key, buttons=buttons_json)


def _find_default_button(page_row: dict, button_id: str) -> dict | None:
    """Находит дефолтную кнопку по id в buttons_default страницы."""
    raw = page_row.get("buttons_default")
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(parsed, list):
        return None
    for b in parsed:
        if isinstance(b, dict) and b.get("id") == button_id:
            return b
    return None


async def _delete_page_button(page_key: str, button_id: str) -> str:
    """
    Атомарно «удаляет» (скрывает) одну кнопку страницы.

    Алгоритм:
    1. Читает текущий buttons_custom (если есть).
    2. Если кнопка с этим id уже в custom — ставит is_hidden=true.
    3. Если нет — добавляет tombstone-запись с is_hidden=true.
    4. Пишет обновлённый custom. Остальные кнопки не трогает.
    """
    page_key = (page_key or "").strip()
    button_id = (button_id or "").strip()
    if not page_key:
        return "ОШИБКА delete_page_button: не указан page_key"
    if not button_id:
        return "ОШИБКА delete_page_button: не указан button_id"

    custom, page_row = await _load_custom_buttons(page_key)
    if page_row is None:
        return f"ОШИБКА delete_page_button: страница '{page_key}' не найдена"

    default_btn = _find_default_button(page_row, button_id)
    is_known = default_btn is not None or any(
        b.get("id") == button_id for b in custom
    )
    if not is_known:
        return (
            f"ОШИБКА delete_page_button: кнопка с id='{button_id}' не найдена ни в "
            f"buttons_default, ни в buttons_custom страницы '{page_key}'. "
            f"Сначала вызови get_page_buttons чтобы узнать корректные id."
        )

    # Изменяем существующую запись или добавляем новую
    updated = False
    for b in custom:
        if b.get("id") == button_id:
            b["is_hidden"] = True
            updated = True
            break
    if not updated:
        # Tombstone: копируем дефолтную кнопку (чтобы все поля были корректны) и ставим hidden
        if default_btn is not None:
            tomb = dict(default_btn)
            tomb["is_hidden"] = True
            custom.append(tomb)
        else:
            custom.append({
                "id": button_id,
                "label": "",
                "color": "secondary",
                "row": 0,
                "col": 0,
                "is_hidden": True,
                "action_type": "internal",
                "action_value": "noop",
            })

    await _save_custom_buttons(page_key, custom)
    logger.info(
        "DeepSeek Agent tool: delete_page_button page_key=%s id=%s",
        page_key, button_id,
    )
    return (
        f"Кнопка '{button_id}' скрыта на странице '{page_key}'. "
        "Изменения видны мгновенно."
    )


async def _add_page_button(page_key: str, button: Any) -> str:
    """
    Атомарно добавляет одну кнопку. Если кнопка с таким id уже есть — заменяет её
    (полезно для «верни кнопку обратно» = снять hidden + восстановить поля).
    Не трогает остальные кнопки в custom.
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА add_page_button: не указан page_key"
    if not isinstance(button, dict):
        return f"ОШИБКА add_page_button: button должен быть объектом, получено: {type(button).__name__}"

    try:
        normalized = _normalize_button(button, 0)
    except DeepSeekAgentError as e:
        return f"ОШИБКА add_page_button: {e}"

    custom, page_row = await _load_custom_buttons(page_key)
    if page_row is None:
        return f"ОШИБКА add_page_button: страница '{page_key}' не найдена"

    # Заменяем по id или добавляем
    replaced = False
    for i, b in enumerate(custom):
        if b.get("id") == normalized["id"]:
            custom[i] = normalized
            replaced = True
            break
    if not replaced:
        custom.append(normalized)

    await _save_custom_buttons(page_key, custom)
    action = "обновлена" if replaced else "добавлена"
    logger.info(
        "DeepSeek Agent tool: add_page_button page_key=%s id=%s replaced=%s",
        page_key, normalized["id"], replaced,
    )
    return (
        f"Кнопка '{normalized['id']}' {action} на странице '{page_key}'. "
        "Изменения видны мгновенно."
    )


async def _update_page_button(
    page_key: str,
    button_id: str,
    label: Any = None,
    action_type: Any = None,
    action_value: Any = None,
    row: Any = None,
    col: Any = None,
    is_hidden: Any = None,
    color: Any = None,
) -> str:
    """
    Атомарно меняет поля одной кнопки. Берёт текущее состояние (custom override
    over default), применяет изменения, пишет в custom.
    """
    page_key = (page_key or "").strip()
    button_id = (button_id or "").strip()
    if not page_key:
        return "ОШИБКА update_page_button: не указан page_key"
    if not button_id:
        return "ОШИБКА update_page_button: не указан button_id"

    custom, page_row = await _load_custom_buttons(page_key)
    if page_row is None:
        return f"ОШИБКА update_page_button: страница '{page_key}' не найдена"

    # Берём текущую кнопку: сначала из custom, потом из default
    current = None
    in_custom = False
    for b in custom:
        if b.get("id") == button_id:
            current = dict(b)
            in_custom = True
            break
    if current is None:
        default_btn = _find_default_button(page_row, button_id)
        if default_btn is None:
            return (
                f"ОШИБКА update_page_button: кнопка с id='{button_id}' не найдена "
                f"на странице '{page_key}'."
            )
        current = dict(default_btn)

    # Применяем изменения
    changes_applied = []
    if label is not None:
        current["label"] = str(label)
        changes_applied.append("label")
    if action_type is not None:
        at_str = str(action_type).strip()
        if at_str not in _ALLOWED_ACTION_TYPES:
            return f"ОШИБКА update_page_button: action_type={at_str!r} недопустим"
        current["action_type"] = at_str
        changes_applied.append("action_type")
    if action_value is not None:
        current["action_value"] = str(action_value)
        changes_applied.append("action_value")
    if row is not None:
        current["row"] = int(row)
        changes_applied.append("row")
    if col is not None:
        current["col"] = int(col)
        changes_applied.append("col")
    if is_hidden is not None:
        current["is_hidden"] = bool(is_hidden)
        changes_applied.append("is_hidden")
    if color is not None:
        current["color"] = str(color)
        changes_applied.append("color")

    if not changes_applied:
        return "ОШИБКА update_page_button: не указано ни одно поле для изменения"

    # Нормализуем и сохраняем
    try:
        current = _normalize_button(current, 0)
    except DeepSeekAgentError as e:
        return f"ОШИБКА update_page_button: {e}"

    if in_custom:
        for i, b in enumerate(custom):
            if b.get("id") == button_id:
                custom[i] = current
                break
    else:
        custom.append(current)

    await _save_custom_buttons(page_key, custom)
    logger.info(
        "DeepSeek Agent tool: update_page_button page_key=%s id=%s fields=%s",
        page_key, button_id, ",".join(changes_applied),
    )
    return (
        f"Кнопка '{button_id}' на странице '{page_key}' обновлена. "
        f"Изменены поля: {', '.join(changes_applied)}. Изменения видны мгновенно."
    )


_MAX_TEXT_LEN = 4000  # Telegram caps: 4096 для message, 1024 для caption. С запасом.


async def _update_page_text(page_key: str, text: Any) -> str:
    """Меняет text_custom страницы. Принимает HTML aiogram (b, i, code, a, etc.)."""
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА update_page_text: не указан page_key"
    if text is None:
        return "ОШИБКА update_page_text: не указан text"
    text_str = str(text)
    if len(text_str) > _MAX_TEXT_LEN:
        return (
            f"ОШИБКА update_page_text: текст слишком длинный ({len(text_str)} символов). "
            f"Максимум {_MAX_TEXT_LEN}. Сократи или используй несколько страниц."
        )

    from database.db_pages import get_page, update_page_custom
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return f"ОШИБКА update_page_text: страница '{page_key}' не найдена"

    try:
        await asyncio.to_thread(update_page_custom, page_key, text=text_str)
    except Exception as e:
        return f"ОШИБКА update_page_text: запись в БД не удалась: {e}"

    logger.info(
        "DeepSeek Agent tool: update_page_text page_key=%s len=%d",
        page_key, len(text_str),
    )
    return (
        f"Текст страницы '{page_key}' обновлён ({len(text_str)} символов). "
        "Изменения видны мгновенно."
    )


async def _reset_page_text(page_key: str) -> str:
    """Сброс кастомного текста: рендер вернётся к text_default."""
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА reset_page_text: не указан page_key"

    from database.db_pages import get_page, update_page_custom
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return f"ОШИБКА reset_page_text: страница '{page_key}' не найдена"

    try:
        # Пустая строка в text_custom — page_renderer возьмёт text_default ("" falsy)
        await asyncio.to_thread(update_page_custom, page_key, text="")
    except Exception as e:
        return f"ОШИБКА reset_page_text: запись в БД не удалась: {e}"

    logger.info("DeepSeek Agent tool: reset_page_text page_key=%s", page_key)
    return f"Текст страницы '{page_key}' сброшен на дефолтный. Изменения видны мгновенно."


async def _update_page_image(page_key: str, image: Any) -> str:
    """
    Меняет image_custom: принимает Telegram file_id (короткий blob) ИЛИ URL.
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА update_page_image: не указан page_key"
    if image is None or str(image).strip() == "":
        return "ОШИБКА update_page_image: не указан image (file_id или URL). Для сброса используй reset_page_image."

    image_str = str(image).strip()
    # Лёгкая валидация: либо URL, либо непустая строка похожая на file_id (>= 20 chars)
    is_url = image_str.startswith(("http://", "https://"))
    is_file_id_like = len(image_str) >= 20 and not any(c.isspace() for c in image_str)
    if not (is_url or is_file_id_like):
        return (
            f"ОШИБКА update_page_image: image должен быть Telegram file_id "
            f"(длинный токен без пробелов) или URL (http(s)://...). Получено: {image_str[:60]!r}"
        )

    from database.db_pages import get_page, update_page_custom
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return f"ОШИБКА update_page_image: страница '{page_key}' не найдена"

    try:
        await asyncio.to_thread(update_page_custom, page_key, image=image_str)
    except Exception as e:
        return f"ОШИБКА update_page_image: запись в БД не удалась: {e}"

    kind = "URL" if is_url else "file_id"
    logger.info(
        "DeepSeek Agent tool: update_page_image page_key=%s kind=%s",
        page_key, kind,
    )
    return (
        f"Картинка страницы '{page_key}' обновлена ({kind}). "
        "Изменения видны мгновенно — пользователь увидит её при следующем заходе."
    )


async def _reset_page_image(page_key: str) -> str:
    """Сброс кастомной картинки: рендер вернётся к image_default (если есть) или без картинки."""
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА reset_page_image: не указан page_key"

    from database.db_pages import get_page, update_page_custom
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return f"ОШИБКА reset_page_image: страница '{page_key}' не найдена"

    try:
        await asyncio.to_thread(update_page_custom, page_key, image="")
    except Exception as e:
        return f"ОШИБКА reset_page_image: запись в БД не удалась: {e}"

    logger.info("DeepSeek Agent tool: reset_page_image page_key=%s", page_key)
    return f"Картинка страницы '{page_key}' сброшена. Изменения видны мгновенно."


async def _get_page_content(page_key: str) -> str:
    """
    Возвращает текущее содержимое страницы: текст, картинку, число кнопок.
    Помогает модели понять состояние перед изменением.
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА get_page_content: не указан page_key"

    try:
        from bot.utils.page_renderer import get_page_data
    except Exception as e:
        return f"ОШИБКА get_page_content: импорт page_renderer не удался: {e}"

    from database.db_pages import get_page
    page_row = await asyncio.to_thread(get_page, page_key)
    if not page_row:
        return f"ОШИБКА get_page_content: страница '{page_key}' не найдена"

    try:
        data = await asyncio.to_thread(get_page_data, page_key)
    except Exception as e:
        return f"ОШИБКА get_page_content: чтение БД не удалось: {e}"

    text = data.get("text") or ""
    image = data.get("image")
    buttons = data.get("buttons", []) or []
    visible = sum(1 for b in buttons if not b.get("is_hidden"))
    hidden = len(buttons) - visible

    # Дополнительно показываем источник (custom или default)
    text_source = "custom" if page_row.get("text_custom") else "default"
    image_source = "custom" if page_row.get("image_custom") else (
        "default" if page_row.get("image_default") else "none"
    )

    text_preview = text if len(text) <= 800 else text[:800] + f"\n... (обрезано, всего {len(text)} символов)"

    logger.info(
        "DeepSeek Agent tool: get_page_content page_key=%s text_src=%s image_src=%s buttons=%d",
        page_key, text_source, image_source, len(buttons),
    )

    out = [
        f"=== Содержимое страницы '{page_key}' ===",
        f"Текст ({text_source}, {len(text)} символов):",
        text_preview,
        "",
        f"Картинка: {image_source}" + (f" — {image[:60]}..." if image else ""),
        "",
        f"Кнопки: видимых {visible}, скрытых {hidden}. Подробности — get_page_buttons.",
        "=== КОНЕЦ ===",
    ]
    return "\n".join(out)


async def _update_page_buttons(
    page_key: str,
    buttons: Any,
    hide_default_ids: Any = None,
) -> str:
    """
    Прямая запись кнопок страницы в БД (поле buttons_custom).

    Изменения видны мгновенно — рендер главного меню читает pages.buttons_custom при
    каждом /start. Перезапуск бота не требуется.

    Важно про удаление дефолтных кнопок:
    Логика мёржа в page_renderer.py не позволяет «удалить» дефолтную кнопку,
    просто опустив её в buttons. Default-кнопки берутся из buttons_default по id.
    Чтобы кнопка не отображалась — её надо включить в buttons с флагом
    is_hidden=true, либо передать её id в hide_default_ids (этот хелпер сам
    добавит запись с is_hidden=true).
    """
    page_key = (page_key or "").strip()
    if not page_key:
        return "ОШИБКА update_page_buttons: не указан page_key"

    if not isinstance(buttons, list):
        return (
            "ОШИБКА update_page_buttons: параметр buttons должен быть массивом (list), "
            f"получено: {type(buttons).__name__}"
        )

    # hide_default_ids — опциональный список id для скрытия дефолтных кнопок.
    hide_ids: list[str] = []
    if hide_default_ids is not None:
        if not isinstance(hide_default_ids, list):
            return (
                "ОШИБКА update_page_buttons: hide_default_ids должен быть массивом (list) id строк, "
                f"получено: {type(hide_default_ids).__name__}"
            )
        for hid in hide_default_ids:
            hid_str = str(hid).strip()
            if hid_str:
                hide_ids.append(hid_str)

    try:
        normalized = [_normalize_button(b, i) for i, b in enumerate(buttons)]
    except DeepSeekAgentError as e:
        return f"ОШИБКА update_page_buttons: {e}"

    # Применяем hide_default_ids: для каждого id, который ещё не в buttons,
    # добавим заглушку с is_hidden=true. Если id уже в списке — принудительно
    # установим is_hidden=true (выигрывает явное скрытие).
    if hide_ids:
        present_ids = {b["id"] for b in normalized}
        for hid in hide_ids:
            if hid in present_ids:
                for b in normalized:
                    if b["id"] == hid:
                        b["is_hidden"] = True
                        break
            else:
                # Минимальная корректная запись-tombstone: id + is_hidden=true.
                # Остальные обязательные поля заполняем no-op значениями.
                normalized.append({
                    "id": hid,
                    "label": "",
                    "color": "secondary",
                    "row": 0,
                    "col": 0,
                    "is_hidden": True,
                    "action_type": "internal",
                    "action_value": "noop",
                })

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

    visible_count = sum(1 for b in normalized if not b.get("is_hidden"))
    hidden_count = len(normalized) - visible_count

    logger.info(
        "DeepSeek Agent tool: update_page_buttons page_key=%s buttons=%d visible=%d hidden=%d",
        page_key,
        len(normalized),
        visible_count,
        hidden_count,
    )

    hide_note = f", скрыто (is_hidden=true) {hidden_count}" if hidden_count else ""
    return (
        f"Кнопки страницы '{page_key}' обновлены: {visible_count} видимых{hide_note}. "
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

    elif tool_name == "get_page_content":
        return await _get_page_content(str(arguments.get("page_key", "")).strip())

    elif tool_name == "update_page_text":
        return await _update_page_text(
            str(arguments.get("page_key", "")).strip(),
            arguments.get("text"),
        )

    elif tool_name == "reset_page_text":
        return await _reset_page_text(str(arguments.get("page_key", "")).strip())

    elif tool_name == "update_page_image":
        return await _update_page_image(
            str(arguments.get("page_key", "")).strip(),
            arguments.get("image"),
        )

    elif tool_name == "reset_page_image":
        return await _reset_page_image(str(arguments.get("page_key", "")).strip())

    elif tool_name == "delete_page_button":
        page_key = str(arguments.get("page_key", "")).strip()
        button_id = str(arguments.get("button_id", "")).strip()
        return await _delete_page_button(page_key, button_id)

    elif tool_name == "add_page_button":
        page_key = str(arguments.get("page_key", "")).strip()
        button = arguments.get("button")
        return await _add_page_button(page_key, button)

    elif tool_name == "update_page_button":
        page_key = str(arguments.get("page_key", "")).strip()
        button_id = str(arguments.get("button_id", "")).strip()
        return await _update_page_button(
            page_key,
            button_id,
            label=arguments.get("label"),
            action_type=arguments.get("action_type"),
            action_value=arguments.get("action_value"),
            row=arguments.get("row"),
            col=arguments.get("col"),
            is_hidden=arguments.get("is_hidden"),
            color=arguments.get("color"),
        )

    elif tool_name == "update_page_buttons":
        page_key = str(arguments.get("page_key", "")).strip()
        buttons = arguments.get("buttons")
        hide_default_ids = arguments.get("hide_default_ids")
        if not page_key:
            return "ОШИБКА: не указан page_key для update_page_buttons"
        if buttons is None:
            # Допускаем пустой buttons, если переданы только hide_default_ids
            # (сценарий «просто скрой кнопку X»).
            if hide_default_ids:
                buttons = []
            else:
                return "ОШИБКА: не указан buttons для update_page_buttons (передай полный список кнопок)"
        return await _update_page_buttons(page_key, buttons, hide_default_ids=hide_default_ids)

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
    pending_image_file_id: Optional[str] = None,
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
        pending_image_file_id: Telegram file_id фото, которое админ только что прислал.
            Если задан — модель должна использовать его в update_page_image, если задача
            про картинку.

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
        # НЕ даём инструменты записи и page-tools
        active_tools = [
            t for t in TOOLS
            if t["function"]["name"] not in (
                "modify_file_content",
                "patch_file_content",
                "get_page_buttons",
                "get_page_content",
                "update_page_buttons",
                "delete_page_button",
                "add_page_button",
                "update_page_button",
                "update_page_text",
                "reset_page_text",
                "update_page_image",
                "reset_page_image",
            )
        ]
    else:
        active_tools = TOOLS

    # Подмешиваем контекст экрана админа и pending-картинки, если они переданы.
    # Это сильнее всего помогает модели понять «здесь/сюда/тут» в командах вроде
    # «/ai добавь сюда кнопку» — она увидит current_page_key и подставит его как default.
    page_context_key = (current_page_key or "").strip()
    pending_image = (pending_image_file_id or "").strip()
    context_lines: list[str] = []
    if page_context_key:
        context_lines.append(f"current_page_key='{page_context_key}'")
    if pending_image:
        context_lines.append(f"pending_image_file_id='{pending_image}'")

    if context_lines:
        notes = [
            "(Это технические подсказки от системы, не часть задачи админа.)",
        ]
        if page_context_key:
            notes.append(
                "Слова «здесь», «сюда», «тут», «туда», «это меню», «эта страница» "
                "относятся к current_page_key. Если page_key явно не указан — это default."
            )
        if pending_image:
            notes.append(
                "Админ только что прислал фото — file_id выше. Если задача про картинку "
                "(«поставь сюда», «замени картинку», «обнови фото»), вызови "
                "update_page_image(page_key=<нужная>, image=pending_image_file_id)."
            )
        contextualized_user_message = (
            "[CONTEXT] " + "; ".join(context_lines) + "\n"
            + "\n".join(notes) + "\n\n"
            + f"ЗАДАЧА: {user_message}"
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
                    "- Если задача про кнопки страниц (одну кнопку):\n"
                    "  • удалить → delete_page_button(page_key, button_id)\n"
                    "  • добавить → add_page_button(page_key, button={...})\n"
                    "  • изменить → update_page_button(page_key, button_id, label=...|action_value=...|...)\n"
                    "  НЕ читай database/migrations.py — там устаревшие дефолты.\n"
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
                elif tool_name == "get_page_content":
                    await _progress(f"🔍 Читаю содержимое страницы '{page_hint}'...")
                elif tool_name == "update_page_text":
                    t = str(args.get("text", ""))
                    await _progress(f"📝 Меняю текст страницы '{page_hint}' ({len(t)} символов)...")
                elif tool_name == "reset_page_text":
                    await _progress(f"↩️ Сбрасываю текст страницы '{page_hint}' на дефолтный...")
                elif tool_name == "update_page_image":
                    img = str(args.get("image", ""))
                    kind = "URL" if img.startswith(("http://", "https://")) else "file_id"
                    await _progress(f"🖼 Меняю картинку страницы '{page_hint}' ({kind})...")
                elif tool_name == "reset_page_image":
                    await _progress(f"↩️ Сбрасываю картинку страницы '{page_hint}'...")
                elif tool_name == "delete_page_button":
                    bid = str(args.get("button_id", ""))
                    await _progress(f"❌ Скрываю кнопку '{bid}' на странице '{page_hint}'...")
                elif tool_name == "add_page_button":
                    btn = args.get("button") or {}
                    bid = str(btn.get("id", ""))
                    await _progress(f"➕ Добавляю кнопку '{bid}' на страницу '{page_hint}'...")
                elif tool_name == "update_page_button":
                    bid = str(args.get("button_id", ""))
                    await _progress(f"✏️ Меняю кнопку '{bid}' на странице '{page_hint}'...")
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
                _DB_WRITE_TOOLS = (
                    "update_page_buttons",
                    "delete_page_button",
                    "add_page_button",
                    "update_page_button",
                    "update_page_text",
                    "reset_page_text",
                    "update_page_image",
                    "reset_page_image",
                )
                if tool_name in _DB_WRITE_TOOLS and not result_text.startswith("ОШИБКА"):
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
