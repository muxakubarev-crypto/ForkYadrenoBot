"""
Локальный асинхронный ИИ-агент на базе DeepSeek API (OpenAI-совместимый).

Предоставляет три инструмента (Function Calling / Tools):
- read_file_content  — чтение файлов бота
- modify_file_content — перезапись / правка кода
- restart_bot_process — перезапуск systemd-службы

Безопасность:
- Все пути валидируются через _resolve_tool_path (не выходят за PROJECT_ROOT)
- Shell-команды проверяются deny-листом опасных паттернов
- Полный аудит каждого tool_call в лог
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional

from openai import AsyncOpenAI

from config import DEEPSEEK_API_KEY, DEEPSEEK_BASE_URL, DEEPSEEK_MODEL, DEEPSEEK_PROXY

logger = logging.getLogger(__name__)

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

КРИТИЧЕСКИ ВАЖНО: Ты НИКОГДА, НИ ПРИ КАКИХ ОБСТОЯТЕЛЬСТВАХ не задаёшь уточняющих вопросов.
Ты САМ принимаешь решение «куда» и «как» на основе анализа кодовой базы.
Если не уверен — всё равно действуешь, выбрав наиболее вероятный вариант.

ЕСЛИ ТЫ ЗАДАШЬ ВОПРОС — ТЫ НАРУШИШЬ ПРОТОКОЛ. ДИАЛОГ РАЗОРВЁТСЯ.

Доступные инструменты:
1. **read_file_content** — читать файлы
2. **modify_file_content** — ПЕРЕЗАПИСАТЬ файл ПОЛНОСТЬЮ
3. **restart_bot_process** — перезапустить systemd-службу

АЛГОРИТМ РАБОТЫ (строго соблюдай):
1. Сразу читай read_file_content нужных файлов — НЕ спрашивай какие, читай те что вероятнее всего.
2. Вноси изменения через modify_file_content (ВЕСЬ файл целиком).
3. Вызови restart_bot_process.
4. Напиши ОДНИМ предложением что сделано.

ГДЕ ЧТО ЛЕЖИТ:
- Кнопки главного меню: bot/keyboards/admin_misc.py → admin_main_menu_kb()
- Стартовое сообщение /start: bot/handlers/user/start.py
- Пользовательские кнопки: bot/keyboards/user.py
- Обработчики: bot/handlers/

ОТВЕТ ВСЕГДА СТРОГАЯ ФОРМУЛА:
«Файл X изменён: [что сделано]. Перезагрузка...»
Если задача невыполнима — «Ошибка: [причина]»"""

SYSTEM_PROMPT_DIALOG = """Ты — ИИ-администратор VPN-бота Yadreno VPN.
Ты общаешься с администратором сервера в режиме диалога.

Доступные инструменты:
1. **read_file_content** — читать файлы исходного кода бота
2. **modify_file_content** — перезаписывать / править файлы кода (ПОЛНОСТЬЮ весь файл)
3. **restart_bot_process** — перезапускать systemd-службу бота

Правила диалогового режима:
- Если задача непонятна — задай ОДИН уточняющий вопрос и жди ответа.
- Если задача ясна — сразу выполняй через инструменты, не переспрашивай.
- Перед изменением файла всегда сначала прочитай его через read_file_content.
- При изменении кода возвращай ПОЛНОЕ содержимое файла.
- Кнопки главного меню: bot/keyboards/admin_misc.py (admin_main_menu_kb).
- Пользовательские кнопки: bot/keyboards/user.py.
- Обработчики: bot/handlers/.
- После успешных изменений вызывай restart_bot_process.
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
            "description": "Полностью перезаписывает содержимое файла. Внимание: передавай ПОЛНОЕ новое содержимое файла, а не только изменённые строки.",
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
]


# ---------------------------------------------------------------------------
# Исполнение tool_call
# ---------------------------------------------------------------------------
async def _read_file_content(path: str, max_lines: int = 500) -> str:
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
    """Перезаписывает файл полностью."""
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

        process = await asyncio.create_subprocess_exec(
            "systemctl", "restart", service_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)

        if process.returncode == 0:
            logger.info(
                "DeepSeek Agent tool: restart_bot_process service=%s OK",
                service_name,
            )
            return f"Служба {service_name} успешно перезапущена."
        else:
            error_msg = (stderr or stdout or b"").decode("utf-8", errors="replace")
            return f"ОШИБКА перезапуска {service_name} (exit={process.returncode}): {error_msg}"
    except asyncio.TimeoutError:
        return f"ОШИБКА: таймаут перезапуска {service_name} (30 сек)"
    except FileNotFoundError:
        return "ОШИБКА: systemctl не найден в системе"
    except Exception as e:
        return f"ОШИБКА перезапуска {service_name}: {e}"


async def _execute_tool_call(tool_name: str, arguments: dict[str, Any]) -> str:
    """Диспетчер: исполняет tool_call и возвращает строку-результат."""
    logger.info(
        "DeepSeek Agent tool_call: tool=%s args=%s",
        tool_name,
        {k: v for k, v in arguments.items() if k != "content"},
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

    elif tool_name == "restart_bot_process":
        service_name = str(arguments.get("service_name", "yadreno-vpn")).strip()
        return await _restart_bot_process(service_name)

    else:
        return f"ОШИБКА: неизвестный инструмент {tool_name!r}"


# ---------------------------------------------------------------------------
# Основной цикл диалога
# ---------------------------------------------------------------------------


async def run_dialog(
    user_message: str,
    system_prompt: str | None = None,
) -> str:
    """
    Отправляет сообщение модели DeepSeek и выполняет полный цикл
    запрос → tool_calls → ответ (с повторами при необходимости).

    Args:
        user_message: Текст задачи от администратора.
        system_prompt: Системный промпт. Если None — используется SYSTEM_PROMPT_EXEC.

    Возвращает финальный текст ответа для показа администратору.

    Выбрасывает DeepSeekAgentError при ошибках API.
    """
    if not DEEPSEEK_API_KEY:
        raise DeepSeekAgentError(
            "DEEPSEEK_API_KEY не задан. Добавьте ключ в .env или config.py."
        )

    client = _build_client()
    model = DEEPSEEK_MODEL

    prompt = system_prompt if system_prompt is not None else SYSTEM_PROMPT_EXEC
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": prompt},
        {"role": "user", "content": user_message},
    ]

    max_tool_rounds = 5
    for _round in range(max_tool_rounds):
        try:
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                tools=TOOLS,
                tool_choice="auto",
                temperature=0.3,
                max_tokens=4096,
            )
        except Exception as e:
            raise DeepSeekAgentError(f"Ошибка DeepSeek API: {e}") from e

        choice = response.choices[0]
        finish_reason = choice.finish_reason

        # Если модель вернула финальный текст
        if finish_reason == "stop" and choice.message.content:
            return choice.message.content

        # Если модель хочет вызвать инструмент
        if finish_reason == "tool_calls" or choice.message.tool_calls:
            # Добавляем ответ модели в историю
            messages.append({
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
            })

            # Исполняем каждый tool_call
            for tc in choice.message.tool_calls:
                import json
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}

                result_text = await _execute_tool_call(tc.function.name, args)

                # Добавляем результат в историю
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": result_text,
                })

            continue  # Ещё один раунд, чтобы модель обработала результаты

        # Другие причины завершения
        if choice.message.content:
            return choice.message.content

        raise DeepSeekAgentError(
            f"Неожиданный finish_reason: {finish_reason}"
        )

    raise DeepSeekAgentError(
        f"Достигнут лимит tool_call раундов ({max_tool_rounds})"
    )
