"""
Диалог с ИИ-агентом DeepSeek AI и команда /ai.

Жёсткий firewall: доступ только для ADMIN_TELEGRAM_ID (строгое int-сравнение).
Посторонние пользователи мгновенно отсекаются без объяснения причин (RCE-защита).

Прогресс: каждый шаг агента виден в реальном времени.
Перезапуск: автоматический после изменения файлов.
"""
from __future__ import annotations

import asyncio

from aiogram import F, Router
from aiogram.filters import Command, CommandObject
from aiogram.fsm.context import FSMContext
from aiogram.types import CallbackQuery, Message

from bot.keyboards.admin import (
    deepseek_admin_chat_kb,
    deepseek_admin_no_key_kb,
)
from bot.services.deepseek_agent import (
    DeepSeekAgentError,
    ProgressCallback,
    _restart_bot_process,
    run_dialog,
    SYSTEM_PROMPT_DIALOG,
    SYSTEM_PROMPT_EXEC,
)
from bot.services.page_context import get_page_context
from bot.states.admin_states import AdminStates
from bot.utils.admin import is_admin
from bot.utils.text import escape_html, safe_edit_or_send
from config import ADMIN_TELEGRAM_ID, DEEPSEEK_API_KEY

router = Router()


# ---------------------------------------------------------------------------
# Firewall: строгая проверка ADMIN_TELEGRAM_ID
# ---------------------------------------------------------------------------
def _is_ai_admin(user_id: int) -> bool:
    """
    Жёсткий firewall для AI-агента.

    Доступ разрешён ТОЛЬКО если user_id строго совпадает с ADMIN_TELEGRAM_ID.
    Это предотвращает RCE посторонними даже при ошибках в списке ADMIN_IDS.
    """
    if not ADMIN_TELEGRAM_ID:
        return False
    return user_id == ADMIN_TELEGRAM_ID


# ---------------------------------------------------------------------------
# UI-тексты
# ---------------------------------------------------------------------------
def _chat_intro_text() -> str:
    """Текст экрана чата с агентом."""
    return (
        "🤖 <b>DeepSeek AI Agent</b>\n\n"
        "Напишите задачу обычным сообщением — ИИ-агент может читать и "
        "редактировать файлы бота, а также перезапускать службу.\n\n"
        "Модель: <code>deepseek-v4-pro</code> (по умолчанию) / <code>deepseek-v4-flash</code>\n\n"
        "Чтобы остановить текущий запрос, отправьте <code>/cancel</code>."
    )


# ---------------------------------------------------------------------------
# Прогресс-коллбэк: редактирует thinking-сообщение в реальном времени
# ---------------------------------------------------------------------------
def _make_progress(anchor: Message):
    """
    Возвращает async-коллбэк для run_dialog(), который редактирует
    сообщение-якорь, показывая текущий шаг агента.
    """
    async def _progress(step: str) -> None:
        try:
            await safe_edit_or_send(
                anchor,
                f"🤖 <b>DeepSeek AI</b>\n\n{escape_html(step)}",
            )
        except Exception:
            pass

    return _progress


# ---------------------------------------------------------------------------
# Авто-перезапуск после изменений
# ---------------------------------------------------------------------------
async def _auto_restart_if_needed(
    modified_files: list[str],
    anchor: Message,
) -> None:
    """Если были изменены файлы — перезапускает бота и сообщает об этом."""
    if not modified_files:
        return

    files_list = ", ".join(modified_files)

    # Сначала показываем сообщение
    await safe_edit_or_send(
        anchor,
        f"🤖 <b>DeepSeek AI</b>\n\n"
        f"✅ Изменения внесены. Файлы: {escape_html(files_list)}.\n\n"
        f"🔄 Перезапускаю бота...\n"
        f"<i>Бот вернётся через ~5 секунд. Отправьте /start.</i>",
        reply_markup=deepseek_admin_chat_kb(),
    )

    # Даём Telegram 2 секунды доставить сообщение
    await asyncio.sleep(2)

    try:
        await _restart_bot_process("yadreno-vpn")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Вход в раздел
# ---------------------------------------------------------------------------
@router.callback_query(F.data == "admin_yadreno")
async def show_deepseek_admin(callback: CallbackQuery, state: FSMContext):
    """Открывает раздел DeepSeek AI Agent."""
    if not _is_ai_admin(callback.from_user.id):
        await callback.answer("⛔ Доступ запрещён", show_alert=True)
        return

    await callback.answer()

    if not DEEPSEEK_API_KEY:
        await safe_edit_or_send(
            callback.message,
            "🤖 <b>DeepSeek AI Agent</b>\n\n"
            "❌ <b>DEEPSEEK_API_KEY не задан.</b>\n\n"
            "Добавьте ключ в файл <code>.env</code>:\n"
            "<code>DEEPSEEK_API_KEY=sk-...</code>\n\n"
            "Получить ключ: https://platform.deepseek.com/api_keys",
            reply_markup=deepseek_admin_no_key_kb(),
        )
        return

    await state.set_state(AdminStates.deepseek_chat)
    await safe_edit_or_send(
        callback.message,
        _chat_intro_text(),
        reply_markup=deepseek_admin_chat_kb(),
    )


# ---------------------------------------------------------------------------
# Команда /ai — вход в ИИ-чат из любого места
# ---------------------------------------------------------------------------
@router.message(Command("ai"))
async def ai_command(message: Message, state: FSMContext, command: CommandObject):
    """
    Команда /ai — универсальный вход в диалог с DeepSeek AI.

    Использование:
        /ai — войти в режим диалога
        /ai поправь код обработчика платежей — сразу отправить задачу
    """
    # ЖЁСТКИЙ FIREWALL
    if not _is_ai_admin(message.from_user.id):
        return

    if not DEEPSEEK_API_KEY:
        await safe_edit_or_send(
            message,
            "🤖 <b>DeepSeek AI Agent</b>\n\n"
            "❌ <b>DEEPSEEK_API_KEY не задан.</b>\n\n"
            "Добавьте ключ в файл <code>.env</code>:\n"
            "<code>DEEPSEEK_API_KEY=sk-...</code>",
            reply_markup=deepseek_admin_no_key_kb(),
            force_new=True,
        )
        return

    task = (command.args or "").strip()

    if task:
        # Режим исполнения: FSM + progress + авто-перезапуск.
        # _run_agent сам читает контекст экрана и pending_image_file_id.
        await state.set_state(AdminStates.deepseek_chat)
        await _run_agent(
            message,
            state,
            task,
            system_prompt=SYSTEM_PROMPT_EXEC,
            thinking_verb="Анализирую задачу",
        )
        return

    # Без задачи — просто входим в режим диалога
    await state.set_state(AdminStates.deepseek_chat)
    await safe_edit_or_send(
        message,
        _chat_intro_text(),
        reply_markup=deepseek_admin_chat_kb(),
        force_new=True,
    )


# ---------------------------------------------------------------------------
# Команда /cancel в режиме диалога
# ---------------------------------------------------------------------------
@router.message(Command("cancel"), AdminStates.deepseek_chat)
async def cancel_dialog(message: Message, state: FSMContext):
    """Выход из режима диалога с DeepSeek AI."""
    if not _is_ai_admin(message.from_user.id):
        return

    await state.clear()
    await safe_edit_or_send(
        message,
        "🛑 <b>Диалог с DeepSeek AI завершён.</b>\n\n"
        "Отправьте <code>/ai</code> чтобы начать заново.",
        force_new=True,
    )


# ---------------------------------------------------------------------------
# Сообщения в режиме диалога
# ---------------------------------------------------------------------------
async def _run_agent(
    message: Message,
    state: FSMContext,
    task_text: str,
    system_prompt: str = SYSTEM_PROMPT_DIALOG,
    thinking_verb: str = "Думаю",
) -> None:
    """
    Универсальный запуск агента из любого хендлера.
    Достаёт контекст экрана и pending_image_file_id из FSM, запускает run_dialog,
    показывает прогресс/результат, при изменениях файлов вызывает рестарт.
    """
    ctx = get_page_context(message.from_user.id)
    current_page_key = ctx.page_key if ctx else None

    # Достаём pending image (если был прислан раньше) и сразу очищаем — одна задача.
    data = await state.get_data()
    pending_image = data.get("pending_image_file_id")
    if pending_image:
        await state.update_data(pending_image_file_id=None)

    intro_lines = ["🤖 <b>DeepSeek AI</b>", "", f"⏳ {thinking_verb}..."]
    if current_page_key:
        intro_lines.append(f"<i>🖼 контекст: {escape_html(current_page_key)}</i>")
    if pending_image:
        intro_lines.append("<i>📸 + прикреплённое фото</i>")
    intro = "\n".join(intro_lines)

    thinking = await safe_edit_or_send(message, intro, force_new=True)

    progress = _make_progress(thinking)
    try:
        final, modified_files = await run_dialog(
            task_text,
            system_prompt=system_prompt,
            progress_callback=progress,
            current_page_key=current_page_key,
            pending_image_file_id=pending_image,
        )
        await safe_edit_or_send(
            thinking,
            f"🤖 <b>DeepSeek AI</b>\n\n{final}",
            reply_markup=deepseek_admin_chat_kb(),
        )
        if modified_files:
            await _auto_restart_if_needed(modified_files, thinking)
    except DeepSeekAgentError as e:
        await safe_edit_or_send(
            thinking,
            f"🤖 <b>DeepSeek AI</b>\n\n❌ Ошибка: {escape_html(str(e))}",
            reply_markup=deepseek_admin_chat_kb(),
        )


@router.message(AdminStates.deepseek_chat, F.text, ~F.text.startswith('/'))
async def handle_chat_message(message: Message, state: FSMContext):
    """Отправляет текстовое сообщение администратора DeepSeek AI."""
    if not _is_ai_admin(message.from_user.id):
        return

    if not DEEPSEEK_API_KEY:
        await safe_edit_or_send(
            message,
            "🤖 <b>DeepSeek AI Agent</b>\n\n"
            "❌ <b>DEEPSEEK_API_KEY не задан.</b>",
            reply_markup=deepseek_admin_no_key_kb(),
            force_new=True,
        )
        return

    text = (message.text or "").strip()
    if not text:
        return

    await _run_agent(message, state, text)


@router.message(AdminStates.deepseek_chat, F.photo)
async def handle_chat_photo(message: Message, state: FSMContext):
    """
    Обработка фото в /ai-диалоге.
    - С подписью (caption): подпись = задача, file_id передаётся в run_dialog.
    - Без подписи: сохраняем file_id в FSM и просим админа сказать что делать.
    """
    if not _is_ai_admin(message.from_user.id):
        return

    if not DEEPSEEK_API_KEY:
        return

    # Берём максимальное разрешение присланной фотографии
    if not message.photo:
        return
    file_id = message.photo[-1].file_id
    caption = (message.caption or "").strip()

    if caption:
        # Фото с подписью — обрабатываем как обычную задачу с file_id в контексте.
        # Сохраняем file_id в FSM, _run_agent его достанет и передаст в run_dialog.
        await state.update_data(pending_image_file_id=file_id)
        await _run_agent(message, state, caption)
    else:
        # Только фото — сохраняем и просим инструкцию.
        await state.update_data(pending_image_file_id=file_id)
        ctx = get_page_context(message.from_user.id)
        hint = ""
        if ctx:
            hint = (
                f"\n\n<i>Подсказка: ты сейчас на странице "
                f"'{escape_html(ctx.page_key)}'. Можно просто написать «поставь сюда».</i>"
            )
        await message.answer(
            "📸 <b>Фото получено.</b>\n\n"
            "Напиши, что с ним сделать, например:\n"
            "• «поставь сюда»\n"
            "• «поставь на главную»\n"
            "• «поставь на справку»\n"
            "• «замени картинку на пробной странице»"
            + hint,
        )
