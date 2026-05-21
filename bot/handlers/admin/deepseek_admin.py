"""
Диалог с ИИ-агентом DeepSeek AI и команда /ai.

Жёсткий firewall: доступ только для ADMIN_TELEGRAM_ID (строгое int-сравнение).
Посторонние пользователи мгновенно отсекаются без объяснения причин (RCE-защита).
"""
from __future__ import annotations

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
    run_dialog,
)
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
        return  # Мгновенный возврат без ответа — посторонний не узнает о существовании команды

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
        # Сразу выполняем задачу
        thinking = await safe_edit_or_send(
            message,
            "🤖 <b>DeepSeek AI</b>\n\n⏳ Думаю...",
            force_new=True,
        )
        try:
            final = await run_dialog(task)
            await safe_edit_or_send(
                thinking,
                f"🤖 <b>DeepSeek AI</b>\n\n{final}",
                reply_markup=deepseek_admin_chat_kb(),
            )
        except DeepSeekAgentError as e:
            await safe_edit_or_send(
                thinking,
                f"🤖 <b>DeepSeek AI</b>\n\n❌ Ошибка: {escape_html(str(e))}",
                reply_markup=deepseek_admin_chat_kb(),
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
@router.message(AdminStates.deepseek_chat, F.text, ~F.text.startswith('/'))
async def handle_chat_message(message: Message):
    """Отправляет сообщение администратора DeepSeek AI и показывает ответ."""
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

    text = message.text.strip() if message.text else ""
    if not text:
        return

    thinking = await safe_edit_or_send(
        message,
        "🤖 <b>DeepSeek AI</b>\n\n⏳ Думаю...",
        force_new=True,
    )

    try:
        final = await run_dialog(text)
        # Экранируем HTML-спецсимволы в ответе модели, кроме тех случаев
        # когда модель явно использует HTML-теги (доверяем модели)
        await safe_edit_or_send(
            thinking,
            f"🤖 <b>DeepSeek AI</b>\n\n{final}",
            reply_markup=deepseek_admin_chat_kb(),
        )
    except DeepSeekAgentError as e:
        await safe_edit_or_send(
            thinking,
            f"🤖 <b>DeepSeek AI</b>\n\n❌ Ошибка: {escape_html(str(e))}",
            reply_markup=deepseek_admin_chat_kb(),
        )
