"""Клавиатуры раздела DeepSeek AI Agent."""
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from aiogram.utils.keyboard import InlineKeyboardBuilder

from .admin_misc import back_button, home_button


def deepseek_admin_no_key_kb() -> InlineKeyboardMarkup:
    """Клавиатура экрана, когда DEEPSEEK_API_KEY не задан."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text='ℹ️ Как получить ключ',
            url='https://platform.deepseek.com/api_keys',
        )
    )
    builder.row(back_button('admin_panel'), home_button())
    return builder.as_markup()


def deepseek_admin_chat_kb() -> InlineKeyboardMarkup:
    """Клавиатура режима диалога с DeepSeek AI."""
    builder = InlineKeyboardBuilder()
    builder.row(
        InlineKeyboardButton(
            text='🌐 DeepSeek Platform',
            url='https://platform.deepseek.com',
        )
    )
    builder.row(back_button('admin_panel'), home_button())
    return builder.as_markup()
