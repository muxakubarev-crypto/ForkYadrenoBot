# AGENTS.md — Контекст проекта ForkYadrenoBot (DeepSeek AI Agent)

> **ПРОЧИТАЙ ЭТОТ ФАЙЛ ПЕРВЫМ. Здесь полная история, архитектура, где застряли и что делать.**

---

## 1. ИСХОДНАЯ ЗАДАЧА

Заменить интеграцию с платным/закрытым ИИ-сервером `admin.yadreno.ru` на локального ИИ-агента DeepSeek (AsyncOpenAI, Function Calling). Администратор должен иметь возможность через команду `/ai` в Telegram управлять ботом: добавлять кнопки, менять текст, проверять сервер и т.д.

---

## 2. АРХИТЕКТУРА ПРОЕКТА (КРИТИЧНО ДЛЯ ПОНИМАНИЯ)

### 2.1 Как рендерится главное меню пользователя

**Главное меню пользователя (экран `/start`) рендерится НЕ из кода, а из БАЗЫ ДАННЫХ SQLite!**

```
/start → cmd_start() [bot/handlers/user/start.py:115]
  → _render_main_page() [start.py:62]
    → render_page(target, page_key='main') [bot/utils/page_renderer.py:299]
      → get_page_data('main') [page_renderer.py:26]
        → get_page('main') [database/db_pages.py:24]
          → SELECT * FROM pages WHERE page_key = 'main'
        → _merge_buttons_by_id(buttons_default, buttons_custom)
```

**Таблица `pages`:**
- `page_key = 'main'` — главный экран пользователя
- `buttons_default` — дефолтные кнопки (задаются в `database/migrations.py`, строка 354–368)
- `buttons_custom` — кастомные кнопки админа (NULL = не заданы, приоритет над default)
- `text_default` / `text_custom` — текст страницы
- Функция `update_page_custom('main', buttons=...)` в [`database/db_pages.py:43`](database/db_pages.py) обновляет `buttons_custom`

**ВАЖНО:** Функция `main_menu_kb()` в [`bot/keyboards/user.py:10`](bot/keyboards/user.py) — это УСТАРЕВШИЙ КОД, который **НЕ ИСПОЛЬЗУЕТСЯ** для рендеринга главного экрана. Главный экран рендерится через `render_page(target, page_key='main')`. Редактирование `user.py` НЕ МЕНЯЕТ главное меню пользователя.

### 2.2 Дефолтные кнопки главного меню (БД)

В [`database/migrations.py:354-368`](database/migrations.py) в словаре `page_defaults['main']['buttons']` хранится JSON-список:

```python
{"id": "btn_my_keys",  "label": "🔑 Мои ключи",         "row": 0, "col": 0, "action_type": "internal", "action_value": "cmd_my_keys"},
{"id": "btn_buy_key",  "label": "💳 Купить ключ",        "row": 0, "col": 1, "action_type": "internal", "action_value": "cmd_buy"},
{"id": "btn_trial",    "label": "🎁 Пробная подписка",   "row": 1, "col": 0, "is_hidden": True, ...},
{"id": "btn_referral", "label": "🔗 Реферальная ссылка",  "row": 2, "col": 0, "is_hidden": True, ...},
{"id": "btn_help",     "label": "❓ Справка",             "row": 2, "col": 1, ...},
```

**Типы action_type:** `internal` (callback), `url` (внешняя ссылка), `system` (динамическая логика)

### 2.3 Как применить изменения кнопок

Есть два пути:

**Путь А (рекомендуемый): Прямая запись в БД**
Вызвать `update_page_custom('main', buttons=<JSON-строка>)` — изменения применяются мгновенно, без перезапуска бота. Кнопки попадают в `buttons_custom` и имеют приоритет над `buttons_default`.

**Путь Б: Редактирование `database/migrations.py`**
Изменить `page_defaults['main']['buttons']` в коде. Изменения применятся только после перезапуска бота (функция `run_migrations()` в `main.py:59` вызывает `upsert_page_defaults`).

### 2.4 ИИ-агент (DeepSeek)

Файл: [`bot/services/deepseek_agent.py`](bot/services/deepseek_agent.py) (~816 строк)

**Доступные инструменты (5):**
| Инструмент | Назначение |
|---|---|
| `read_file_content` | Чтение файлов проекта |
| `patch_file_content` | Точечная замена фрагмента в файле (не требует перезаписи всего файла) |
| `modify_file_content` | Полная перезапись файла (только для новых файлов) |
| `restart_bot_process` | systemctl restart yadreno-vpn (fire-and-forget) |
| `execute_server_command` | Диагностика сервера (allowlist + deny-list) |

---

## 3. ЧТО УЖЕ СДЕЛАНО ✅

### 3.1 Замена интеграции
- ✅ Удалён старый HTTP-клиент `yadreno_admin.py` к `admin.yadreno.ru`
- ✅ Создан `deepseek_agent.py` с нуля: AsyncOpenAI, 5 инструментов Function Calling
- ✅ Обработчик `/ai` с firewall (строго `ADMIN_TELEGRAM_ID`)
- ✅ Классификатор code vs diagnostic, фильтрация tools
- ✅ Progress callback (real-time шаги в Telegram)
- ✅ Авто-перезапуск после изменений (fire-and-forget)

### 3.2 Безопасность
- ✅ Path sandbox: все пути внутри `PROJECT_ROOT`
- ✅ Shell allowlist: 42 безопасных префикса
- ✅ Shell deny-list: 6 опасных паттернов (rm -rf, mkfs, dd of=/dev/, fork bomb, chmod -R /, curl|bash)
- ✅ Timeout: 15 сек для команд, 30 сек для перезапуска
- ✅ Firewall: строгое int-сравнение с `ADMIN_TELEGRAM_ID`

### 3.3 `patch_file_content` (РЕШЁННАЯ проблема №1)
- ✅ Создан инструмент точечной замены фрагментов кода
- ✅ Нормализация `\r\n` → `\n` (кроссплатформенность)
- ✅ Проверка уникальности фрагмента (0 вхождений = ошибка, >1 = ошибка с номерами строк)
- ✅ Интегрирован в `run_dialog()`: прогресс, отслеживание успеха, forced patch после 2 раундов чтения
- ✅ Системные промпты обновлены

### 3.4 Что работает хорошо
- Диагностика сервера: `/ai покажи состояние сервера` — free, df, uptime, ps (~3-5 сек)
- Логи: `/ai что с логами` — journalctl
- Диски и сеть: `/ai проверь диски и сеты` — df, lsblk, ip addr, ss
- Firewall: посторонние отсекаются мгновенно

---

## 4. ГДЕ МЫ ЗАСТРЯЛИ ❌ — ТЕКУЩАЯ ПРОБЛЕМА

### 4.1 Симптом

Команда `/ai добавь кнопки Политика конфиденциальности и Пользовательское соглашение в главное меню` **не добавляет кнопки на экран**, хотя:
- `patch_file_content` успешно срабатывает
- Бот сообщает «✅ Файл изменён»
- Бот перезапускается

### 4.2 Хронология проблемы

| Этап | Что происходило | Результат |
|---|---|---|
| **Фаза 1** | Модель вызывала `modify_file_content` для перезаписи 1000+ строк файла | ❌ Зависание, max_tool_rounds exceeded |
| **Фаза 2** | Создан `patch_file_content` — точечная правка | ✅ patch работает, файл меняется |
| **Фаза 3** | Модель патчила `bot/keyboards/user.py` | ❌ Кнопки не появляются на экране |
| **Фаза 4** | Промпт обновлён на `database/migrations.py` | ❌ Модель теряется в большом файле (908 строк), 4 раунда без modify |

### 4.3 КОРНЕВАЯ ПРИЧИНА

**Модель редактирует НЕ ТО, что рендерится на экране!**

- Модель обучена редактировать Python-файлы (`user.py`, `migrations.py`)
- Но главное меню рендерится из **БАЗЫ ДАННЫХ** (`pages` таблица, `buttons_custom` поле)
- Даже если модель отредактирует `migrations.py` → нужно ПЕРЕЗАПУСТИТЬ бота → миграции обновят `buttons_default` → только тогда кнопки появятся
- Модель не имеет инструмента для **прямой записи в БД**

### 4.4 Почему не работает даже с migrations.py

Файл `migrations.py` содержит 908 строк сложного кода (JSON-вставки, SQL, условия). Модель DeepSeek теряется в нём и не может найти нужный фрагмент для патча (early abort после 4 раундов).

---

## 5. ПЛАН РЕШЕНИЯ

### 5.1 Главная цель

**Сделать так, чтобы `/ai добавь кнопки X и Y в главное меню` работало мгновенно и без перезапуска.**

### 5.2 Решение: новый инструмент `update_page_buttons`

Добавить в ИИ-агента **6-й инструмент** `update_page_buttons`, который напрямую пишет кнопки в БД через `update_page_custom()`.

```json
{
  "name": "update_page_buttons",
  "parameters": {
    "page_key": "main",
    "buttons": [
      {"id": "btn_privacy", "label": "📜 Политика конфиденциальности", "row": 0, "col": 0, "action_type": "url", "action_value": "https://..."},
      {"id": "btn_terms", "label": "📋 Пользовательское соглашение", "row": 0, "col": 1, "action_type": "url", "action_value": "https://..."}
    ]
  }
}
```

**Преимущества:**
- Не требует редактирования файлов
- Не требует перезапуска бота
- Изменения видны мгновенно (рендерер читает `buttons_custom` из БД)
- Модель работает с чистыми данными (JSON), а не с кодом

### 5.3 Что нужно реализовать

**Задача 1: Новый инструмент `update_page_buttons` в `deepseek_agent.py`**
1. Добавить определение tool в `TOOLS`
2. Создать функцию `_update_page_buttons(page_key, buttons)` — вызывает `update_page_custom(page_key, buttons=json.dumps(buttons))`
3. Обновить `_execute_tool_call()` — обработка нового tool
4. Обновить `run_dialog()` — прогресс-коллбэк, отслеживание успеха
5. Обновить классификатор — `update_page_buttons` доступен в code-режиме

**Задача 2: Обновить системные промпты**
- `SYSTEM_PROMPT_EXEC`: явно указать, что кнопки главного меню добавляются через `update_page_buttons`
- `SYSTEM_PROMPT_DIALOG`: то же самое
- Убрать из промптов упоминания `bot/keyboards/user.py` и `main_menu_kb()` для главного меню
- Оставить `user.py` только для других пользовательских клавиатур

**Задача 3: Обновить `SYSTEM_PROMPT_EXEC` — пример для модели**
Добавить конкретный пример:
```
Чтобы добавить кнопки в главное меню:
1. НЕ читай файлы.
2. Вызови update_page_buttons с page_key='main' и buttons=[...]
3. Кнопки типа url должны иметь action_type='url' и action_value со ссылкой.
4. Новые кнопки размещай на row=0 (перед существующими), существующие сдвинь на row=1,2...
```

### 5.4 Полный алгоритм для модели (code-режим)

```
ЗАДАЧА: «добавь кнопки X и Y в главное меню»

Шаг 1: read_file_content('database/migrations.py', max_lines=30)
       → Найди начало page_defaults['main']['buttons'] (строка ~362)
       → Скопируй ВСЕ существующие кнопки
       
Шаг 2: update_page_buttons('main', [...новые_кнопки..., ...существующие_кнопки...])
       → Новые кнопки на row=0
       → Существующие сдвинуты на row=1,2,3...
       → Готово! Кнопки видны мгновенно.
```

---

## 6. ФАЙЛЫ ДЛЯ ИЗМЕНЕНИЯ

| Файл | Что меняем |
|---|---|
| **`bot/services/deepseek_agent.py`** | Добавить tool `update_page_buttons`, функцию `_update_page_buttons()`, обновить `_execute_tool_call()`, `run_dialog()`, классификатор, промпты |
| **`database/db_pages.py`** | Уже содержит `update_page_custom()` — используется без изменений |

**НЕ ТРОГАТЬ (работает):**
- `restart_bot_process` (fire-and-forget)
- `execute_server_command` (allowlist/deny-list)
- `_resolve_tool_path` (path sandbox)
- `_is_ai_admin` (firewall)
- `ProgressCallback`
- `_auto_restart_if_needed`

---

## 7. ПЕРЕМЕННЫЕ ОКРУЖЕНИЯ (.env)

```env
BOT_TOKEN=токен_бота_telegram
ADMIN_IDS=465403010
DEEPSEEK_API_KEY=sk-...
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-v4-pro
ADMIN_TELEGRAM_ID=465403010
DEEPSEEK_PROXY=                # опционально
```

**КРИТИЧНО:** `DEEPSEEK_BASE_URL` должен быть `https://api.deepseek.com` (БЕЗ `/v1` — OpenAI SDK добавляет сам).

---

## 8. КОМАНДЫ ДЕПЛОЯ

```bash
# На сервере (SSH):
cd /root/YadrenoVPN
git fetch origin && git reset --hard origin/main
source venv/bin/activate
pip install -r requirements.txt   # только если новые зависимости
systemctl restart yadreno-vpn.service

# Проверка логов:
journalctl -u yadreno-vpn.service --no-pager --since "1 minute ago" | grep -i "deepseek_agent\|tool_call\|ошибка\|error"
tail -50 /root/YadrenoVPN/logs/bot.log | grep -i "deepseek\|tool_call"
```

---

## 9. КЛЮЧЕВЫЕ ФУНКЦИИ

| Функция | Файл:строка | Назначение |
|---|---|---|
| `render_page(target, 'main')` | `bot/utils/page_renderer.py:299` | Рендерит главный экран пользователя из БД |
| `get_page_data('main')` | `bot/utils/page_renderer.py:26` | Читает страницу из БД, мержит default+custom кнопки |
| `update_page_custom()` | `database/db_pages.py:43` | Пишет кастомные данные страницы в БД |
| `page_defaults['main']['buttons']` | `database/migrations.py:354-368` | Дефолтные кнопки главного меню (JSON) |
| `_render_main_page()` | `bot/handlers/user/start.py:62` | Точка входа для рендеринга главной |
| `run_dialog()` | `bot/services/deepseek_agent.py` | Основной цикл ИИ-агента |
| `SYSTEM_PROMPT_EXEC` | `bot/services/deepseek_agent.py:173` | Промпт для `/ai задача` |
| `SYSTEM_PROMPT_DIALOG` | `bot/services/deepseek_agent.py:214` | Промпт для FSM-чата |
| `main_menu_kb()` | `bot/keyboards/user.py:10` | **УСТАРЕВШАЯ! НЕ используется для главного экрана!** |

---

## 10. СТРУКТУРА ПРОЕКТА

```
ForkYadrenoBot/
├── .gitignore
├── config.py.example             # ВСЕ настройки + парсер .env
├── requirements.txt              # openai, httpx[socks], aiogram...
├── main.py                       # Точка входа (миграции + бот)
├── bot/
│   ├── handlers/
│   │   ├── admin/
│   │   │   ├── deepseek_admin.py # /ai обработчик (firewall + FSM + progress + restart)
│   │   │   └── main.py           # admin_main_menu_kb
│   │   └── user/
│   │       └── start.py          # /start → _render_main_page → render_page('main')
│   ├── keyboards/
│   │   ├── admin_misc.py         # admin_main_menu_kb (админ-панель)
│   │   └── user.py               # main_menu_kb() — УСТАРЕВШАЯ, НЕ ИСПОЛЬЗУЕТСЯ для главной
│   ├── services/
│   │   └── deepseek_agent.py     # ЯДРО: AsyncOpenAI + 5 tools + run_dialog
│   └── utils/
│       └── page_renderer.py      # Рендер страниц из БД (таблица pages)
├── database/
│   ├── db_pages.py               # get_page(), update_page_custom()
│   └── migrations.py             # page_defaults (дефолтные тексты и кнопки)
└── logs/
    └── bot.log
```

---

## 11. ИНСТРУКЦИЯ ДЛЯ НОВОГО АГЕНТА

> Если ты новый AI-агент и читаешь этот файл — вот что нужно сделать:

### Шаг 0: Пойми архитектуру
- **Раздел 2** — пойми, что главное меню рендерится из БД, а не из `user.py`
- **Раздел 4** — пойми, где мы застряли и почему

### Шаг 1: Реализуй `update_page_buttons`
В файле `bot/services/deepseek_agent.py`:

1. **Добавь tool в `TOOLS`:**
```python
{
    "type": "function",
    "function": {
        "name": "update_page_buttons",
        "description": "Обновляет кнопки страницы в базе данных. Изменения видны мгновенно, без перезапуска бота. Используй для добавления/изменения кнопок в главном меню.",
        "parameters": {
            "type": "object",
            "properties": {
                "page_key": {"type": "string", "description": "Ключ страницы: 'main' для главного меню"},
                "buttons": {"type": "array", "description": "ПОЛНЫЙ список кнопок страницы в формате [{id, label, row, col, action_type, action_value, ...}]"}
            },
            "required": ["page_key", "buttons"]
        }
    }
}
```

2. **Создай функцию `_update_page_buttons(page_key, buttons)`:**
```python
async def _update_page_buttons(page_key: str, buttons: list) -> str:
    import json
    from database.db_pages import update_page_custom
    try:
        buttons_json = json.dumps(buttons, ensure_ascii=False)
        await asyncio.to_thread(update_page_custom, page_key, buttons=buttons_json)
        return f"Кнопки страницы '{page_key}' обновлены ({len(buttons)} кнопок). Изменения уже видны."
    except Exception as e:
        return f"ОШИБКА update_page_buttons: {e}"
```

3. **Обнови `_execute_tool_call()`** — добавь elif для `update_page_buttons`

4. **Обнови `run_dialog()`** — прогресс-коллбэк "🎛️ Обновляю кнопки...", отслеживание как успешного действия

5. **Обнови классификатор** — `update_page_buttons` доступен в code-режиме

### Шаг 2: Обнови системные промпты

В `SYSTEM_PROMPT_EXEC`:
- Укажи, что для добавления кнопок в главное меню используется `update_page_buttons('main', [...])`
- НЕ нужно читать файлы или редактировать `user.py`
- Дай пример формата кнопок

В `SYSTEM_PROMPT_DIALOG`:
- Добавь `update_page_buttons` в список инструментов
- Укажи правила использования

### Шаг 3: Проверь
- Запусти `python -c "import ast; ast.parse(open('bot/services/deepseek_agent.py').read()); print('OK')"` — синтаксис
- Убедись, что `update_page_buttons` не фильтруется классификатором для code-задач
- Все остальные инструменты продолжают работать

### Шаг 4: Запушь и протестируй
```bash
cd ForkYadrenoBot
git add bot/services/deepseek_agent.py
git commit -m "feat: add update_page_buttons tool for direct DB writes"
git push origin main
```

---

## 12. JUMPSTART PROMPT ДЛЯ НОВОГО ЧАТА

```
Ты — Python-разработчик. Мы работаем над форком YadrenoVPN-бота.

ПРОЧИТАЙ ПЕРВЫМ ДЕЛОМ файл ForkYadrenoBot/AGENTS.md — там полная история проекта,
архитектура (главное меню рендерится из БД!), что сделано, где застряли и что нужно чинить.

Коротко: мы заменили интеграцию с платным ИИ-сервером на локальный DeepSeek-агент
(AsyncOpenAI, Function Calling). Диагностика сервера работает отлично.
Уже реализован инструмент patch_file_content для точечной правки файлов.

НО команда "/ai добавь кнопки в главное меню" не работает — модель редактирует
файлы (user.py, migrations.py), но главное меню рендерится из БАЗЫ ДАННЫХ SQLite
(таблица pages, функция render_page в page_renderer.py).

Нужно реализовать новый инструмент update_page_buttons для прямой записи
кнопок в БД через update_page_custom() и починить кодинг.

Все детали в AGENTS.md. Начинай с чтения этого файла.
```
