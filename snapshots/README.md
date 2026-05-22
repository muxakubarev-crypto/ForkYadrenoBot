# Snapshots — точки отката кастомизации бота

Эта папка хранит **снимки настроек бота** (тексты страниц, кнопки, картинки, значения настроек) в JSON-формате. Не содержит пользовательских данных — её можно безопасно держать в публичном git-репо.

## Что внутри

Каждая подпапка `YYYY-MM-DD[-tag]/` это один снапшот:

| Файл | Описание |
|---|---|
| `customization.json` | Снимок таблиц `pages` и `settings` |
| `meta.json` | Метаданные: дата, размер БД, счётчики |

**Что снапшот НЕ содержит:** пользователи, ключи, платежи, статистика, рефералы. Эти данные остаются только в БД на сервере и в локальных файловых бэкапах `vpn_bot.db`.

## Создать новый снапшот

На сервере (или локально, если у тебя есть копия `vpn_bot.db`):

```bash
cd /root/YadrenoVPN          # или путь к проекту
source venv/bin/activate     # если нужно
python3 scripts/dump_customization.py --tag before-ai-rework
```

После выполнения:

```bash
git add snapshots/2026-05-22-before-ai-rework/
git commit -m "snapshot: customization before AI rework"
git push origin main
```

## Восстановить из снапшота

```bash
# Сначала проверь, что именно изменится (без записи в БД):
python3 scripts/restore_customization.py snapshots/2026-05-22 --dry-run

# Если всё ок — применяй:
python3 scripts/restore_customization.py snapshots/2026-05-22
```

Скрипт **автоматически делает бэкап текущей БД** в `database/vpn_bot.db.bak-<timestamp>` перед записью.

Восстанавливаются только `text_custom`, `image_custom`, `buttons_custom` в `pages` и значения в `settings`. Пользователи и платежи **не трогаются**.

Изменения видны мгновенно — рестарт бота не нужен (страницы рендерятся из БД при каждом /start).

## Опции скриптов

```bash
# Дамп с кастомным тегом
python3 scripts/dump_customization.py --tag manual-test

# Восстановление без бэкапа (рискованно!)
python3 scripts/restore_customization.py snapshots/X --no-backup

# Восстановить только страницы, settings оставить как есть
python3 scripts/restore_customization.py snapshots/X --pages-only
```

## Полный бэкап БД

Если нужен **полный** бэкап (с пользователями) — просто скопируй `database/vpn_bot.db` на свой компьютер через scp. Этот файл НЕ нужно класть в публичный git.

```bash
# С компьютера:
scp root@hostoff:/root/YadrenoVPN/database/vpn_bot.db ./local-backups/vpn_bot.db.2026-05-22
```
