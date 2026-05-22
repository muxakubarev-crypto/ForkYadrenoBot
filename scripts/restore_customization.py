#!/usr/bin/env python3
"""
Восстановление кастомизации бота из снапшота snapshots/<папка>/customization.json.

Записывает в БД ТОЛЬКО кастомные поля (text_custom, image_custom, buttons_custom)
и значения настроек. НЕ затрагивает пользователей, ключи, платежи. *_default
поля тоже не перезаписываются — они обновляются миграциями при старте бота.

Использование:
    python3 scripts/restore_customization.py snapshots/2026-05-22
    python3 scripts/restore_customization.py snapshots/2026-05-22 --dry-run
    python3 scripts/restore_customization.py snapshots/2026-05-22 --pages-only

Перед записью делает бэкап текущей БД рядом с ней:
    database/vpn_bot.db.bak-<timestamp>
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "vpn_bot.db"


def _to_json_or_none(value):
    """Сериализует объект в JSON-строку. None и пустые значения возвращает как None."""
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return None


def restore_pages(conn: sqlite3.Connection, pages: list[dict], dry_run: bool) -> int:
    """Восстанавливает кастомные поля страниц. Возвращает количество обновлённых строк."""
    updated = 0
    for p in pages:
        page_key = p.get("page_key")
        if not page_key:
            continue

        cur = conn.execute(
            "SELECT 1 FROM pages WHERE page_key = ?", (page_key,)
        )
        if not cur.fetchone():
            print(f"  пропуск: страницы '{page_key}' нет в БД (нужна миграция?)")
            continue

        text_custom = p.get("text_custom")
        image_custom = p.get("image_custom")
        buttons_custom = _to_json_or_none(p.get("buttons_custom"))

        if dry_run:
            print(
                f"  [dry-run] {page_key}: "
                f"text={'<custom>' if text_custom else '<none>'}, "
                f"image={'<custom>' if image_custom else '<none>'}, "
                f"buttons={'<' + str(len(p.get('buttons_custom') or [])) + ' btns>' if buttons_custom else '<none>'}"
            )
        else:
            conn.execute(
                "UPDATE pages SET text_custom = ?, image_custom = ?, "
                "buttons_custom = ?, updated_at = CURRENT_TIMESTAMP WHERE page_key = ?",
                (text_custom, image_custom, buttons_custom, page_key),
            )
            print(f"  обновлено: {page_key}")
        updated += 1
    return updated


def restore_settings(conn: sqlite3.Connection, settings: list[dict], dry_run: bool) -> int:
    """Восстанавливает таблицу settings, если она есть в БД и в снапшоте."""
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
    )
    if not cur.fetchone():
        print("  таблицы settings нет — пропуск")
        return 0

    # Получаем реальные колонки таблицы
    cur = conn.execute("PRAGMA table_info(settings)")
    db_cols = {row[1] for row in cur.fetchall()}

    updated = 0
    for s in settings:
        cols = [c for c in s.keys() if c in db_cols]
        if not cols:
            continue
        placeholders = ",".join("?" for _ in cols)
        col_list = ",".join(cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols)
        sql = (
            f"INSERT INTO settings({col_list}) VALUES({placeholders}) "
            f"ON CONFLICT DO UPDATE SET {updates}"
        )
        if dry_run:
            print(f"  [dry-run] settings: {s}")
        else:
            try:
                conn.execute(sql, tuple(s[c] for c in cols))
            except sqlite3.Error as e:
                print(f"  ошибка settings row {s}: {e}")
                continue
        updated += 1
    return updated


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("snapshot_dir", help="Путь к папке снапшота, например snapshots/2026-05-22")
    p.add_argument("--dry-run", action="store_true", help="Не писать в БД, только показать что будет сделано")
    p.add_argument("--pages-only", action="store_true", help="Восстановить только страницы, settings не трогать")
    p.add_argument("--db", default=str(DB_PATH), help=f"Путь к БД (по умолчанию: {DB_PATH})")
    p.add_argument("--no-backup", action="store_true", help="Не делать бэкап БД перед записью")
    args = p.parse_args()

    snap_dir = Path(args.snapshot_dir)
    if not snap_dir.is_dir():
        print(f"ОШИБКА: папка снапшота не найдена: {snap_dir}", file=sys.stderr)
        return 1

    customization_file = snap_dir / "customization.json"
    if not customization_file.is_file():
        print(f"ОШИБКА: не найден файл {customization_file}", file=sys.stderr)
        return 1

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"ОШИБКА: БД не найдена: {db_path}", file=sys.stderr)
        return 1

    snapshot = json.loads(customization_file.read_text(encoding="utf-8"))
    if snapshot.get("schema_version") != 1:
        print(
            f"ОШИБКА: неподдерживаемая schema_version: {snapshot.get('schema_version')!r}",
            file=sys.stderr,
        )
        return 1

    # Бэкап БД перед изменениями
    if not args.dry_run and not args.no_backup:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = db_path.with_suffix(db_path.suffix + f".bak-{ts}")
        shutil.copy2(db_path, backup_path)
        print(f"Бэкап текущей БД: {backup_path}")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        print(f"Восстанавливаю страницы из {customization_file}...")
        pages_updated = restore_pages(conn, snapshot.get("pages") or [], args.dry_run)

        settings_updated = 0
        if not args.pages_only and snapshot.get("settings"):
            print(f"Восстанавливаю настройки...")
            settings_updated = restore_settings(conn, snapshot["settings"], args.dry_run)

        if not args.dry_run:
            conn.commit()
    finally:
        conn.close()

    print()
    print(f"Готово. Страниц обновлено: {pages_updated}, настроек: {settings_updated}.")
    if args.dry_run:
        print("Это был dry-run, ничего не записано. Запусти без --dry-run чтобы применить.")
    else:
        print("Изменения видны мгновенно (страницы рендерятся из БД при каждом /start).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
