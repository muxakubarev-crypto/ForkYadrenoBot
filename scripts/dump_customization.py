#!/usr/bin/env python3
"""
Дамп кастомизации бота из таблицы pages (и settings, если есть) в JSON.

Сохраняет ТОЛЬКО админскую кастомизацию (text_custom, image_custom, buttons_custom
и значения настроек), НЕ трогая user-data (пользователи, ключи, платежи). Поэтому
результат БЕЗОПАСНО коммитить в публичный git-репозиторий.

Использование (на сервере или локально):
    python3 scripts/dump_customization.py
    python3 scripts/dump_customization.py --tag manual-2026-05-22

Результат:
    snapshots/<YYYY-MM-DD>[-<tag>]/customization.json
    snapshots/<YYYY-MM-DD>[-<tag>]/meta.json
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "vpn_bot.db"
SNAPSHOTS_DIR = PROJECT_ROOT / "snapshots"


def _parse_json_field(raw):
    """Парсит JSON-поле БД в Python-объект. На ошибке возвращает исходную строку."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        return raw
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return raw


def dump_pages(conn: sqlite3.Connection) -> list[dict]:
    """Снимает все страницы из таблицы pages."""
    cur = conn.execute(
        "SELECT page_key, text_default, image_default, buttons_default, "
        "text_custom, image_custom, buttons_custom, updated_at "
        "FROM pages ORDER BY page_key"
    )
    rows = []
    for r in cur.fetchall():
        rows.append({
            "page_key": r["page_key"],
            "text_default": r["text_default"],
            "image_default": r["image_default"],
            "buttons_default": _parse_json_field(r["buttons_default"]),
            "text_custom": r["text_custom"],
            "image_custom": r["image_custom"],
            "buttons_custom": _parse_json_field(r["buttons_custom"]),
            "updated_at": r["updated_at"],
        })
    return rows


def dump_settings(conn: sqlite3.Connection) -> list[dict] | None:
    """Снимает таблицу settings, если она существует."""
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
    )
    if not cur.fetchone():
        return None
    cur = conn.execute("SELECT * FROM settings")
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--tag",
        default="",
        help="Дополнительный суффикс к имени папки снапшота (например, 'before-ai-rework')",
    )
    p.add_argument(
        "--db",
        default=str(DB_PATH),
        help=f"Путь к файлу БД (по умолчанию: {DB_PATH})",
    )
    args = p.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"ОШИБКА: БД не найдена по пути {db_path}", file=sys.stderr)
        return 1

    today = datetime.now().strftime("%Y-%m-%d")
    folder_name = f"{today}-{args.tag}" if args.tag else today
    out_dir = SNAPSHOTS_DIR / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        pages = dump_pages(conn)
        settings = dump_settings(conn)
    finally:
        conn.close()

    snapshot = {
        "schema_version": 1,
        "pages": pages,
        "settings": settings,
    }

    customization_path = out_dir / "customization.json"
    customization_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    meta = {
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "db_path": str(db_path),
        "db_size_bytes": db_path.stat().st_size,
        "pages_count": len(pages),
        "settings_count": len(settings) if settings is not None else None,
        "tag": args.tag or None,
        "note": (
            "Содержит только кастомизацию страниц и настройки. "
            "Не содержит пользователей, ключей, платежей."
        ),
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"OK Снапшот сохранён в: {out_dir}")
    print(f"   - страниц: {len(pages)}")
    if settings is not None:
        print(f"   - настроек: {len(settings)}")
    print(f"   - размер БД: {meta['db_size_bytes'] / 1024:.1f} KB")
    print()
    print(f"Закоммить и запушь:")
    print(f"   git add snapshots/{folder_name}/")
    print(f"   git commit -m 'snapshot: customization {folder_name}'")
    print(f"   git push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
