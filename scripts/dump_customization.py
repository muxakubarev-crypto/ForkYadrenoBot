#!/usr/bin/env python3
"""
Дамп кастомизации бота из таблицы pages в JSON.

БЕЗОПАСНОСТЬ:
Таблица `settings` содержит платёжные секреты (yookassa_secret_key, provider_token,
crypto_secret_key, platega_secret и пр.). По умолчанию settings НЕ выгружаются.

Что выгружается по умолчанию (безопасно для git):
- pages: все поля включая text_custom, image_custom, buttons_custom

Опционально:
- --include-settings        — выгружает settings с маскировкой (<REDACTED>)
- --include-settings-unsafe — выгружает settings БЕЗ маскировки; папка получает
                              суффикс -unsafe и автоматически попадает в .gitignore

Использование:
    python3 scripts/dump_customization.py
    python3 scripts/dump_customization.py --tag stable-2026-05-23
    python3 scripts/dump_customization.py --include-settings
    python3 scripts/dump_customization.py --include-settings-unsafe  # НЕ для git

Результат:
    snapshots/<YYYY-MM-DD>[-<tag>][-unsafe]/customization.json
    snapshots/<YYYY-MM-DD>[-<tag>][-unsafe]/meta.json
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


# Подстроки в имени ключа, которые указывают на секрет → маскируем при --include-settings.
_SECRET_NAME_PATTERNS: tuple[str, ...] = (
    "secret", "token", "api_key", "apikey",
    "password", "passwd", "private",
    "merchant_id", "shop_id", "provider_token",
)


def _is_secret_key(name: str) -> bool:
    lower = (name or "").lower()
    return any(p in lower for p in _SECRET_NAME_PATTERNS)


def dump_settings(
    conn: sqlite3.Connection,
    mask_secrets: bool = True,
) -> list[dict] | None:
    """
    Снимает таблицу settings, если она существует.

    При mask_secrets=True значения подозрительных ключей заменяются на "<REDACTED>".
    Даже после маскировки лучше не пушить settings в публичный git без необходимости.
    """
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='settings'"
    )
    if not cur.fetchone():
        return None
    cur = conn.execute("SELECT * FROM settings")
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, r)) for r in cur.fetchall()]

    if not mask_secrets:
        return rows

    masked = []
    for r in rows:
        key_field = r.get("key")
        if key_field and _is_secret_key(key_field):
            r = dict(r)
            if r.get("value"):
                r["value"] = "<REDACTED>"
        masked.append(r)
    return masked


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--tag",
        default="",
        help="Дополнительный суффикс к имени папки снапшота (например, 'stable-2026-05-23')",
    )
    p.add_argument(
        "--db",
        default=str(DB_PATH),
        help=f"Путь к файлу БД (по умолчанию: {DB_PATH})",
    )
    p.add_argument(
        "--include-settings",
        action="store_true",
        help="Выгрузить таблицу settings с маскировкой секретов (<REDACTED>)",
    )
    p.add_argument(
        "--include-settings-unsafe",
        action="store_true",
        help="Выгрузить settings БЕЗ маскировки. ОПАСНО — папка получит суффикс -unsafe и попадёт в .gitignore.",
    )
    args = p.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"ОШИБКА: БД не найдена по пути {db_path}", file=sys.stderr)
        return 1

    # Режим выгрузки settings: по умолчанию пропускаем.
    if args.include_settings_unsafe:
        settings_mode = "unsafe"
    elif args.include_settings:
        settings_mode = "masked"
    else:
        settings_mode = "skipped"

    today = datetime.now().strftime("%Y-%m-%d")
    folder_name = f"{today}-{args.tag}" if args.tag else today
    # Unsafe-снапшоты получают суффикс -unsafe — .gitignore их блокирует.
    if settings_mode == "unsafe":
        folder_name = f"{folder_name}-unsafe"
    out_dir = SNAPSHOTS_DIR / folder_name
    out_dir.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        pages = dump_pages(conn)
        if settings_mode == "skipped":
            settings = None
        else:
            settings = dump_settings(conn, mask_secrets=(settings_mode == "masked"))
    finally:
        conn.close()

    snapshot = {
        "schema_version": 1,
        "pages": pages,
        "settings": settings,
        "settings_mode": settings_mode,
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
        "settings_count": len(settings) if settings is not None else 0,
        "settings_mode": settings_mode,
        "safe_for_public_repo": settings_mode in ("skipped", "masked"),
        "tag": args.tag or None,
        "note": (
            "Содержит кастомизацию страниц. Не содержит пользователей, ключей, платежей."
            + {
                "skipped": " Таблица settings не выгружалась.",
                "masked": " settings выгружены с маскировкой секретов (<REDACTED>).",
                "unsafe": " ВНИМАНИЕ: settings выгружены БЕЗ маскировки. НЕ публикуй!",
            }[settings_mode]
        ),
    }
    (out_dir / "meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(f"OK Снапшот сохранён в: {out_dir}")
    print(f"   - страниц: {len(pages)}")
    if settings is not None:
        print(f"   - настроек: {len(settings)} (режим: {settings_mode})")
    else:
        print(f"   - настроек: пропущены (settings_mode=skipped)")
    print(f"   - размер БД: {meta['db_size_bytes'] / 1024:.1f} KB")
    print()
    if settings_mode == "unsafe":
        print("!!! ВНИМАНИЕ: settings выгружены БЕЗ маскировки !!!")
        print(f"!!! Папка ({out_dir}) попадает в .gitignore, в git НЕ закоммитится.")
    else:
        print("Безопасно публиковать. Закоммить и запушь:")
        print(f"   git add snapshots/{folder_name}/")
        print(f"   git commit -m 'snapshot: customization {folder_name}'")
        print(f"   git push")
    return 0


if __name__ == "__main__":
    sys.exit(main())
