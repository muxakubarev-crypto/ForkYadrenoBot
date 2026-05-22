#!/usr/bin/env python3
"""
Простой сканер staged-файлов на наличие секретов.

Использование (как pre-commit hook):
    1. Скопировать этот скрипт в .git/hooks/pre-commit
    2. chmod +x .git/hooks/pre-commit
    Тогда git commit будет отказывать, если в staged-файлах найдены секреты.

Использование (ручной запуск):
    python3 scripts/check_no_secrets.py                # проверить staged-файлы
    python3 scripts/check_no_secrets.py --all          # проверить весь рабочий tree
    python3 scripts/check_no_secrets.py --path file.py # проверить конкретный файл

Что ищется:
    - YooKassa live secret keys (live_xxxxx)
    - Telegram Payments provider tokens (XXXXX:LIVE:XXXXX)
    - Stripe live keys (sk_live_xxxxx)
    - GitHub Personal Access Tokens (ghp_xxxxx, gho_xxxxx, ghs_xxxxx)
    - Stripe webhook secrets (whsec_xxxxx)
    - AWS access keys (AKIA + 16 chars)
    - bearer-style API tokens длиннее 30 символов в плотном алфавите
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Паттерны секретов: (regex, человеческое имя)
SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\blive_[A-Za-z0-9_\-]{20,}\b"), "YooKassa LIVE secret"),
    (re.compile(r"\b\d{6,}:LIVE:[A-Za-z0-9_\-]{5,}\b"), "Telegram Payments LIVE provider token"),
    (re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"), "Stripe LIVE secret key"),
    (re.compile(r"\bsk_test_[A-Za-z0-9]{20,}\b"), "Stripe TEST secret key"),
    (re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b"), "Stripe webhook secret"),
    (re.compile(r"\b(ghp|gho|ghs|ghr|github_pat)_[A-Za-z0-9_]{30,}\b"), "GitHub Personal Access Token"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS Access Key ID"),
    (re.compile(r"\b[A-Za-z0-9]{40,}\b"), "Long opaque token (40+ chars) — проверь вручную"),
]

# Расширения файлов, которые сканируем
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".env", ".cfg", ".conf", ".md", ".txt", ".sh", ".sql",
}

# Имена/пути, которые игнорируем
IGNORE_PATHS = {
    ".git", "venv", ".venv", "node_modules", "__pycache__", "logs",
    "snapshots",  # снапшоты сами проверяют себя через dump-скрипт
    "scripts/check_no_secrets.py",  # сам файл со списком паттернов
}


def _is_ignored(path: Path) -> bool:
    parts = set(path.parts)
    for ig in IGNORE_PATHS:
        if ig in parts or str(path).replace("\\", "/").endswith(ig):
            return True
    return False


def _get_staged_files() -> list[Path]:
    """Получить список staged-файлов из git."""
    try:
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMRT"],
            capture_output=True, text=True, check=True, cwd=PROJECT_ROOT,
        )
        return [PROJECT_ROOT / line for line in result.stdout.splitlines() if line.strip()]
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []


def _get_all_files() -> list[Path]:
    """Получить все файлы проекта подходящих типов."""
    files = []
    for path in PROJECT_ROOT.rglob("*"):
        if path.is_file() and path.suffix.lower() in SCAN_EXTENSIONS:
            rel = path.relative_to(PROJECT_ROOT)
            if not _is_ignored(rel):
                files.append(path)
    return files


# Маркеры, гарантирующие что это пример/документация/алфавит, а не настоящий секрет.
_FAKE_MARKERS = (
    "abcdef",       # пример формата в документации, "123:LIVE:abcdef"
    "ABCDEF",
    "012345",
    "xxxxx",
    "XXXXX",
    "example",
    "your_token",
    "YOUR_TOKEN",
    "<your",
    "<insert",
)


def _has_sequential_ascii(s: str, threshold: int = 6) -> bool:
    """
    True если в строке есть N+ подряд идущих ASCII-символов (0123, abcd, ABCD).
    Это характерная сигнатура алфавитов/тестовых констант.
    """
    if len(s) < threshold:
        return False
    for i in range(len(s) - threshold + 1):
        chunk = s[i:i + threshold]
        if all(ord(chunk[j + 1]) == ord(chunk[j]) + 1 for j in range(threshold - 1)):
            return True
    return False


def _looks_fake(snippet: str) -> bool:
    """Эвристики «это не настоящий секрет»."""
    if any(m in snippet for m in _FAKE_MARKERS):
        return True
    if _has_sequential_ascii(snippet, threshold=6):
        return True
    return False


def scan_file(path: Path) -> list[tuple[int, str, str]]:
    """Возвращает [(line_no, secret_type, matched_string), ...]"""
    findings = []
    if not path.exists() or not path.is_file():
        return findings
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return findings

    for line_no, line in enumerate(content.splitlines(), start=1):
        for pattern, name in SECRET_PATTERNS:
            for match in pattern.finditer(line):
                snippet = match.group(0)
                # Снижаем шум для длинного opaque-токена: пропускаем
                # хеши коммитов (40 hex), алфавиты, явные плейсхолдеры.
                if name.startswith("Long opaque") and re.fullmatch(r"[0-9a-f]{40}", snippet):
                    continue
                if _looks_fake(snippet):
                    continue
                findings.append((line_no, name, snippet[:60]))
    return findings


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--all", action="store_true", help="Сканировать весь рабочий tree, не только staged")
    p.add_argument("--path", action="append", help="Сканировать только указанные файлы")
    args = p.parse_args()

    # На Windows консоль часто cp1251 — переключаем stdout на UTF-8.
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    except Exception:
        pass

    explicit_paths = bool(args.path)
    if args.path:
        files = [PROJECT_ROOT / Path(p) for p in args.path]
    elif args.all:
        files = _get_all_files()
    else:
        files = _get_staged_files()
        if not files:
            print("Нет staged-файлов. (Используй --all для полного сканирования.)")
            return 0

    # Отфильтруем по типам. При явном --path фильтр IGNORE_PATHS не применяется
    # (пользователь может намеренно проверить файл из snapshots/).
    if explicit_paths:
        files = [f for f in files if f.suffix.lower() in SCAN_EXTENSIONS]
    else:
        files = [
            f for f in files
            if f.suffix.lower() in SCAN_EXTENSIONS
            and not _is_ignored(f.relative_to(PROJECT_ROOT) if f.is_absolute() else f)
        ]

    total_findings = 0
    for f in files:
        rel = f.relative_to(PROJECT_ROOT) if f.is_absolute() else f
        results = scan_file(f)
        if results:
            print(f"\n[!] {rel}:")
            for line_no, name, snippet in results:
                print(f"    line {line_no}: {name}")
                print(f"        {snippet}")
            total_findings += len(results)

    if total_findings == 0:
        print(f"OK — секреты не найдены ({len(files)} файлов просканировано).")
        return 0
    else:
        print(f"\n!!! Найдено возможных секретов: {total_findings}")
        print("Если это false-positive — переделай шаблон в этом скрипте или удали лишнее.")
        print("Если настоящий секрет — РОТИРУЙ ключ и удали из коммита/файла перед push.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
