#!/usr/bin/env python3
"""
rebrand.py — تغییر نام/برند پروژه با یک دستور.

مثال:
    python3 rebrand.py --name "Aurora"
    python3 rebrand.py --name "Aurora" --tagline "SYSTEM CONSOLE" --dry-run

هر جا برند فعلی (Vega) در فایل‌های متنی پروژه باشد با نام جدید عوض می‌شود،
با حفظ حالت حروف (UPPER / Title / lower / camelCase).
"""

import argparse
import os
import sys

CURRENT = "Vega"          # برند فعلی
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
TEXT_EXT = {
    ".py", ".html", ".htm", ".md", ".txt", ".json", ".yml", ".yaml",
    ".toml", ".cfg", ".ini", ".css", ".js", ".sh", ".env", ".example",
    ".dockerfile", "",
}


BOLD_BASE = 0x1D5D4  # MATHEMATICAL SANS-SERIF BOLD CAPITAL A


def to_bold(text: str) -> str:
    """تبدیل حروف لاتین به فرم بولد یونیکد (𝗔𝗕𝗖)."""
    out = []
    for ch in text.upper():
        if "A" <= ch <= "Z":
            out.append(chr(BOLD_BASE + ord(ch) - ord("A")))
        else:
            out.append(ch)
    return "".join(out)


def build_rules(old: str, new: str):
    """قواعد جایگزینی از خاص‌ترین به عام‌ترین.

    نکته: بعضی پروژه‌ها برند را با حروف یونیکد بولد می‌نویسند (مثل 𝗣𝗔𝗕𝗟𝗢)
    که با جستجوی متنی معمولی پیدا نمی‌شود؛ آن فرم هم پوشش داده شده است.
    """
    o_lo, o_up, o_ti = old.lower(), old.upper(), old.capitalize()
    n_lo, n_up, n_ti = new.lower(), new.upper(), new.capitalize()
    return [
        (to_bold(o_up + " PANEL"), to_bold(n_up)),
        (to_bold(o_up + "PANEL"), to_bold(n_up + "PANEL")),
        (to_bold(o_up), to_bold(n_up)),
        (o_up + "PANEL", n_up + "PANEL"),
        (o_ti + "Panel", n_ti + "Panel"),
        (o_lo + "Panel", n_lo + "Panel"),
        (o_up + " PANEL", n_up + " PANEL"),
        (o_ti + " Panel", n_ti + " Panel"),
        (o_up, n_up),
        (o_ti, n_ti),
        (o_lo, n_lo),
    ]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True, help="نام جدید پروژه، مثلا Aurora")
    ap.add_argument("--tagline", default=None, help="متن زیر لوگو در صفحه ورود")
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--dry-run", action="store_true", help="فقط گزارش، بدون نوشتن")
    args = ap.parse_args()

    new = args.name.strip()
    if not new or not new.replace("-", "").replace("_", "").isalnum():
        sys.exit("نام باید فقط حرف/عدد باشد.")

    rules = build_rules(CURRENT, new)
    total_files = total_hits = 0

    for dirpath, dirnames, filenames in os.walk(args.root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            path = os.path.join(dirpath, fn)
            ext = os.path.splitext(fn)[1].lower()
            if ext not in TEXT_EXT:
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    src = f.read()
            except (UnicodeDecodeError, OSError):
                continue

            out, hits = src, 0
            for a, b in rules:
                c = out.count(a)
                if c:
                    out = out.replace(a, b)
                    hits += c

            if args.tagline and "SYSTEM CONTROL CONSOLE" in out:
                out = out.replace("SYSTEM CONTROL CONSOLE", args.tagline.upper())
                hits += 1

            if hits:
                total_files += 1
                total_hits += hits
                rel = os.path.relpath(path, args.root)
                print(f"  {rel}: {hits}")
                if not args.dry_run:
                    with open(path, "w", encoding="utf-8") as f:
                        f.write(out)

    verb = "می‌شد" if args.dry_run else "شد"
    print(f"\n{total_hits} جایگزینی در {total_files} فایل {verb} → «{new}»")


if __name__ == "__main__":
    main()
