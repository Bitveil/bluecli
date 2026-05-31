"""Tiny presentation layer.

ANSI colors only — no curses, no Rich, no fancy frameworks. The CLI must
remain readable in every terminal, including Windows cmd.exe.

On Windows, ANSI escape sequences are off by default in cmd.exe; we flip
them on at import time via `kernel32.SetConsoleMode`. If that fails (very
old Windows, or stdout redirected to something exotic), colors auto-disable
so the user never sees raw `←[1m` garbage.
"""

from __future__ import annotations

import getpass
import os
import sys
import time

from . import art


def _enable_windows_vt() -> bool:
    """Turn on ANSI escape processing on Windows. No-op elsewhere."""
    if sys.platform != "win32":
        return True
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        STD_OUTPUT_HANDLE = -11
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(
            kernel32.SetConsoleMode(
                handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING
            )
        )
    except Exception:
        return False


# Auto-detect: TTY + ANSI actually supported. If either condition fails,
# every color helper degrades to plain text.
_TTY = sys.stdout.isatty() and _enable_windows_vt()


def _wrap(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _TTY else text


def bold(s: str) -> str:
    return _wrap("1", s)


def dim(s: str) -> str:
    return _wrap("2", s)


def red(s: str) -> str:
    return _wrap("31", s)


def green(s: str) -> str:
    return _wrap("32", s)


def yellow(s: str) -> str:
    return _wrap("33", s)


def cyan(s: str) -> str:
    return _wrap("36", s)


def blue(s: str) -> str:
    return _wrap("94", s)


def info(msg: str) -> None:
    print(msg)


def success(msg: str) -> None:
    print(green("✓ ") + msg)


def warn(msg: str) -> None:
    print(yellow("! ") + msg)


def error(msg: str) -> None:
    print(red("✗ ") + msg)


def clear() -> None:
    """Wipe the screen so each menu starts on a clean slate — the CLI shows
    only the current screen, never a scrollback of stale ones. No-op when
    stdout isn't a TTY (tests, pipes, redirected output), so we never spew
    escape codes or spawn a pointless subprocess where it makes no sense.
    """
    if not sys.stdout.isatty():
        return
    os.system("cls" if os.name == "nt" else "clear")


def banner() -> None:
    """The BlueCLI wordmark, drawn at the top of every screen so it stays
    'stuck' there (each screen clears, then redraws this first). On a real
    terminal it's the blue art; with output redirected (tests, pipes) it
    collapses to a single blank line, leaving non-interactive output exactly
    as it was before the banner existed."""
    if _TTY:
        for line in art.BANNER_LINES:
            print(blue(line))
    print()


def header(title: str) -> None:
    # Every screen begins with a header, so clearing here (and only here) is
    # what keeps the terminal showing just the current screen. The banner is
    # redrawn right after the wipe, which is what makes it look pinned to the
    # top across menus, the wallet setup/import flow and the unlock prompt.
    clear()
    banner()
    print(bold(cyan("== " + title + " ==")))


def prompt(label: str) -> str:
    try:
        return input(label).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def password(label: str) -> str:
    """Read a password without echoing it."""
    try:
        return getpass.getpass(label)
    except (EOFError, KeyboardInterrupt):
        print()
        return ""


def format_bytes(n: int) -> str:
    """Human-readable size: '0 B', '512 KB', '3.2 GB'. Binary units."""
    f = float(max(0, int(n)))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            if unit in ("B", "KB"):
                return f"{int(f)} {unit}"
            return f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"  # unreachable, keeps type-checkers happy


def format_duration(seconds: int) -> str:
    """Human-readable span: '45m', '3h', '1h 12m'."""
    seconds = max(0, int(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes = rem // 60
    if hours and minutes:
        return f"{hours}h {minutes}m"
    if hours:
        return f"{hours}h"
    return f"{minutes}m"


def yes_no(label: str, default_no: bool = True) -> bool:
    suffix = " [y/N] " if default_no else " [Y/n] "
    answer = prompt(label + suffix).lower()
    if not answer:
        return not default_no
    return answer.startswith("y")


def pause(label: str) -> None:
    try:
        input(label)
    except (EOFError, KeyboardInterrupt):
        print()


# Startup splash timing: tuned so the reveal lands around two seconds —
# long enough to register, short enough not to nag.
_INTRO_LINE_DELAY = 0.05
_INTRO_HOLD = 0.5


def intro() -> None:
    """One-time mascot reveal at launch: the 'bluefren' art prints line by
    line, top to bottom, as if cascading into place, then holds briefly so the
    finished picture registers before the first screen wipes it. TTY only —
    with output redirected it's a no-op (no escape codes, no sleeps), so tests
    and pipes are completely unaffected."""
    if not _TTY:
        return
    clear()
    print()
    for line in art.BLUEFREN_LINES:
        print(blue(line))
        time.sleep(_INTRO_LINE_DELAY)
    time.sleep(_INTRO_HOLD)
