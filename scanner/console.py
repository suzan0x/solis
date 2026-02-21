# terminal output helpers — colors, banner, progress spinners
# kept simple on purpose, no external deps needed

import os
import ctypes

VERSION = "1.0.0"


class ConsoleUI:
    """Pretty-prints scan progress to the terminal with ANSI colors."""

    C = {
        'reset': '\033[0m', 'bold': '\033[1m',
        'cyan': '\033[96m', 'green': '\033[92m',
        'yellow': '\033[93m', 'red': '\033[91m',
        'blue': '\033[94m', 'dim': '\033[2m',
    }

    @staticmethod
    def enable_colors():
        """Turn on ANSI escape codes on Windows terminals."""
        if os.name == 'nt':
            os.system('color')
            try:
                k = ctypes.windll.kernel32
                k.SetConsoleMode(k.GetStdHandle(-11), 7)
            except Exception:
                pass

    @classmethod
    def banner(cls):
        c = cls.C
        print(f"""
{c['cyan']}{c['bold']}
    ███████╗ ██████╗ ██╗     ██╗███████╗
    ██╔════╝██╔═══██╗██║     ██║██╔════╝
    ███████╗██║   ██║██║     ██║███████╗
    ╚════██║██║   ██║██║     ██║╚════██║
    ███████║╚██████╔╝███████╗██║███████║
    ╚══════╝ ╚═════╝ ╚══════╝╚═╝╚══════╝
{c['reset']}
{c['dim']}    System Security Auditor v{VERSION}
    ─────────────────────────────────────{c['reset']}
        """)

    @classmethod
    def section(cls, title, icon=""):
        print(f"\n{cls.C['cyan']}{'━' * 50}\n  {icon}  {title}\n{'━' * 50}{cls.C['reset']}")

    @classmethod
    def ok(cls, msg):
        print(f"  {cls.C['green']}✓{cls.C['reset']} {msg}")

    @classmethod
    def warn(cls, msg):
        print(f"  {cls.C['yellow']}⚠{cls.C['reset']} {msg}")

    @classmethod
    def fail(cls, msg):
        print(f"  {cls.C['red']}✗{cls.C['reset']} {msg}")

    @classmethod
    def info(cls, msg):
        print(f"  {cls.C['blue']}ℹ{cls.C['reset']} {msg}")

    @classmethod
    def progress(cls, msg):
        print(f"  {cls.C['dim']}⟳ {msg}...{cls.C['reset']}", end='\r')

    @classmethod
    def done(cls, msg):
        print(f"  {cls.C['green']}✓{cls.C['reset']} {msg}          ")
