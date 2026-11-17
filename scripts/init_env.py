"""Create .env from .env.example with fresh random secrets. Never overwrites an existing .env."""

import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    env, example = ROOT / ".env", ROOT / ".env.example"
    if env.exists():
        print(".env already exists, leaving it alone")
        return 0
    lines = []
    for line in example.read_text(encoding="utf-8").splitlines():
        key, sep, value = line.partition("=")
        if sep and value.strip() == "change-me":
            line = f"{key}={secrets.token_urlsafe(32)}"
        lines.append(line)
    env.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("wrote .env with generated secrets (operator token is AEROSCAN_OPERATOR_TOKEN)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
