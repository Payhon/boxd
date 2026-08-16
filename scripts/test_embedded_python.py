#!/usr/bin/env python3
"""Parse every quoted PY heredoc embedded in repository shell runners."""

from __future__ import annotations

import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PATTERN = re.compile(r"<<'PY'\n(.*?)\nPY(?:\n|$)", re.DOTALL)


def main() -> None:
    parsed = 0
    for path in sorted((ROOT / "scripts").rglob("*.sh")):
        for index, source in enumerate(PATTERN.findall(path.read_text(encoding="utf-8")), start=1):
            ast.parse(source, filename=f"{path}#PY-{index}")
            parsed += 1
    if parsed == 0:
        raise AssertionError("no embedded Python heredocs were discovered")
    print(f"embedded Python heredoc tests passed ({parsed} blocks)")


if __name__ == "__main__":
    main()
