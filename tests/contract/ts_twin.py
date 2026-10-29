"""Read the TypeScript twin's source, so a parity test restates nothing.

The Python seat words are compared with the sentences and constants in ``rine-core`` and
``rine-ts-sdk`` as written there; a clause added on one side only changes the entry and is seen.
"""

from __future__ import annotations

import re
from pathlib import Path

CORE_SRC = Path(__file__).parents[3] / "rine-core" / "src"
TS_SDK_SRC = Path(__file__).parents[3] / "rine-ts-sdk" / "src"


LITERAL = re.compile(r"""(["`])((?:\\.|(?!\1).)*)\1""", re.DOTALL)


def source(name: str) -> str:
    return (CORE_SRC / name).read_text(encoding="utf-8")


def literals(text: str) -> str:
    """The string literals of a TypeScript expression, concatenated as written."""
    return "".join(m[2] for m in LITERAL.finditer(text))


def function_body(text: str, name: str) -> str:
    start = text.index(f"function {name}(")
    return text[start : text.index("\n}\n", start)]


def constant(text: str, name: str) -> str:
    start = text.index(f"const {name} =")
    return text[start : text.index(";\n", start)]


def object_members(text: str, name: str) -> dict[str, str]:
    """``Key: "value"`` pairs of one ``export const Name = {...} as const`` block."""
    start = text.index(f"export const {name} = {{")
    block = text[start : text.index("} as const", start)]
    return dict(re.findall(r'(\w+):\s*"([a-z_]+)"', block))


def snake(pascal: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", pascal).upper()


def as_ts_template(template: str) -> str:
    return template.replace("{epoch}", "${epoch}").replace("{detail}", "${detail}")


def sentence_table(text: str, table: str, reasons: str) -> dict[str, str]:
    """One ``const TABLE: Record<...> = {...};`` block as ``{REASON_NAME: sentence}``.

    The sentence is the concatenated string literals of the entry, so a clause added
    only on the TypeScript side changes the entry and is seen.
    """
    start = text.index(f"const {table}:")
    block = text[start : text.index("\n};\n", start)]
    entries = re.split(rf"\[{reasons}\.(\w+)\]:", block)[1:]
    return {
        snake(key): literals(body) for key, body in zip(entries[::2], entries[1::2], strict=True)
    }
