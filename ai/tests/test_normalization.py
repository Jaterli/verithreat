"""Comprueba loaders.normalize_value con los casos compartidos de db/normalization_cases.json.

Uso:  python ai/tests/test_normalization.py      (o con pytest)
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ai" / "src"))
from loaders import normalize_value  # noqa: E402

CASES = json.loads((ROOT / "db" / "normalization_cases.json").read_text(encoding="utf-8"))["cases"]


def _check(case) -> str:
    try:
        got = normalize_value(case["type"], case["input"])
    except ValueError:
        got = None
    return "" if got == case["expected"] else f"{case['type']} {case['input']!r}: expected {case['expected']!r}, got {got!r}"


def test_normalization_cases():
    failures = [f for f in map(_check, CASES) if f]
    assert not failures, "\n".join(failures)


if __name__ == "__main__":
    failures = [f for f in map(_check, CASES) if f]
    print("\n".join(failures) if failures else f"OK: {len(CASES)} cases")
    sys.exit(1 if failures else 0)
