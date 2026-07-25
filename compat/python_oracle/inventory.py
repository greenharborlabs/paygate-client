"""Generate reviewable Git-derived inventory evidence (never used as source truth)."""

from __future__ import annotations

import json
from pathlib import Path

from compat.python_oracle.replay import BASELINE_COMMIT, git_tree


def main() -> None:
    root = Path(__file__).resolve().parents[2]
    value = {"baseline_commit": BASELINE_COMMIT, "tree": git_tree(root)}
    print(json.dumps(value, sort_keys=True, indent=2) + "\n", end="")


if __name__ == "__main__":
    main()
