"""Compare a veyrix scan JSON report with the action outputs. Used by CI."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    report_path = Path(os.environ["JSON"])
    report = json.loads(report_path.read_text(encoding="utf-8"))
    score = report["score"]["score"]
    findings = len(report["findings"])
    engine = report["engine_version"]
    print(f"report score={score} findings={findings} engine={engine}")
    if str(score) != os.environ["SCORE"] or str(findings) != os.environ["FINDINGS"]:
        print("Action outputs do not match the JSON report", file=sys.stderr)
        return 1
    if engine != os.environ["ENGINE"] or not engine:
        print("Action engine output does not match the JSON report", file=sys.stderr)
        return 1
    if str(score) != os.environ["EXPECT_SCORE"] or str(findings) != os.environ["EXPECT_FINDINGS"]:
        print(
            f"Expected score {os.environ['EXPECT_SCORE']} and "
            f"{os.environ['EXPECT_FINDINGS']} findings",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
