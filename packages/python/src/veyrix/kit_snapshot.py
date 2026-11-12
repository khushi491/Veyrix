"""Bundle the two local fixture scans for the public red-team kit page.

Scores, findings, and traces come from ``execute_scan``. This module does not invent
them. The committed file is what the dashboard shows when the scheduled publication
is missing. The publish command only wraps reports the workflow already produced.
It does not push commits.
"""

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from veyrix.adapters import SYNTHETIC_SECRET
from veyrix.scan import ScanTarget, default_name, execute_scan, normalize_policy

REPO_ROOT = Path(__file__).resolve().parents[4]
SNAPSHOT_PATH = REPO_ROOT / "apps" / "web" / "demo" / "kit-scan.json"
REPOSITORY = "https://github.com/khushi491/Veyrix"
PUBLICATION_BRANCH = "kit-scans"
PUBLICATION_FILE = "latest.json"
PUBLICATION_URL = (
    "https://raw.githubusercontent.com/khushi491/Veyrix/kit-scans/latest.json"
)
WORKFLOW_URL = f"{REPOSITORY}/actions/workflows/veyrix-scan.yml"
CODE_SCANNING_URL = f"{REPOSITORY}/security/code-scanning"
ACTION_DOCS_URL = f"{REPOSITORY}/blob/main/docs/github-action.md"
SARIF_DOCS_URL = (
    "https://docs.github.com/en/code-security/code-scanning/"
    "integrating-with-code-scanning/sarif-support-for-code-scanning"
)
FORMAT_VERSION = 1
SOURCES = ("committed-snapshot", "build", "github-actions")
FIXTURE_NOTE = (
    "The vulnerable document assistant is a deliberately vulnerable local fixture. "
    "It is a sample target for the scanner. It is not a finding against the Veyrix "
    "product source, and it is not a production agent."
)


def iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def local_target(variant: str) -> ScanTarget:
    """Same flags the self-test passes to the composite action."""
    return ScanTarget(
        adapter="local",
        variant=variant,
        server_variant="vulnerable",
        suite="all",
        name=default_name("local", variant, "vulnerable"),
        policy=normalize_policy(None),
    )


def assemble_publication(
    vulnerable: dict[str, Any],
    hardened: dict[str, Any],
    *,
    source: str,
    published_at: datetime,
    run_url: str | None = None,
    run_id: str | None = None,
    sha: str | None = None,
    ref: str | None = None,
) -> dict[str, Any]:
    """Wrap two finished local reports. Rejects a bundle that leaks the synthetic secret."""
    if source not in SOURCES:
        raise ValueError("source must be committed-snapshot, build, or github-actions.")
    _require_report(vulnerable, "vulnerable")
    _require_report(hardened, "hardened")
    document = {
        "format_version": FORMAT_VERSION,
        "generator": "veyrix.kit_snapshot",
        "source": source,
        "published_at": iso(published_at),
        "run_url": run_url,
        "run_id": run_id,
        "sha": sha,
        "ref": ref,
        "repository": REPOSITORY,
        "workflow_url": WORKFLOW_URL,
        "code_scanning_url": CODE_SCANNING_URL,
        "sarif_docs_url": SARIF_DOCS_URL,
        "action_docs_url": ACTION_DOCS_URL,
        "publication_url": PUBLICATION_URL,
        "fixture_note": FIXTURE_NOTE,
        "scans": {"vulnerable": vulnerable, "hardened": hardened},
    }
    if SYNTHETIC_SECRET in json.dumps(document):
        raise ValueError("Refusing to write a kit scan that contains the synthetic secret.")
    return document


def publication_from_env(
    vulnerable: dict[str, Any],
    hardened: dict[str, Any],
    *,
    published_at: datetime | None = None,
) -> dict[str, Any]:
    """Metadata for a GitHub Actions run. A non-github.com host drops the run link."""
    repository = os.environ.get("GITHUB_REPOSITORY") or "khushi491/Veyrix"
    run_id = os.environ.get("GITHUB_RUN_ID") or None
    prefix = f"https://github.com/{repository}/actions/runs/"
    run_url = f"{prefix}{run_id}" if run_id else None
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    if run_url and not server.startswith("https://github.com"):
        run_url = None
    return assemble_publication(
        vulnerable,
        hardened,
        source="github-actions",
        published_at=published_at or datetime.now(UTC),
        run_url=run_url,
        run_id=run_id,
        sha=os.environ.get("GITHUB_SHA") or None,
        ref=os.environ.get("GITHUB_REF") or None,
    )


def build_bundle(source: str, published_at: datetime | None = None) -> dict[str, Any]:
    """Run both local fixtures in-process and wrap the reports."""
    vulnerable = execute_scan(local_target("vulnerable"))
    hardened = execute_scan(local_target("hardened"))
    return assemble_publication(
        vulnerable,
        hardened,
        source=source,
        published_at=published_at or datetime.now(UTC),
    )


def write_bundle(source: str, output: Path, published_at: datetime | None = None) -> Path:
    if source == "build" and output.resolve() == SNAPSHOT_PATH.resolve():
        raise ValueError("A build bundle cannot replace the committed snapshot.")
    document = build_bundle(source, published_at)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    return output


def load_report(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Could not read scan report {path.name}.") from exc
    if not isinstance(data, dict):
        raise TypeError(f"{path.name} is not a scan report object.")
    return data


def find_report(root: Path, filename: str) -> Path:
    matches = sorted(path for path in root.rglob(filename) if path.is_file())
    if len(matches) != 1:
        raise ValueError(f"Expected one {filename} under {root}, found {len(matches)}.")
    return matches[0]


def _require_report(report: dict[str, Any], variant: str) -> None:
    if not isinstance(report, dict):
        raise TypeError(f"The {variant} scan is not an object.")
    target = report.get("target")
    if not isinstance(target, dict) or target.get("variant") != variant:
        raise ValueError(f"The {variant} scan is not the {variant} local fixture.")
    if target.get("adapter") != "local":
        raise ValueError(f"The {variant} kit scan must use the local adapter.")
    score = report.get("score")
    if not isinstance(score, dict) or not isinstance(score.get("score"), int):
        raise TypeError(f"The {variant} scan has no integer score.")
    if not 0 <= score["score"] <= 100:
        raise ValueError(f"The {variant} score is outside 0-100.")
    for key in ("engine_version", "scoring_version", "generated_at"):
        if not isinstance(report.get(key), str) or not report[key]:
            raise ValueError(f"The {variant} scan is missing {key}.")
    findings = report.get("findings")
    results = report.get("results")
    if not isinstance(findings, list) or not isinstance(results, list):
        raise TypeError(f"The {variant} scan is missing findings or results.")
    if not results:
        raise ValueError(f"The {variant} scan recorded no scenarios.")
    for result in results:
        _require_trace(result, variant)


def _require_trace(result: Any, variant: str) -> None:
    if not isinstance(result, dict):
        raise TypeError(f"The {variant} scan has a result that is not an object.")
    events = result.get("events")
    scenario_id = result.get("scenario_id")
    if not isinstance(events, list) or not events:
        raise ValueError(f"{variant} scenario {scenario_id} has no evidence trace.")
    sequences = [event.get("sequence") if isinstance(event, dict) else None for event in events]
    if sequences != list(range(1, len(events) + 1)):
        raise ValueError(f"{variant} scenario {scenario_id} trace is not ordered.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m veyrix.kit_snapshot",
        description="Build the public red-team kit scan bundle.",
    )
    sub = parser.add_subparsers(dest="command")
    write = sub.add_parser("write", help="Run both local fixtures and write a bundle.")
    write.add_argument("--source", choices=SOURCES, default="committed-snapshot")
    write.add_argument("--output", type=Path)
    publish = sub.add_parser(
        "publish",
        help="Wrap two finished scan reports. Does not run the engine or push git.",
    )
    publish.add_argument("--artifacts", type=Path)
    publish.add_argument("--vulnerable", type=Path)
    publish.add_argument("--hardened", type=Path)
    publish.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "publish":
            vulnerable_path, hardened_path = _publish_paths(args)
            document = publication_from_env(
                load_report(vulnerable_path),
                load_report(hardened_path),
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
            print(f"Wrote {args.output}")
            return 0
        source = "committed-snapshot" if args.command is None else args.source
        output = SNAPSHOT_PATH if args.command is None or args.output is None else args.output
        written = write_bundle(source, output)
    except (ValueError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Wrote {written}")
    return 0


def _publish_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    if args.vulnerable or args.hardened:
        if not args.vulnerable or not args.hardened:
            raise ValueError("Pass both --vulnerable and --hardened.")
        return args.vulnerable, args.hardened
    if args.artifacts is None:
        raise ValueError("Pass --artifacts or both report paths.")
    return (
        find_report(args.artifacts, "vulnerable.json"),
        find_report(args.artifacts, "hardened.json"),
    )


if __name__ == "__main__":
    sys.exit(main())
