"""Command-line scans. No Postgres or Redis; scores come from veyrix.scoring."""

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any, TextIO

from pydantic import ValidationError

from veyrix import __version__
from veyrix.engine import ENGINE_VERSION
from veyrix.sarif import build_sarif
from veyrix.scan import (
    ADAPTERS,
    VARIANTS,
    ScanError,
    ScanTarget,
    TargetError,
    artifact_uri,
    default_name,
    execute_scan,
    normalize_policy,
    region_start_line,
)
from veyrix.scoring import SCORING_VERSION

SEVERITIES = ("info", "low", "medium", "high", "critical")
SUITES = (
    "all",
    "prompt-injection",
    "authorization-boundary",
    "unsafe-tool-execution",
    "data-exfiltration",
    "multi-step-manipulation",
    "mcp-security",
)
ALLOWED_KEYS = {"adapter", "variant", "server_variant", "suite", "name", "policy"}
# Endpoint and credential fields are environment-only, for every adapter.
FORBIDDEN_KEYS = {
    "api_key",
    "apikey",
    "api-key",
    "token",
    "access_token",
    "access-token",
    "secret",
    "password",
    "passwd",
    "base_url",
    "base-url",
    "model",
    "veyrix_llm_api_key",
    "veyrix-llm-api-key",
    "veyrix_llm_base_url",
    "veyrix-llm-base-url",
    "veyrix_llm_model",
    "veyrix-llm-model",
}
EXIT_OK = 0
EXIT_GATE = 1
EXIT_USAGE = 2
EXIT_SCAN = 3

EPILOG = """
exit codes:
  0  the scan finished and every requested gate passed
  1  the score is below --fail-under, or a verified finding meets --fail-on
  2  the arguments, config file, or llm environment is invalid
  3  a scenario failed to execute

--fail-under passes when the numeric score is greater than or equal to N.
A run with no numeric score fails --fail-under.
--fail-on matches that severity and every severity above it.
Without either gate, a finished scan exits 0 even when findings exist.
""".strip()


def console_main() -> None:
    """Setuptools entry point. The process status is the scan exit code."""
    sys.exit(main())


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        if code is None:
            return EXIT_OK
        return code if isinstance(code, int) else EXIT_USAGE
    try:
        return _scan(args)
    except TargetError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_USAGE
    except ScanError as exc:
        print(str(exc), file=sys.stderr)
        return EXIT_SCAN
    except Exception as exc:  # noqa: BLE001 - do not print a message that may contain a secret
        print(f"Scan failed ({type(exc).__name__}).", file=sys.stderr)
        return EXIT_SCAN


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="veyrix", description="Veyrix agent security scans.")
    parser.add_argument(
        "--version",
        action="version",
        version=f"veyrix {__version__} (engine {ENGINE_VERSION}, scoring {SCORING_VERSION})",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    scan = commands.add_parser(
        "scan",
        help="Run bundled scenarios in-process and print a score.",
        description=(
            "Run the bundled scenarios in-process against a local fixture, the bundled "
            "MCP server, or an OpenAI-compatible llm endpoint. The score is calculate_score "
            "on those results. Postgres and Redis are not used."
        ),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("--config", help="JSON or TOML target file. Flags override file values.")
    scan.add_argument("--adapter", choices=ADAPTERS, help="local, mcp, or llm.")
    scan.add_argument("--variant", choices=VARIANTS, help="vulnerable or hardened fixture.")
    scan.add_argument(
        "--server-variant",
        choices=VARIANTS,
        help="Bundled MCP server variant. Default: vulnerable.",
    )
    scan.add_argument("--suite", choices=SUITES, help="Scenario suite. Default: all.")
    scan.add_argument("--name", help="Display name stored in the report.")
    scan.add_argument(
        "--format",
        choices=("text", "json", "sarif"),
        help="Output format. Default: text, or inferred from --output.",
    )
    scan.add_argument("--output", help="Write the report to this path instead of stdout.")
    scan.add_argument(
        "--fail-under",
        type=_fail_under,
        help="Exit 1 when the score is missing or below this integer (0-100).",
    )
    scan.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        help="Exit 1 when a verified finding has this severity or higher.",
    )
    scan.add_argument(
        "--version",
        action="version",
        version=f"veyrix {__version__} (engine {ENGINE_VERSION}, scoring {SCORING_VERSION})",
    )
    return parser


def render_text(report: dict[str, Any]) -> str:
    score = report["score"]
    number = "none" if score["score"] is None else f"{score['score']}/100"
    counts = score["counts"]
    target = report["target"]
    configuration = report["configuration"]
    lines = [
        f"Veyrix engine {report['engine_version']}  scoring {report['scoring_version']}",
        f"Target  {target['name']}",
        (
            f"        adapter {configuration['adapter']}  variant {configuration['variant']}"
            f"  server {configuration['server_variant']}  suite {configuration['suite']}"
        ),
        "",
        f"Score   {number}  {score['label']}",
        (
            f"        coverage {score['coverage_percent']}%  "
            f"determinate {score['determinate_tests']}/{score['catalog_count']}"
        ),
    ]
    for reason in score["reasons"]:
        lines.append(f"        {reason}")
    verdict_counts = "  ".join(
        f"{status} {counts[status]}"
        for status in ("PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_TESTED")
    )
    lines.extend(["", f"Verdicts  {verdict_counts}", ""])
    for scenario in report["scenarios"]:
        verdict = scenario["verdict"]
        line = f"  {verdict['status']:<12}  {scenario['severity']:<8}  {scenario['id']}"
        if verdict["outcome"]:
            line += f"  {verdict['outcome']}"
        lines.append(line)
    lines.extend(["", f"Findings  {len(report['findings'])} verified"])
    for finding in report["findings"]:
        outcome = finding["outcome"] or "unconfirmed"
        lines.append(f"  {finding['severity']:<8}  {finding['scenario_id']}  {outcome}")
    if report["limitations"]:
        lines.extend(["", "Limitations"])
        lines.extend(f"  {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def gate_messages(
    report: dict[str, Any], fail_under: int | None, fail_on: str | None
) -> list[str]:
    messages: list[str] = []
    if fail_under is not None:
        score = report["score"]["score"]
        if score is None:
            messages.append(
                f"No numeric score; --fail-under {fail_under} requires an eligible assessment."
            )
        elif score < fail_under:
            messages.append(f"Score {score} is below --fail-under {fail_under}.")
    if fail_on is not None:
        minimum = SEVERITIES.index(fail_on)
        matched = [
            finding
            for finding in report["findings"]
            if SEVERITIES.index(finding["severity"]) >= minimum
        ]
        if matched:
            messages.append(
                f"{len(matched)} verified finding(s) at severity {fail_on} or higher."
            )
    return messages


def _scan(args: argparse.Namespace) -> int:
    target = _target_from_args(args)
    report = execute_scan(target)
    rendered = _render(report, _output_format(args))
    _write_report(rendered, args.output, report)
    messages = gate_messages(report, args.fail_under, args.fail_on)
    for message in messages:
        print(message, file=sys.stderr)
    return EXIT_GATE if messages else EXIT_OK


def _target_from_args(args: argparse.Namespace) -> ScanTarget:
    file_data = _load_config(args.config) if args.config else {}
    adapter = args.adapter or _optional_string(file_data, "adapter")
    variant = args.variant or _optional_string(file_data, "variant")
    server_variant = (
        args.server_variant or _optional_string(file_data, "server_variant") or "vulnerable"
    )
    suite = args.suite or _optional_string(file_data, "suite") or "all"
    if adapter is None or variant is None:
        raise TargetError("Set adapter and variant with --adapter/--variant or a config file.")
    if adapter not in ADAPTERS:
        raise TargetError("adapter must be local, mcp, or llm.")
    if variant not in VARIANTS or server_variant not in VARIANTS:
        raise TargetError("variant and server_variant must be vulnerable or hardened.")
    if suite not in SUITES:
        raise TargetError(f"suite must be one of: {', '.join(SUITES)}.")
    name = args.name or _optional_string(file_data, "name") or default_name(
        adapter, variant, server_variant
    )
    if len(name) > 120 or any(ord(char) < 32 for char in name):
        raise TargetError("name must be 1-120 characters without control characters.")
    policy = file_data.get("policy")
    if policy is None:
        parsed_policy = normalize_policy(None)
    else:
        if not isinstance(policy, dict):
            raise TargetError("policy must be an object.")
        try:
            parsed_policy = normalize_policy(policy)
        except ValidationError as exc:
            raise TargetError(_policy_error(exc)) from exc
    return ScanTarget(
        adapter=adapter,
        variant=variant,
        server_variant=server_variant,
        suite=suite,
        name=name,
        policy=parsed_policy,
        config_path=args.config,
        artifact_uri=artifact_uri(args.config),
        region_start_line=region_start_line(args.config, variant),
    )


def _load_config(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    if not path.is_file():
        raise TargetError(f"Config file not found: {path_text}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise TargetError(f"Could not read {path.name}.") from exc
    data = _parse_config(path, text)
    if not isinstance(data, dict):
        raise TargetError("Target config must be a JSON or TOML object.")
    forbidden = _forbidden_keys(data)
    if forbidden:
        names = ", ".join(forbidden)
        raise TargetError(
            f"Target config must not contain {names}. "
            "Set the model, base URL, and API key with VEYRIX_LLM_* environment variables."
        )
    unknown = sorted(set(data) - ALLOWED_KEYS)
    if unknown:
        raise TargetError(f"Unknown config field: {', '.join(unknown)}.")
    return data


def _parse_config(path: Path, text: str) -> Any:
    suffix = path.suffix.lower()
    try:
        if suffix == ".toml":
            return tomllib.loads(text)
        if suffix == ".json":
            return json.loads(text)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return tomllib.loads(text)
    except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
        detail = getattr(exc, "msg", None) or "invalid syntax"
        raise TargetError(f"Could not parse {path.name}: {detail}") from exc


def _forbidden_keys(value: Any) -> list[str]:
    found: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, item in node.items():
                if _is_forbidden(str(key)):
                    found.append(str(key))
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(value)
    return found


def _is_forbidden(key: str) -> bool:
    normalized = key.strip().lower().replace("_", "-")
    return normalized in {_normalize_key(item) for item in FORBIDDEN_KEYS}


def _normalize_key(key: str) -> str:
    return key.strip().lower().replace("_", "-")


def _optional_string(data: dict[str, Any], key: str) -> str | None:
    if key not in data or data[key] is None:
        return None
    value = data[key]
    if not isinstance(value, str) or not value.strip():
        raise TargetError(f"{key} must be a string.")
    return value.strip()


def _policy_error(exc: ValidationError) -> str:
    parts = []
    for error in exc.errors():
        location = ".".join(str(item) for item in error["loc"]) or "policy"
        parts.append(f"{location}: {error['msg']}")
    return "Invalid policy. " + "; ".join(parts)


def _output_format(args: argparse.Namespace) -> str:
    if args.format:
        return args.format
    if not args.output:
        return "text"
    name = Path(args.output).name.lower()
    if name.endswith((".sarif.json", ".sarif")):
        return "sarif"
    if name.endswith(".json"):
        return "json"
    return "text"


def _render(report: dict[str, Any], report_format: str) -> str:
    if report_format == "json":
        return json.dumps(report, indent=2) + "\n"
    if report_format == "sarif":
        return json.dumps(build_sarif(report), indent=2) + "\n"
    if report_format == "text":
        return render_text(report)
    raise TargetError("format must be text, json, or sarif.")


def _write_report(rendered: str, output: str | None, report: dict[str, Any]) -> None:
    if output is None:
        _emit(sys.stdout, rendered)
        return
    path = Path(output)
    if path.exists() and path.is_dir():
        raise TargetError(f"Output path is a directory: {output}")
    if path.parent != Path(".") and not path.parent.exists():
        raise TargetError(f"Output directory does not exist: {path.parent}")
    try:
        path.write_text(rendered, encoding="utf-8")
    except OSError as exc:
        raise TargetError(f"Could not write {path.name}.") from exc
    score = report["score"]["score"]
    shown = "none" if score is None else f"{score}/100"
    print(
        f"Veyrix score {shown}, {len(report['findings'])} verified findings. Wrote {output}",
        file=sys.stderr,
    )


def _emit(stream: TextIO, text: str) -> None:
    stream.write(text)
    if not text.endswith("\n"):
        stream.write("\n")
    # Flush before any stderr gate message so a pipe keeps report text ahead of the failure.
    stream.flush()


def _fail_under(value: str) -> int:
    if not value.isdigit():
        raise argparse.ArgumentTypeError("--fail-under must be an integer from 0 to 100")
    number = int(value)
    if number > 100:
        raise argparse.ArgumentTypeError("--fail-under must be an integer from 0 to 100")
    return number
