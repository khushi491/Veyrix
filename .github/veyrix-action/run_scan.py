"""Composite-action entry point. Install is a separate step; this runs the scan."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
TRUE_VALUES = {"true", "1", "yes"}
FALSE_VALUES = {"false", "0", "no", ""}
UPLOAD_SKIPPED = {
    "fork": "SARIF upload skipped: pull requests from forks cannot write code scanning results.",
    "dependabot": (
        "SARIF upload skipped: Dependabot pull requests cannot write code scanning results."
    ),
    "disabled": "SARIF upload is off.",
    "no-sarif": "SARIF upload skipped: the scan did not write a SARIF file.",
}


class UsageError(ValueError):
    """The action inputs are invalid. The message is safe to print."""


class ReportError(RuntimeError):
    """The scan finished but the report could not be turned into SARIF or a summary."""


def main(argv: list[str] | None = None, env: Mapping[str, str] | None = None) -> int:
    """Run a scan, or record the later SARIF upload step. Returns the process status."""
    args = list(sys.argv[1:] if argv is None else argv)
    current = os.environ if env is None else env
    if args[:1] == ["record-upload"]:
        return record_upload(current)
    if args:
        print("Usage: run_scan.py [record-upload]", file=sys.stderr)
        return 2
    try:
        return run_scan(current)
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        _write_failure_summary(current, str(exc))
        _emit_scan_outputs(current, ready=False, upload=False)
        return 2


def run_scan(env: Mapping[str, str]) -> int:
    requested = _parse_bool(env.get("VEYRIX_UPLOAD_SARIF", ""), "upload-sarif")
    json_path = _json_output_path(env)
    sarif_path = sarif_path_for(json_path)
    if sarif_path.resolve() == json_path.resolve():
        raise UsageError("The JSON output path and the SARIF path are the same.")
    try:
        from veyrix import __version__ as package_version
        from veyrix.cli import gate_messages
        from veyrix.sarif import build_sarif
        from veyrix.scan import ScanError
    except ImportError:
        print("Veyrix is not installed for this Python.", file=sys.stderr)
        _write_failure_summary(env, "Veyrix is not installed for this Python.")
        _emit_scan_outputs(env, ready=False, upload=False)
        return 3

    json_path.parent.mkdir(parents=True, exist_ok=True)
    command = scan_command(env, json_path)
    print("+", " ".join(command[1:]), flush=True)
    completed = subprocess.run(
        command,
        cwd=_workspace(env),
        env=_subprocess_env(env),
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.stderr:
        sys.stderr.write(completed.stderr)
        if not completed.stderr.endswith("\n"):
            sys.stderr.write("\n")
    if completed.returncode not in (0, 1):
        if completed.stdout.strip():
            print(completed.stdout, file=sys.stderr, end="")
        detail = completed.stderr.strip() or f"veyrix scan exited {completed.returncode}."
        _write_failure_summary(env, detail)
        _emit_scan_outputs(env, ready=False, upload=False)
        return completed.returncode if completed.returncode in (2, 3) else 3

    try:
        report = json.loads(json_path.read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise ReportError("The JSON report is not an object.")
        sarif_path.write_text(
            json.dumps(build_sarif(report), indent=2) + "\n",
            encoding="utf-8",
        )
        fail_under = _parsed_fail_under(env.get("VEYRIX_FAIL_UNDER", ""))
        fail_on = env.get("VEYRIX_FAIL_ON", "").strip() or None
        messages = gate_messages(report, fail_under, fail_on)
        reason = upload_block_reason(env, requested=requested, sarif_ready=True)
        summary = render_summary(
            report,
            messages=messages,
            fail_under=fail_under,
            fail_on=fail_on,
            package_version=package_version,
            json_display=_display_path(json_path, env),
            sarif_display=_display_path(sarif_path, env),
            upload_note=_upload_note(reason),
        )
    except (OSError, json.JSONDecodeError, ReportError, ScanError, KeyError, TypeError) as exc:
        print(f"Could not prepare the scan report ({type(exc).__name__}).", file=sys.stderr)
        _write_failure_summary(env, "Could not prepare the scan report.")
        _emit_scan_outputs(env, ready=False, upload=False)
        return 3

    _append(env.get("GITHUB_STEP_SUMMARY"), summary)
    score = report["score"]["score"]
    _emit_scan_outputs(
        env,
        ready=True,
        upload=reason is None,
        score="" if score is None else str(score),
        findings=str(len(report["findings"])),
        sarif_path=_display_path(sarif_path, env),
        json_path=_display_path(json_path, env),
        engine=str(report["engine_version"]),
    )
    if reason in {"fork", "dependabot"}:
        print(f"::notice title=Veyrix::{UPLOAD_SKIPPED[reason]}")
    return completed.returncode


def record_upload(env: Mapping[str, str]) -> int:
    """Append the upload result and set sarif-uploaded. Does not fail the scan again."""
    outcome = env.get("UPLOAD_OUTCOME", "").strip()
    planned = env.get("UPLOAD_PLANNED", "").strip().lower() == "true"
    uploaded = outcome == "success"
    _emit_outputs(env, {"sarif-uploaded": "true" if uploaded else "false"})
    if uploaded:
        note = "SARIF upload to code scanning succeeded."
        sarif_id = env.get("SARIF_ID", "").strip()
        if _safe_token(sarif_id):
            print(f"Code scanning SARIF id: {sarif_id}")
    elif outcome == "failure":
        note = "SARIF upload to code scanning failed."
    elif planned:
        note = "SARIF upload did not run."
    else:
        note = ""
    if note:
        print(note)
        _append(env.get("GITHUB_STEP_SUMMARY"), "\n" + note + "\n")
    return 0


def scan_command(env: Mapping[str, str], output: Path) -> list[str]:
    """Argv for `python -m veyrix scan`. Flags are omitted when the input is empty."""
    command = [
        sys.executable,
        "-m",
        "veyrix",
        "scan",
        "--format",
        "json",
        "--output",
        str(output),
    ]
    flags = (
        ("VEYRIX_CONFIG", "--config"),
        ("VEYRIX_ADAPTER", "--adapter"),
        ("VEYRIX_VARIANT", "--variant"),
        ("VEYRIX_SERVER_VARIANT", "--server-variant"),
        ("VEYRIX_SUITE", "--suite"),
        ("VEYRIX_NAME", "--name"),
        ("VEYRIX_FAIL_UNDER", "--fail-under"),
        ("VEYRIX_FAIL_ON", "--fail-on"),
    )
    for key, flag in flags:
        value = env.get(key, "").strip()
        if value:
            command.extend([flag, value])
    return command


def sarif_path_for(json_path: Path) -> Path:
    name = json_path.name
    for suffix in (".sarif.json", ".json"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return json_path.with_name(f"{name}.sarif")


def upload_block_reason(
    env: Mapping[str, str], *, requested: bool, sarif_ready: bool
) -> str | None:
    """None means the upload step should run. Any other value is a skip reason."""
    if not requested:
        return "disabled"
    if not sarif_ready:
        return "no-sarif"
    if env.get("GITHUB_ACTOR") == "dependabot[bot]":
        return "dependabot"
    if env.get("GITHUB_EVENT_NAME") == "pull_request" and _pull_request_cannot_upload(env):
        return "fork"
    return None


def render_summary(
    report: dict[str, Any],
    *,
    messages: list[str],
    fail_under: int | None,
    fail_on: str | None,
    package_version: str,
    json_display: str,
    sarif_display: str,
    upload_note: str,
) -> str:
    score = report["score"]
    counts = score["counts"]
    target = report["target"]
    configuration = report["configuration"]
    findings = list(report["findings"])
    number = "none" if score["score"] is None else f"{score['score']}/100"
    verdicts = " · ".join(
        f"{status} {counts[status]}"
        for status in ("PASS", "FAIL", "INCONCLUSIVE", "ERROR", "NOT_TESTED")
    )
    lines = [
        "## Veyrix scan",
        "",
        _lead(findings, messages, fail_under, fail_on),
        "",
        "| | |",
        "| --- | --- |",
        f"| Score | **{number}** |",
        f"| Label | {_cell(score['label'])} |",
        f"| Verified findings | {len(findings)} |",
        f"| Engine | {_cell(report['engine_version'])} |",
        f"| Scoring | {_cell(report['scoring_version'])} |",
        f"| Package | {_cell(package_version)} |",
        f"| Target | {_cell(target['name'])} |",
        f"| Adapter | {_cell(configuration['adapter'])} |",
        f"| Variant | {_cell(configuration['variant'])} |",
        f"| Server variant | {_cell(configuration['server_variant'])} |",
        f"| Suite | {_cell(configuration['suite'])} |",
        (
            f"| Coverage | {_cell(score['coverage_percent'])}% "
            f"({_cell(score['determinate_tests'])}/{_cell(score['catalog_count'])} determinate) |"
        ),
        f"| Verdicts | {_cell(verdicts)} |",
        "",
        "### Findings",
        "",
    ]
    lines.extend(_findings_table(findings))
    lines.extend(["", "### Scenarios", ""])
    lines.extend(_scenario_table(list(report["scenarios"])))
    limitations = report.get("limitations") or []
    if limitations:
        lines.extend(["", "### Limits", ""])
        lines.extend(f"- {_cell(item)}" for item in limitations)
    lines.extend(
        [
            "",
            f"JSON report: `{json_display}`",
            "",
            f"SARIF file: `{sarif_display}`",
            "",
            upload_note,
            "",
        ]
    )
    return "\n".join(lines)


def _lead(
    findings: list[dict[str, Any]],
    messages: list[str],
    fail_under: int | None,
    fail_on: str | None,
) -> str:
    if messages:
        bullets = "\n".join(f"- {_cell(message)}" for message in messages)
        return "The scan finished and a gate failed.\n\n" + bullets
    if fail_under is None and fail_on is None:
        if findings:
            return (
                "The scan finished. No fail-under or fail-on gate was set, "
                f"so {len(findings)} verified findings do not fail this job."
            )
        return "The scan finished with no verified findings. No gate was set."
    return "The scan finished and every requested gate passed."


def _findings_table(findings: list[dict[str, Any]]) -> list[str]:
    if not findings:
        return ["No verified findings."]
    ordered = sorted(findings, key=_finding_key)
    rows = [
        "| Severity | Outcome | Scenario | Category | Title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for finding in ordered:
        rows.append(
            "| {severity} | {outcome} | {scenario} | {category} | {title} |".format(
                severity=_cell(finding.get("severity")),
                outcome=_cell(finding.get("outcome")),
                scenario=_cell(finding.get("scenario_id")),
                category=_cell(finding.get("category")),
                title=_cell(finding.get("title")),
            )
        )
    return rows


def _scenario_table(scenarios: list[dict[str, Any]]) -> list[str]:
    if not scenarios:
        return ["No scenarios were selected."]
    rows = [
        "| Status | Severity | Scenario | Outcome |",
        "| --- | --- | --- | --- |",
    ]
    for scenario in scenarios:
        verdict = scenario.get("verdict") or {}
        rows.append(
            "| {status} | {severity} | {scenario} | {outcome} |".format(
                status=_cell(verdict.get("status")),
                severity=_cell(scenario.get("severity")),
                scenario=_cell(scenario.get("id")),
                outcome=_cell(verdict.get("outcome")),
            )
        )
    return rows


def _finding_key(finding: dict[str, Any]) -> tuple[int, str]:
    severity = str(finding.get("severity", ""))
    return (SEVERITY_RANK.get(severity, 99), str(finding.get("scenario_id", "")))


def _cell(value: object) -> str:
    if value is None:
        return "-"
    text = str(value).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", " ")
    text = text.strip()
    if len(text) > 180:
        text = text[:177] + "..."
    return text or "-"


def _upload_note(reason: str | None) -> str:
    if reason is None:
        return "SARIF upload to code scanning was requested."
    return UPLOAD_SKIPPED[reason]


def _parse_bool(value: str, label: str) -> bool:
    text = value.strip().lower()
    if text in FALSE_VALUES:
        return False
    if text in TRUE_VALUES:
        return True
    raise UsageError(f"{label} must be true or false.")


def _parsed_fail_under(value: str) -> int | None:
    text = value.strip()
    if not text or not text.isdigit() or int(text) > 100:
        return None
    return int(text)


def _json_output_path(env: Mapping[str, str]) -> Path:
    raw = env.get("VEYRIX_OUTPUT", "").strip() or "veyrix-results.json"
    path = Path(raw)
    if path.exists() and path.is_dir():
        raise UsageError(f"Output path is a directory: {raw}")
    return path


def _workspace(env: Mapping[str, str]) -> str | None:
    workspace = env.get("GITHUB_WORKSPACE", "").strip()
    if workspace and Path(workspace).is_dir():
        return workspace
    return None


def _display_path(path: Path, env: Mapping[str, str]) -> str:
    workspace = _workspace(env)
    if workspace is not None:
        try:
            return path.resolve().relative_to(Path(workspace).resolve()).as_posix()
        except ValueError:
            pass
    return path.as_posix()


def _subprocess_env(env: Mapping[str, str]) -> dict[str, str]:
    merged = dict(os.environ)
    merged.update(env)
    return merged


def _pull_request_cannot_upload(env: Mapping[str, str]) -> bool:
    """True when this pull request must not receive a code-scanning write."""
    path = env.get("GITHUB_EVENT_PATH", "").strip()
    if not path:
        return True
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return True
    pull_request = payload.get("pull_request") if isinstance(payload, dict) else None
    head = pull_request.get("head") if isinstance(pull_request, dict) else None
    repo = head.get("repo") if isinstance(head, dict) else None
    if not isinstance(repo, dict):
        return True
    if repo.get("fork") is True:
        return True
    full_name = repo.get("full_name")
    expected = env.get("GITHUB_REPOSITORY", "").strip()
    if isinstance(full_name, str) and expected and full_name != expected:
        return True
    return repo.get("fork") is not False


def _safe_token(value: str) -> bool:
    return bool(value) and len(value) <= 80 and all(char.isalnum() or char in "-_" for char in value)


def _write_failure_summary(env: Mapping[str, str], detail: str) -> None:
    quoted = "\n".join(f"> {_cell(line)}" for line in detail.splitlines()) or "> Scan failed."
    text = f"## Veyrix scan\n\nThe scan did not finish.\n\n{quoted}\n"
    _append(env.get("GITHUB_STEP_SUMMARY"), text)


def _emit_scan_outputs(
    env: Mapping[str, str],
    *,
    ready: bool,
    upload: bool,
    score: str = "",
    findings: str = "",
    sarif_path: str = "",
    json_path: str = "",
    engine: str = "",
) -> None:
    _emit_outputs(
        env,
        {
            "score": score,
            "findings-count": findings,
            "sarif-path": sarif_path,
            "json-path": json_path,
            "engine-version": engine,
            "sarif-ready": "true" if ready else "false",
            "upload": "true" if upload else "false",
        },
    )


def _emit_outputs(env: Mapping[str, str], values: dict[str, str]) -> None:
    for key, value in values.items():
        if "\n" in value or "\r" in value:
            raise UsageError(f"Output {key} cannot contain a newline.")
    payload = "".join(f"{key}={value}\n" for key, value in values.items())
    destination = env.get("GITHUB_OUTPUT")
    if destination:
        with open(destination, "a", encoding="utf-8") as handle:
            handle.write(payload)
    else:
        print(payload, end="")


def _append(path: str | None, text: str) -> None:
    if not text.endswith("\n"):
        text += "\n"
    if not path:
        print(text, end="")
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(text)


if __name__ == "__main__":
    sys.exit(main())
