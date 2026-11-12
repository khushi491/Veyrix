import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

// Best-effort. A missing interpreter or a failed install must not fail the
// Next.js build. The committed snapshot remains the fallback.
const enabled = process.env.VERCEL === "1" || process.env.VEYRIX_REFRESH_KIT_SCAN === "1";
if (!enabled) {
  console.log("Kit scan refresh skipped.");
  process.exit(0);
}

const webRoot = process.cwd();
const repoRoot = path.resolve(webRoot, "..", "..");
const output = path.join(webRoot, "demo", "kit-scan.generated.json");

function finish(message) {
  console.log(message);
  process.exit(0);
}

if (!fs.existsSync(path.join(repoRoot, "pyproject.toml"))) {
  finish(
    "Kit scan refresh skipped: the repository root is not available to this build.",
  );
}

const python = process.env.PYTHON || "python3";
const venv = path.join("/tmp", "veyrix-kit-venv");
const bin = path.join(venv, "bin");
const steps = [
  [python, ["-m", "venv", venv]],
  [path.join(bin, "pip"), ["install", "--disable-pip-version-check", repoRoot]],
  [
    path.join(bin, "python"),
    ["-m", "veyrix.kit_snapshot", "write", "--source", "build", "--output", output],
  ],
];

for (const [command, args] of steps) {
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    timeout: 180000,
    encoding: "utf8",
    env: { ...process.env, PIP_DISABLE_PIP_VERSION_CHECK: "1" },
  });
  if (result.error || result.status !== 0) {
    const detail = `${result.stderr || ""}${result.stdout || ""}${result.error?.message || ""}`;
    finish(`Kit scan refresh skipped.\n${detail.slice(-2000)}`);
  }
}

finish(`Kit scan refresh wrote ${output}`);
