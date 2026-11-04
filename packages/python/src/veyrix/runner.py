"""Bounded subprocess entry point. Only bundled scenarios may be executed."""

import json
import sys

from veyrix.engine import SCENARIOS, run_scenario


def main() -> None:
    # Limits are applied inside the child, never via preexec_fn in a threaded worker.
    import resource

    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if sys.platform == "linux":
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    payload = json.loads(sys.stdin.read(128 * 1024))
    scenario = next(s for s in SCENARIOS if s.id == payload["scenario_id"])
    print(json.dumps(run_scenario(payload["variant"], payload["policy"], scenario)))


if __name__ == "__main__":
    main()
