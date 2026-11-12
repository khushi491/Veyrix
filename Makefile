.PHONY: demo-snapshot kit-snapshot

# Re-run the local engine for the two demo agents and refresh the dashboard snapshot.
demo-snapshot:
	python -m veyrix.demo_snapshot

# Re-run veyrix scan for the public red-team kit fallback.
kit-snapshot:
	python -m veyrix.kit_snapshot
