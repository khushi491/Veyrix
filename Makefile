.PHONY: demo-snapshot

# Re-run the local engine for the two demo agents and refresh the dashboard snapshot.
demo-snapshot:
	python -m veyrix.demo_snapshot
