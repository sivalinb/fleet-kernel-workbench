"""Use the installed catalog package for reconciliation, provenance and impact."""

from datetime import timedelta
from pathlib import Path

from fleet_catalog.catalog import Batch, Record, impact, ingest, snapshot
from fleet_catalog.models import Source, make_database, utcnow


def catalog_context(directory: Path, profile: str):
    directory.mkdir(parents=True, exist_ok=True)
    engine, factory = make_database("sqlite:///" + str(directory / "catalog.db"))
    owner = {} if profile == "unknown-owner" else {"owner": "team:platform"}
    records = [
        ("team:platform", "team", {"name": "Platform Engineering"}),
        ("cluster:learning", "cluster", {"name": "Learning cluster", "owner": "team:platform"}),
        (
            "node:lab-node",
            "node",
            {"name": "Lab node", "owner": "team:platform", "cluster": "cluster:learning"},
        ),
        (
            "service:kernel-client",
            "service",
            {
                "name": "Kernel client",
                **owner,
                "runsOn": ["node:lab-node"],
                "cluster": "cluster:learning",
                "lifecycle": "experimental",
                "description": "Explicit binding to the workbench-owned loopback client.",
            },
        ),
        (
            "service:frontend",
            "service",
            {
                "name": "Frontend",
                "owner": "team:platform",
                "dependsOn": ["service:kernel-client"],
                "runsOn": ["node:lab-node"],
            },
        ),
    ]
    observed = utcnow() - timedelta(hours=2 if profile == "stale-owner" else 0)
    try:
        with factory.begin() as db:
            db.add(
                Source(
                    id="learning-catalog",
                    name="Fictional learning inventory",
                    kind="catalog",
                    ttl_seconds=900,
                )
            )
            db.flush()
            ingest(
                db,
                "learning-catalog",
                Batch(
                    batch_id="initial",
                    observed_at=observed,
                    records=[
                        Record(external_id=i, entity_id=i, kind=k, fields=f) for i, k, f in records
                    ],
                ),
            )
        with factory() as db:
            data = snapshot(db)
        service = next(e for e in data["entities"] if e["id"] == "service:kernel-client")
        return {
            "snapshot": data,
            "service": service,
            "exposure": impact(data, "service:kernel-client"),
            "binding": {
                "method": "Explicit owned-process binding; no name or IP inference",
                "service": "service:kernel-client",
                "node": "node:lab-node",
                "inventory_origin": "Fictional learning inventory in both capture modes",
            },
        }
    finally:
        engine.dispose()
