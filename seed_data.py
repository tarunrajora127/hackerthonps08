"""Seed initial security labels for demonstration and testing."""

import sys
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).parent))

from agentgate.db.database import AgentGateDB
from agentgate.models.security import ClassificationLevel, ProvenanceMetadata, SecurityLabel

def seed():
    db = AgentGateDB("achithon-2026-syntaxis/agentgate.db")
    docs_dir = Path("achithon-2026-syntaxis/data/documents")
    
    seeds = [
        ("public_handbook.txt", ClassificationLevel.PUBLIC, []),
        ("internal_roadmap.txt", ClassificationLevel.INTERNAL, []),
        ("confidential_merger.txt", ClassificationLevel.CONFIDENTIAL, ["FINANCE"]),
        ("restricted_keys.txt", ClassificationLevel.RESTRICTED, ["SECURITY"]),
        ("untrusted_vendor_invoice.txt", ClassificationLevel.PUBLIC, []),
    ]
    
    for filename, classification, compartments in seeds:
        filepath = docs_dir / filename
        label = SecurityLabel(
            classification=classification,
            compartments=compartments,
            provenance=ProvenanceMetadata(
                source_id=filename,
                source_uri=str(filepath.resolve()),
                source_classification=classification,
                derived_from=[],
                transformations=["original_upload"],
                created_at=datetime.now(timezone.utc),
            )
        )
        db.save_security_label(filename, label, resource_uri=str(filepath))
        print(f"Seeded label for '{filename}': {classification.value} {compartments}")

if __name__ == "__main__":
    seed()

