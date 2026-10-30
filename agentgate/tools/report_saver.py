"""Protected Report Saving Tool."""

from __future__ import annotations
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentgate.db.database import AgentGateDB
from agentgate.models.action import SaveReportPayload
from agentgate.models.security import ClassificationLevel, ProvenanceMetadata, SecurityLabel


class ReportSaverTool:
    """Protected local tool for saving derived reports while preserving security labels and provenance."""

    def __init__(self, db: AgentGateDB, reports_dir: Optional[str] = None):
        self.db = db
        self.reports_dir = Path(reports_dir).resolve() if reports_dir else (Path.cwd() / "data" / "reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def execute(
        self,
        payload: SaveReportPayload,
        enforced_label: SecurityLabel,
    ) -> Dict[str, Any]:
        """Execute saving of derived report after gateway authorization."""
        report_id = payload.report_id
        safe_filename = f"{report_id.replace(' ', '_').lower()}.txt"
        target_file = self.reports_dir / safe_filename

        # Write report file to disk
        with open(target_file, "w", encoding="utf-8") as f:
            f.write(payload.content)

        # Compute SHA256
        content_hash = hashlib.sha256(payload.content.encode("utf-8")).hexdigest()

        # Update provenance with content checksum and file location
        if enforced_label.provenance:
            enforced_label.provenance.content_sha256 = content_hash
            enforced_label.provenance.source_uri = str(target_file)
        else:
            enforced_label.provenance = ProvenanceMetadata(
                source_id=report_id,
                source_uri=str(target_file),
                source_classification=enforced_label.classification,
                derived_from=payload.source_document_ids,
                transformations=["saved_report"],
                content_sha256=content_hash,
            )

        # Save persistent security label and provenance in SQLite DB
        self.db.save_security_label(report_id, enforced_label, resource_uri=str(target_file))

        return {
            "report_id": report_id,
            "title": payload.title,
            "saved_path": str(target_file),
            "classification": enforced_label.classification.value,
            "compartments": enforced_label.compartments,
            "content_hash": content_hash,
            "derived_from": payload.source_document_ids,
            "security_label": enforced_label.model_dump(),
        }

