"""Protected Document Reading Tool."""

from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from agentgate.db.database import AgentGateDB
from agentgate.models.action import ReadDocumentPayload
from agentgate.models.security import ClassificationLevel, ProvenanceMetadata, SecurityLabel


class DocumentReaderTool:
    """Protected local tool for reading documents and retrieving or establishing security labels."""

    def __init__(self, db: AgentGateDB, base_dir: Optional[str] = None):
        self.db = db
        self.base_dir = Path(base_dir).resolve() if base_dir else Path.cwd()

    def execute(self, payload: ReadDocumentPayload) -> Dict[str, Any]:
        """Execute document read operation after gateway authorization."""
        doc_id = payload.document_id
        path_str = payload.document_path or doc_id

        # Resolve path
        target_path = Path(path_str)
        if not target_path.is_absolute():
            target_path = (self.base_dir / target_path).resolve()

        if not target_path.exists():
            raise FileNotFoundError(f"Document file not found: {target_path}")

        # Read content
        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()

        # Compute SHA256
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()

        # Retrieve or construct security label
        existing_label = self.db.get_security_label(doc_id)
        if existing_label:
            label = existing_label
        else:
            # Infer initial classification from filename or content if not pre-seeded
            inferred_class = ClassificationLevel.INTERNAL
            filename_lower = target_path.name.lower()
            if "public" in filename_lower:
                inferred_class = ClassificationLevel.PUBLIC
            elif "confidential" in filename_lower:
                inferred_class = ClassificationLevel.CONFIDENTIAL
            elif "restricted" in filename_lower:
                inferred_class = ClassificationLevel.RESTRICTED

            label = SecurityLabel(
                classification=inferred_class,
                compartments=[],
                provenance=ProvenanceMetadata(
                    source_id=doc_id,
                    source_uri=str(target_path),
                    source_classification=inferred_class,
                    content_sha256=content_hash,
                ),
            )
            self.db.save_security_label(doc_id, label, resource_uri=str(target_path))

        return {
            "document_id": doc_id,
            "path": str(target_path),
            "content": content,
            "classification": label.classification.value,
            "compartments": label.compartments,
            "content_hash": content_hash,
            "security_label": label.model_dump(),
        }

