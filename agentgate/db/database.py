"""SQLite database manager for AGENTGATE persistence and auditing."""

from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from agentgate.models.audit import AuditEvent, WorkflowSessionState
from agentgate.models.policy import PolicyEffect, PolicyRule, PolicySet
from agentgate.models.security import ClassificationLevel, ProvenanceMetadata, SecurityLabel


class AgentGateDB:
    """Manages SQLite storage for audit logs, security labels, workflow states, and mock inboxes."""

    def __init__(self, db_path: str = "agentgate.db"):
        self.db_path = Path(db_path).resolve()
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize all database tables if they do not exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Audit events table (immutable audit trail)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    session_id TEXT,
                    subject_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    target_resource TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details_json TEXT
                )
                """
            )

            # 2. Security labels & provenance metadata table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_labels (
                    resource_id TEXT PRIMARY KEY,
                    resource_uri TEXT,
                    classification TEXT NOT NULL,
                    compartments_json TEXT,
                    source_classification TEXT,
                    derived_from_json TEXT,
                    transformations_json TEXT,
                    content_sha256 TEXT,
                    created_at TEXT NOT NULL,
                    declassified_by TEXT
                )
                """
            )

            # 3. Workflow session state table (for session resumption without label loss)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS workflow_sessions (
                    session_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    active_subject_id TEXT NOT NULL,
                    loaded_document_ids_json TEXT,
                    highest_active_classification TEXT NOT NULL,
                    active_compartments_json TEXT,
                    status TEXT NOT NULL,
                    metadata_json TEXT
                )
                """
            )

            # 4. Mock inbox messages table (protected delivery destination)
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS mock_inboxes (
                    message_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    sender_id TEXT NOT NULL,
                    recipient_address TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    body TEXT NOT NULL,
                    enforced_classification TEXT NOT NULL,
                    attachments_json TEXT
                )
                """
            )

            # 5. Policy rules table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS policy_rules (
                    rule_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    priority INTEGER NOT NULL,
                    subject_roles_json TEXT NOT NULL,
                    action_types_json TEXT NOT NULL,
                    target_resource_pattern TEXT NOT NULL,
                    max_classification_allowed TEXT,
                    allowed_recipient_domains_json TEXT,
                    block_external_delivery INTEGER NOT NULL,
                    allow_declassification INTEGER NOT NULL,
                    effect TEXT NOT NULL
                )
                """
            )

            conn.commit()

    # --- Audit Operations ---

    def record_audit_event(self, event: AuditEvent) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (
                    event_id, timestamp, event_type, session_id, subject_id,
                    action_type, decision, target_resource, classification, reason, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.timestamp.isoformat(),
                    event.event_type,
                    event.session_id,
                    event.subject_id,
                    event.action_type,
                    event.decision,
                    event.target_resource,
                    event.classification,
                    event.reason,
                    json.dumps(event.details, default=str),
                ),
            )
            conn.commit()

    def get_audit_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

    # --- Security Label Operations ---

    def save_security_label(self, resource_id: str, label: SecurityLabel, resource_uri: Optional[str] = None) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            prov = label.provenance
            cursor.execute(
                """
                INSERT OR REPLACE INTO security_labels (
                    resource_id, resource_uri, classification, compartments_json,
                    source_classification, derived_from_json, transformations_json,
                    content_sha256, created_at, declassified_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    resource_id,
                    resource_uri or (prov.source_uri if prov else None),
                    label.classification.value,
                    json.dumps(label.compartments),
                    prov.source_classification.value if prov else label.classification.value,
                    json.dumps(prov.derived_from if prov else []),
                    json.dumps(prov.transformations if prov else []),
                    prov.content_sha256 if prov else None,
                    (prov.created_at if prov else datetime.now(timezone.utc)).isoformat(),
                    label.declassification_authorized_by,
                ),
            )
            conn.commit()

    def get_security_label(self, resource_id: str) -> Optional[SecurityLabel]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM security_labels WHERE resource_id = ?",
                (resource_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            prov = ProvenanceMetadata(
                source_id=row["resource_id"],
                source_uri=row["resource_uri"],
                source_classification=ClassificationLevel(row["source_classification"]),
                derived_from=json.loads(row["derived_from_json"] or "[]"),
                transformations=json.loads(row["transformations_json"] or "[]"),
                created_at=datetime.fromisoformat(row["created_at"]),
                content_sha256=row["content_sha256"],
            )

            return SecurityLabel(
                classification=ClassificationLevel(row["classification"]),
                compartments=json.loads(row["compartments_json"] or "[]"),
                provenance=prov,
                declassification_authorized_by=row["declassified_by"],
            )

    # --- Workflow Session Resumption Operations ---

    def save_workflow_session(self, session: WorkflowSessionState) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO workflow_sessions (
                    session_id, created_at, updated_at, active_subject_id,
                    loaded_document_ids_json, highest_active_classification,
                    active_compartments_json, status, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.session_id,
                    session.created_at.isoformat(),
                    session.updated_at.isoformat(),
                    session.active_subject_id,
                    json.dumps(session.loaded_document_ids),
                    session.highest_active_classification.value,
                    json.dumps(session.active_compartments),
                    session.status,
                    json.dumps(session.metadata, default=str),
                ),
            )
            conn.commit()

    def get_workflow_session(self, session_id: str) -> Optional[WorkflowSessionState]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM workflow_sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cursor.fetchone()
            if not row:
                return None

            return WorkflowSessionState(
                session_id=row["session_id"],
                created_at=datetime.fromisoformat(row["created_at"]),
                updated_at=datetime.fromisoformat(row["updated_at"]),
                active_subject_id=row["active_subject_id"],
                loaded_document_ids=json.loads(row["loaded_document_ids_json"] or "[]"),
                highest_active_classification=ClassificationLevel(row["highest_active_classification"]),
                active_compartments=json.loads(row["active_compartments_json"] or "[]"),
                status=row["status"],
                metadata=json.loads(row["metadata_json"] or "{}"),
            )

    # --- Mock Inbox Operations ---

    def deliver_to_mock_inbox(
        self,
        message_id: str,
        sender_id: str,
        recipient_address: str,
        subject: str,
        body: str,
        enforced_classification: ClassificationLevel,
        attachments: Optional[List[str]] = None,
    ) -> None:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO mock_inboxes (
                    message_id, timestamp, sender_id, recipient_address,
                    subject, body, enforced_classification, attachments_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    datetime.now(timezone.utc).isoformat(),
                    sender_id,
                    recipient_address,
                    subject,
                    body,
                    enforced_classification.value,
                    json.dumps(attachments or [], default=str),
                ),
            )
            conn.commit()

    def get_mock_inbox_messages(self, recipient_address: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if recipient_address:
                cursor.execute(
                    "SELECT * FROM mock_inboxes WHERE recipient_address = ? ORDER BY timestamp DESC",
                    (recipient_address,),
                )
            else:
                cursor.execute("SELECT * FROM mock_inboxes ORDER BY timestamp DESC")
            rows = cursor.fetchall()
            return [dict(row) for row in rows]

