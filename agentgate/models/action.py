"""Action request models and payloads for protected tools."""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field
from agentgate.models.security import ClassificationLevel, Subject


class ActionType(str, Enum):
    """The three protected tools required by AGENTGATE."""
    READ_DOCUMENT = "read_document"
    SAVE_REPORT = "save_report"
    DELIVER_INBOX = "deliver_inbox"


class ReadDocumentPayload(BaseModel):
    """Payload for reading a document."""
    document_id: str = Field(..., description="Unique ID of document to read")
    document_path: Optional[str] = Field(None, description="Local path or filename")


class SaveReportPayload(BaseModel):
    """Payload for saving an AI-generated or derived report."""
    report_id: str = Field(..., description="Target identifier for the report")
    title: str = Field(..., description="Title of the report")
    content: str = Field(..., description="Report content or summary")
    source_document_ids: List[str] = Field(
        default_factory=list,
        description="IDs of documents that were consulted or summarized to generate this report",
    )
    requested_classification: Optional[ClassificationLevel] = Field(
        None,
        description="Optional explicitly requested classification (gateway enforces correct lattice)",
    )


class DeliverInboxPayload(BaseModel):
    """Payload for delivering a report or message to a recipient inbox."""
    recipient_id: str = Field(..., description="Identifier of recipient user or inbox")
    recipient_address: str = Field(..., description="Email or inbox destination address")
    subject: str = Field(..., description="Subject line")
    body: str = Field(..., description="Message text or content to deliver")
    attached_document_ids: List[str] = Field(
        default_factory=list,
        description="IDs of documents or reports attached / included in delivery",
    )


class ActionRequest(BaseModel):
    """Normalized action proposal submitted by an AI agent to AGENTGATE."""
    request_id: str = Field(..., description="Unique identifier for this action request")
    action_type: ActionType = Field(..., description="Type of tool operation requested")
    subject: Subject = Field(..., description="Identity requesting the operation")
    target_resource: str = Field(
        ..., description="Resource being accessed, modified, or delivered"
    )
    session_id: Optional[str] = Field(
        None, description="Workflow session ID for tracking state across multi-step execution"
    )
    payload: Dict[str, Any] = Field(
        default_factory=dict, description="Tool-specific arguments and payloads"
    )
    tainted_by_sources: List[str] = Field(
        default_factory=list,
        description="IDs of classified documents currently loaded into the agent context",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of request generation",
    )

    def get_read_payload(self) -> ReadDocumentPayload:
        return ReadDocumentPayload(**self.payload)

    def get_save_payload(self) -> SaveReportPayload:
        return SaveReportPayload(**self.payload)

    def get_deliver_payload(self) -> DeliverInboxPayload:
        return DeliverInboxPayload(**self.payload)

