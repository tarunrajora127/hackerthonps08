"""Audit events, authorization decisions, and workflow session state models."""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from agentgate.models.action import ActionType
from agentgate.models.security import ClassificationLevel


class DecisionType(str, Enum):
    """Gateway authorization outcome."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class AuthorizationDecision(BaseModel):
    """Detailed record of an authorization evaluation performed by the Gateway."""
    decision_id: str = Field(..., description="Unique decision ID")
    request_id: str = Field(..., description="ID of corresponding action request")
    decision: DecisionType = Field(..., description="ALLOW or BLOCK")
    action_type: ActionType = Field(..., description="Operation attempted")
    subject_id: str = Field(..., description="Identity requesting operation")
    subject_role: str = Field(..., description="Role of requesting subject")
    target_resource: str = Field(..., description="Resource accessed or created")
    recipient_address: Optional[str] = Field(None, description="Recipient inbox if applicable")
    enforced_classification: ClassificationLevel = Field(
        ..., description="Sensitivity level enforced for this operation"
    )
    reason: str = Field(..., description="Auditable security explanation")
    matched_rule_id: Optional[str] = Field(None, description="Policy rule triggered")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of evaluation",
    )


class AuditEvent(BaseModel):
    """Immutable log entry stored in the persistent audit trail."""
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event timestamp in UTC",
    )
    event_type: str = Field(
        default="AUTHORIZATION_DECISION",
        description="Category: AUTHORIZATION_DECISION, TOOL_EXECUTE, WORKFLOW_PAUSE, WORKFLOW_RESUME",
    )
    session_id: Optional[str] = Field(None, description="Workflow session ID")
    subject_id: str = Field(..., description="Subject identity")
    action_type: str = Field(..., description="Action type or operation")
    decision: str = Field(..., description="ALLOW, BLOCK, SUCCESS, FAILURE")
    target_resource: str = Field(..., description="Target resource or destination")
    classification: str = Field(..., description="Classification level string")
    reason: str = Field(..., description="Explanation or error message")
    details: Dict[str, Any] = Field(default_factory=dict, description="Detailed event context")


class WorkflowSessionState(BaseModel):
    """Persistent workflow context preserving security classifications across resumptions."""
    session_id: str = Field(..., description="Unique session identifier")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    active_subject_id: str = Field(..., description="Subject owning this workflow session")
    loaded_document_ids: List[str] = Field(
        default_factory=list,
        description="IDs of documents loaded/read into this workflow memory",
    )
    highest_active_classification: ClassificationLevel = Field(
        default=ClassificationLevel.PUBLIC,
        description="Highest classification loaded into session context (taint propagation)",
    )
    active_compartments: List[str] = Field(
        default_factory=list,
        description="Set of compartments present in loaded context",
    )
    status: str = Field(default="ACTIVE", description="ACTIVE, PAUSED, COMPLETED")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Session state variables")

