"""AGENTGATE: Security Gateway for AI Actions and Information-Flow Control."""

from agentgate.core.gateway import AgentGate, AuthorizationBlockedException
from agentgate.core.policy_engine import PolicyEngine
from agentgate.db.database import AgentGateDB
from agentgate.models.security import (
    ClassificationLevel,
    ClearanceLevel,
    Subject,
    SecurityLabel,
    ProvenanceMetadata,
)
from agentgate.models.action import (
    ActionType,
    ActionRequest,
    ReadDocumentPayload,
    SaveReportPayload,
    DeliverInboxPayload,
)

__version__ = "0.1.0"

__all__ = [
    "AgentGate",
    "AgentGateDB",
    "AuthorizationBlockedException",
    "PolicyEngine",
    "ClassificationLevel",
    "ClearanceLevel",
    "Subject",
    "SecurityLabel",
    "ProvenanceMetadata",
    "ActionType",
    "ActionRequest",
    "ReadDocumentPayload",
    "SaveReportPayload",
    "DeliverInboxPayload",
]
