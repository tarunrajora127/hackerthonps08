"""Unit tests validating Pydantic schemas for security labels, action requests, and policy structures."""

import pytest
from datetime import datetime, timezone
from agentgate.models.security import (
    ClassificationLevel,
    Subject,
    ProvenanceMetadata,
    SecurityLabel,
)
from agentgate.models.action import (
    ActionType,
    ActionRequest,
    ReadDocumentPayload,
    SaveReportPayload,
    DeliverInboxPayload,
)
from agentgate.models.policy import (
    PolicyEffect,
    PolicyRule,
    PolicySet,
    PolicyEvaluationResult,
)
from agentgate.models.audit import (
    AuthorizationDecision,
    DecisionType,
    AuditEvent,
    WorkflowSessionState,
)


def test_classification_lattice_ordering():
    """Verify Bell-LaPadula lattice comparisons."""
    assert ClassificationLevel.PUBLIC < ClassificationLevel.INTERNAL
    assert ClassificationLevel.INTERNAL < ClassificationLevel.CONFIDENTIAL
    assert ClassificationLevel.CONFIDENTIAL < ClassificationLevel.RESTRICTED
    assert ClassificationLevel.RESTRICTED >= ClassificationLevel.CONFIDENTIAL
    assert ClassificationLevel.PUBLIC <= ClassificationLevel.PUBLIC


def test_security_label_combination():
    """Verify combining labels calculates supremum and merges provenance."""
    label_internal = SecurityLabel(
        classification=ClassificationLevel.INTERNAL,
        compartments=["HR"],
        provenance=ProvenanceMetadata(
            source_id="doc_hr",
            source_classification=ClassificationLevel.INTERNAL,
            derived_from=["raw_hr"],
        ),
    )
    label_confidential = SecurityLabel(
        classification=ClassificationLevel.CONFIDENTIAL,
        compartments=["FINANCE"],
        provenance=ProvenanceMetadata(
            source_id="doc_finance",
            source_classification=ClassificationLevel.CONFIDENTIAL,
            derived_from=["raw_finance"],
        ),
    )

    combined = label_internal.combine_with(label_confidential)
    # Highest classification is CONFIDENTIAL
    assert combined.classification == ClassificationLevel.CONFIDENTIAL
    # Union of compartments
    assert sorted(combined.compartments) == ["FINANCE", "HR"]
    # Merged derivation history
    assert "doc_hr" in combined.provenance.derived_from
    assert "doc_finance" in combined.provenance.derived_from


def test_action_request_validation():
    """Verify ActionRequest schema validates payloads."""
    subject = Subject(
        subject_id="agent_01",
        name="Summarizer Agent",
        role="agent",
        clearance=ClassificationLevel.CONFIDENTIAL,
    )

    # Deliver inbox payload
    deliver_req = ActionRequest(
        request_id="req_100",
        action_type=ActionType.DELIVER_INBOX,
        subject=subject,
        target_resource="inbox:external@client.com",
        payload={
            "recipient_id": "client_1",
            "recipient_address": "external@client.com",
            "subject": "Q3 Summary",
            "body": "Here is the quarterly summary.",
            "attached_document_ids": ["rep_01"],
        },
    )
    payload = deliver_req.get_deliver_payload()
    assert payload.recipient_address == "external@client.com"
    assert payload.attached_document_ids == ["rep_01"]


def test_policy_rule_and_set():
    """Verify PolicyRule and PolicySet validation."""
    rule = PolicyRule(
        rule_id="RULE_NO_EXT_CONFIDENTIAL",
        description="Block external delivery of confidential documents",
        priority=10,
        subject_roles=["*"],
        action_types=[ActionType.DELIVER_INBOX],
        block_external_delivery=True,
        max_classification_allowed=ClassificationLevel.INTERNAL,
        effect=PolicyEffect.ALLOW,
    )

    policy_set = PolicySet(
        policy_id="enterprise_v1",
        name="Enterprise Information Flow Policy",
        default_effect=PolicyEffect.DENY,
        rules=[rule],
    )

    assert len(policy_set.rules) == 1
    assert policy_set.default_effect == PolicyEffect.DENY
    assert policy_set.rules[0].block_external_delivery is True


def test_audit_and_workflow_schemas():
    """Verify AuditEvent and WorkflowSessionState validation."""
    event = AuditEvent(
        event_id="evt_01",
        event_type="AUTHORIZATION_DECISION",
        subject_id="agent_01",
        action_type="deliver_inbox",
        decision="BLOCK",
        target_resource="inbox:external@client.com",
        classification="CONFIDENTIAL",
        reason="Recipient external@client.com not authorized for CONFIDENTIAL data",
    )
    assert event.decision == "BLOCK"

    session = WorkflowSessionState(
        session_id="sess_abc",
        active_subject_id="user_analyst",
        loaded_document_ids=["doc_1", "doc_2"],
        highest_active_classification=ClassificationLevel.CONFIDENTIAL,
        active_compartments=["FINANCE"],
    )
    assert session.highest_active_classification == ClassificationLevel.CONFIDENTIAL
    assert session.status == "ACTIVE"

