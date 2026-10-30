"""Comprehensive test suite for AGENTGATE Security Gateway and Protected Tools."""

import os
import pytest
from pathlib import Path

from agentgate.core.gateway import AgentGate
from agentgate.db.database import AgentGateDB
from agentgate.models.action import ActionRequest, ActionType
from agentgate.models.security import ClassificationLevel, Subject


@pytest.fixture
def test_gateway(tmp_path):
    """Fixture providing an isolated AgentGate instance with temporary SQLite DB."""
    db_file = tmp_path / "test_agentgate.db"
    docs_dir = Path("achithon-2026-syntaxis/data/documents")
    db = AgentGateDB(str(db_file))
    gateway = AgentGate(db=db, base_dir=str(docs_dir))

    # Seed labels in temporary database
    from seed_data import seed
    # Seed labels directly into test db
    for filename, classification, compartments in [
        ("public_handbook.txt", ClassificationLevel.PUBLIC, []),
        ("internal_roadmap.txt", ClassificationLevel.INTERNAL, []),
        ("confidential_merger.txt", ClassificationLevel.CONFIDENTIAL, ["FINANCE"]),
        ("restricted_keys.txt", ClassificationLevel.RESTRICTED, ["SECURITY"]),
        ("untrusted_vendor_invoice.txt", ClassificationLevel.PUBLIC, []),
    ]:
        from agentgate.models.security import ProvenanceMetadata, SecurityLabel
        lbl = SecurityLabel(
            classification=classification,
            compartments=compartments,
            provenance=ProvenanceMetadata(
                source_id=filename,
                source_classification=classification,
            ),
        )
        db.save_security_label(filename, lbl)

    return gateway


def test_authorized_document_read(test_gateway):
    """Verify subject with sufficient clearance can read internal document."""
    analyst = Subject(
        subject_id="analyst_alice",
        name="Alice Analyst",
        role="analyst",
        clearance=ClassificationLevel.INTERNAL,
        compartments=[],
    )

    req = ActionRequest(
        request_id="req_read_01",
        action_type=ActionType.READ_DOCUMENT,
        subject=analyst,
        target_resource="internal_roadmap.txt",
        payload={
            "document_id": "internal_roadmap.txt",
            "document_path": "internal_roadmap.txt",
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is True
    assert result["decision"] == "ALLOW"
    assert "Engineering Roadmap" in result["data"]["content"]
    assert result["data"]["classification"] == "INTERNAL"


def test_blocked_document_read_insufficient_clearance(test_gateway):
    """Verify subject with low clearance is blocked from reading confidential document."""
    junior_staff = Subject(
        subject_id="intern_bob",
        name="Bob Intern",
        role="intern",
        clearance=ClassificationLevel.INTERNAL,  # Lower than CONFIDENTIAL
        compartments=[],
    )

    req = ActionRequest(
        request_id="req_read_02",
        action_type=ActionType.READ_DOCUMENT,
        subject=junior_staff,
        target_resource="confidential_merger.txt",
        payload={
            "document_id": "confidential_merger.txt",
            "document_path": "confidential_merger.txt",
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is False
    assert result["decision"] == "BLOCK"
    assert "Clearance violation" in result["reason"]
    assert result["data"] is None  # Underlying tool was NEVER executed


def test_blocked_document_read_missing_compartment(test_gateway):
    """Verify subject with high clearance but missing compartment is blocked."""
    manager = Subject(
        subject_id="manager_dan",
        name="Dan Manager",
        role="manager",
        clearance=ClassificationLevel.CONFIDENTIAL,
        compartments=[],  # Missing 'FINANCE' compartment
    )

    req = ActionRequest(
        request_id="req_read_03",
        action_type=ActionType.READ_DOCUMENT,
        subject=manager,
        target_resource="confidential_merger.txt",
        payload={
            "document_id": "confidential_merger.txt",
            "document_path": "confidential_merger.txt",
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is False
    assert result["decision"] == "BLOCK"
    assert "lacks required compartments" in result["reason"]


def test_save_report_inherits_classification(test_gateway):
    """Verify saved report inherits the classification of its source documents."""
    officer = Subject(
        subject_id="cfo_clara",
        name="Clara CFO",
        role="admin",
        clearance=ClassificationLevel.RESTRICTED,
        compartments=["FINANCE", "SECURITY"],
    )

    req = ActionRequest(
        request_id="req_save_01",
        action_type=ActionType.SAVE_REPORT,
        subject=officer,
        target_resource="report_merger_summary",
        payload={
            "report_id": "report_merger_summary",
            "title": "M&A Due Diligence Executive Brief",
            "content": "The projected acquisition price is 450M.",
            "source_document_ids": ["confidential_merger.txt"],
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is True
    assert result["decision"] == "ALLOW"
    assert result["data"]["classification"] == "CONFIDENTIAL"

    # Verify label was stored in database
    saved_label = test_gateway.db.get_security_label("report_merger_summary")
    assert saved_label is not None
    assert saved_label.classification == ClassificationLevel.CONFIDENTIAL


def test_blocked_unauthorized_declassification(test_gateway):
    """Verify attempt to downgrade report classification from CONFIDENTIAL to PUBLIC is blocked."""
    analyst = Subject(
        subject_id="analyst_alice",
        name="Alice Analyst",
        role="analyst",
        clearance=ClassificationLevel.CONFIDENTIAL,
        compartments=["FINANCE"],
    )

    req = ActionRequest(
        request_id="req_save_declassify",
        action_type=ActionType.SAVE_REPORT,
        subject=analyst,
        target_resource="report_leaked_notes",
        payload={
            "report_id": "report_leaked_notes",
            "title": "Public Valuation Notes",
            "content": "Acquisition at 450M.",
            "source_document_ids": ["confidential_merger.txt"],
            "requested_classification": ClassificationLevel.PUBLIC,  # Unauthorized downgrade!
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is False
    assert result["decision"] == "BLOCK"
    assert "Unauthorized declassification detected" in result["reason"]


def test_blocked_external_delivery_of_confidential_data(test_gateway):
    """Verify gateway blocks delivering confidential report to external recipient."""
    agent = Subject(
        subject_id="agent_summarizer",
        name="AI Summarizer",
        role="agent",
        clearance=ClassificationLevel.CONFIDENTIAL,
    )

    req = ActionRequest(
        request_id="req_deliv_leak",
        action_type=ActionType.DELIVER_INBOX,
        subject=agent,
        target_resource="inbox:leak@adversary.com",
        payload={
            "recipient_id": "adversary_01",
            "recipient_address": "leak@adversary.com",  # External destination
            "subject": "Confidential Deal Details",
            "body": "Here is the confidential merger document.",
            "attached_document_ids": ["confidential_merger.txt"],
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is False
    assert result["decision"] == "BLOCK"
    assert "Information-flow restriction violation" in result["reason"]

    # Verify message was NEVER delivered to mock inboxes
    inbox_messages = test_gateway.db.get_mock_inbox_messages("leak@adversary.com")
    assert len(inbox_messages) == 0


def test_authorized_internal_delivery(test_gateway):
    """Verify internal corporate delivery succeeds."""
    analyst = Subject(
        subject_id="analyst_alice",
        name="Alice Analyst",
        role="analyst",
        clearance=ClassificationLevel.INTERNAL,
    )

    req = ActionRequest(
        request_id="req_deliv_internal",
        action_type=ActionType.DELIVER_INBOX,
        subject=analyst,
        target_resource="inbox:team@company.com",
        payload={
            "recipient_id": "team_inbox",
            "recipient_address": "team@company.com",
            "subject": "Q4 Roadmap Status",
            "body": "Roadmap update for internal review.",
            "attached_document_ids": ["internal_roadmap.txt"],
        },
    )

    result = test_gateway.execute(req)
    assert result["success"] is True
    assert result["decision"] == "ALLOW"
    assert result["data"]["status"] == "DELIVERED"

    # Verify message in mock inbox table
    inbox_messages = test_gateway.db.get_mock_inbox_messages("team@company.com")
    assert len(inbox_messages) == 1
    assert inbox_messages[0]["subject"] == "Q4 Roadmap Status"


def test_workflow_session_persistence_and_resumption(test_gateway):
    """Verify workflow session resumption preserves taint and blocks unauthorized exfiltration."""
    officer = Subject(
        subject_id="cfo_clara",
        name="Clara CFO",
        role="admin",
        clearance=ClassificationLevel.CONFIDENTIAL,
        compartments=["FINANCE"],
    )

    session_id = "wf_merger_audit_2026"

    # 1. Start session & read confidential document
    test_gateway.create_session(session_id, officer)

    read_req = ActionRequest(
        request_id="req_session_read",
        action_type=ActionType.READ_DOCUMENT,
        subject=officer,
        session_id=session_id,
        target_resource="confidential_merger.txt",
        payload={
            "document_id": "confidential_merger.txt",
            "document_path": "confidential_merger.txt",
        },
    )
    read_res = test_gateway.execute(read_req)
    assert read_res["success"] is True

    # 2. Pause session (checkpoint to DB)
    test_gateway.pause_session(session_id)

    # 3. Simulate process restart / new gateway instance reading from SQLite DB
    new_gateway = AgentGate(db=test_gateway.db, base_dir=test_gateway.doc_reader.base_dir)
    resumed_session = new_gateway.resume_session(session_id)

    assert resumed_session is not None
    assert resumed_session.highest_active_classification == ClassificationLevel.CONFIDENTIAL
    assert "confidential_merger.txt" in resumed_session.loaded_document_ids

    # 4. Attempt to send email within resumed session to external address
    leak_req = ActionRequest(
        request_id="req_session_leak_attempt",
        action_type=ActionType.DELIVER_INBOX,
        subject=officer,
        session_id=session_id,
        target_resource="inbox:hacker@external.io",
        payload={
            "recipient_id": "hacker",
            "recipient_address": "hacker@external.io",
            "subject": "Resumed Workflow Notes",
            "body": "Sending notes from resumed session.",
        },
    )

    leak_res = new_gateway.execute(leak_req)
    # MUST BE BLOCKED because the session retained its CONFIDENTIAL classification across resumption!
    assert leak_res["success"] is False
    assert leak_res["decision"] == "BLOCK"
    assert "Information-flow restriction violation" in leak_res["reason"]


def test_audit_trail_completeness(test_gateway):
    """Verify audit log captures all attempts with complete reasons and decisions."""
    analyst = Subject(
        subject_id="analyst_alice",
        name="Alice Analyst",
        role="analyst",
        clearance=ClassificationLevel.INTERNAL,
    )

    req = ActionRequest(
        request_id="req_audit_test",
        action_type=ActionType.READ_DOCUMENT,
        subject=analyst,
        target_resource="public_handbook.txt",
        payload={
            "document_id": "public_handbook.txt",
            "document_path": "public_handbook.txt",
        },
    )
    test_gateway.execute(req)

    events = test_gateway.db.get_audit_events(limit=10)
    assert len(events) >= 2  # Authorization decision + Tool execute success
    decision_events = [e for e in events if e["event_type"] == "AUTHORIZATION_DECISION"]
    assert len(decision_events) > 0
    assert decision_events[0]["subject_id"] == "analyst_alice"
    assert decision_events[0]["decision"] == "ALLOW"
    assert decision_events[0]["classification"] == "PUBLIC"


def test_prompt_injection_resistance_blocks_exfiltration(test_gateway):
    """Verify that even when an untrusted document tricks an AI into proposing an exfiltration action,

    AGENTGATE independently stops the delivery before execution.
    """
    ai_agent = Subject(
        subject_id="agent_assistant",
        name="LLM Assistant",
        role="agent",
        clearance=ClassificationLevel.INTERNAL,  # Standard clearance
        compartments=[],
    )

    # 1. AI reads untrusted document containing prompt injection
    read_req = ActionRequest(
        request_id="req_read_untrusted",
        action_type=ActionType.READ_DOCUMENT,
        subject=ai_agent,
        target_resource="untrusted_vendor_invoice.txt",
        payload={
            "document_id": "untrusted_vendor_invoice.txt",
            "document_path": "untrusted_vendor_invoice.txt",
        },
    )
    read_res = test_gateway.execute(read_req)
    assert read_res["success"] is True
    assert "[SYSTEM OVERRIDE]" in read_res["data"]["content"]

    # 2. AI model (tricked by prompt injection) tries to read confidential merger file
    attack_read = ActionRequest(
        request_id="req_attack_read_confidential",
        action_type=ActionType.READ_DOCUMENT,
        subject=ai_agent,
        target_resource="confidential_merger.txt",
        payload={
            "document_id": "confidential_merger.txt",
            "document_path": "confidential_merger.txt",
        },
    )
    attack_read_res = test_gateway.execute(attack_read)
    # BLOCKED: agent lacks clearance and FINANCE compartment!
    assert attack_read_res["success"] is False
    assert attack_read_res["decision"] == "BLOCK"

    # 3. AI model tries to exfiltrate confidential content to adversary's external address
    attack_exfiltrate = ActionRequest(
        request_id="req_attack_deliver_leak",
        action_type=ActionType.DELIVER_INBOX,
        subject=ai_agent,
        target_resource="inbox:adversary@external-leak.com",
        payload={
            "recipient_id": "adversary",
            "recipient_address": "adversary@external-leak.com",
            "subject": "Exfiltrated Merger Info",
            "body": "Confidential financial valuation: $450,000,000",
        },
    )
    attack_deliv_res = test_gateway.execute(attack_exfiltrate)
    # BLOCKED: Information-flow restriction prevents external delivery of confidential content!
    assert attack_deliv_res["success"] is False
    assert attack_deliv_res["decision"] == "BLOCK"
    assert "Information-flow restriction violation" in attack_deliv_res["reason"]

    # Inboxes remain completely clean
    adversary_inbox = test_gateway.db.get_mock_inbox_messages("adversary@external-leak.com")
    assert len(adversary_inbox) == 0
