"""End-to-End Testing and Invariant Verification Suite for AGENTGATE."""

import os
import uuid
import pytest
from datetime import datetime, timezone
from pathlib import Path

from agentgate.core.gateway import AgentGate
from agentgate.db.database import AgentGateDB
from agentgate.models.action import ActionRequest, ActionType
from agentgate.models.security import ClassificationLevel, ProvenanceMetadata, SecurityLabel, Subject


@pytest.fixture
def e2e_env(tmp_path):
    """Set up an isolated end-to-end environment with fresh SQLite DB and test docs."""
    db_path = tmp_path / "e2e_agentgate.db"
    docs_dir = Path("achithon-2026-syntaxis/data/documents")
    db = AgentGateDB(str(db_path))
    gateway = AgentGate(db=db, base_dir=str(docs_dir))

    # Seed test documents
    seeds = [
        ("public_handbook.txt", ClassificationLevel.PUBLIC, []),
        ("internal_roadmap.txt", ClassificationLevel.INTERNAL, []),
        ("confidential_merger.txt", ClassificationLevel.CONFIDENTIAL, ["FINANCE"]),
        ("restricted_keys.txt", ClassificationLevel.RESTRICTED, ["SECURITY"]),
        ("untrusted_vendor_invoice.txt", ClassificationLevel.PUBLIC, []),
    ]
    for filename, classification, compartments in seeds:
        lbl = SecurityLabel(
            classification=classification,
            compartments=compartments,
            provenance=ProvenanceMetadata(
                source_id=filename,
                source_classification=classification,
            ),
        )
        db.save_security_label(filename, lbl)

    return {"db": db, "gateway": gateway, "docs_dir": docs_dir}


# ==============================================================================
# PHASE 1: COMPREHENSIVE CLEARANCE & IDENTITY ENFORCEMENT
# ==============================================================================

def test_e2e_clearance_matrix(e2e_env):
    """Test all subjects against all document classifications to verify the Bell-LaPadula lattice."""
    gateway = e2e_env["gateway"]

    subjects = {
        "guest": Subject(subject_id="sub_guest", name="Guest", role="guest", clearance=ClassificationLevel.PUBLIC),
        "intern": Subject(subject_id="sub_intern", name="Intern", role="intern", clearance=ClassificationLevel.INTERNAL),
        "analyst": Subject(subject_id="sub_analyst", name="Analyst", role="analyst", clearance=ClassificationLevel.CONFIDENTIAL, compartments=["FINANCE"]),
        "executive": Subject(subject_id="sub_exec", name="Exec", role="admin", clearance=ClassificationLevel.RESTRICTED, compartments=["FINANCE", "SECURITY"]),
    }

    # Matrix: (subject_key, doc_id, expected_allowed)
    test_cases = [
        # Guest (PUBLIC)
        ("guest", "public_handbook.txt", True),
        ("guest", "internal_roadmap.txt", False),
        ("guest", "confidential_merger.txt", False),
        ("guest", "restricted_keys.txt", False),

        # Intern (INTERNAL)
        ("intern", "public_handbook.txt", True),
        ("intern", "internal_roadmap.txt", True),
        ("intern", "confidential_merger.txt", False),
        ("intern", "restricted_keys.txt", False),

        # Analyst (CONFIDENTIAL + FINANCE)
        ("analyst", "public_handbook.txt", True),
        ("analyst", "internal_roadmap.txt", True),
        ("analyst", "confidential_merger.txt", True),
        ("analyst", "restricted_keys.txt", False),  # Lacks RESTRICTED and SECURITY compartment

        # Executive (RESTRICTED + ALL COMPARTMENTS)
        ("executive", "public_handbook.txt", True),
        ("executive", "internal_roadmap.txt", True),
        ("executive", "confidential_merger.txt", True),
        ("executive", "restricted_keys.txt", True),
    ]

    for subj_key, doc_id, expected_allow in test_cases:
        req = ActionRequest(
            request_id=f"e2e_mat_{subj_key}_{doc_id[:4]}",
            action_type=ActionType.READ_DOCUMENT,
            subject=subjects[subj_key],
            target_resource=doc_id,
            payload={"document_id": doc_id, "document_path": doc_id},
        )
        res = gateway.execute(req)
        assert res["success"] == expected_allow, (
            f"Failed for {subj_key} accessing {doc_id}. Expected {expected_allow}, got {res['success']}. "
            f"Reason: {res['reason']}"
        )
        if expected_allow:
            assert res["data"] is not None
        else:
            assert res["data"] is None  # Invariant: blocked tool never runs


# ==============================================================================
# PHASE 2: MULTI-SOURCE LATTICE SUPREMUM & ANTI-DOWNGRADE ENFORCEMENT
# ==============================================================================

def test_e2e_information_flow_supremum(e2e_env):
    """Verify report combining PUBLIC, INTERNAL, and CONFIDENTIAL sources receives CONFIDENTIAL label."""
    gateway = e2e_env["gateway"]
    cfo = Subject(
        subject_id="cfo",
        name="CFO",
        role="admin",
        clearance=ClassificationLevel.RESTRICTED,
        compartments=["FINANCE", "SECURITY"],
    )

    req = ActionRequest(
        request_id="e2e_supremum_01",
        action_type=ActionType.SAVE_REPORT,
        subject=cfo,
        target_resource="consolidated_executive_report",
        payload={
            "report_id": "consolidated_executive_report",
            "title": "Consolidated Q4 Strategic Brief",
            "content": "Merging handbook, roadmap, and M&A data.",
            "source_document_ids": [
                "public_handbook.txt",        # PUBLIC
                "internal_roadmap.txt",       # INTERNAL
                "confidential_merger.txt",    # CONFIDENTIAL
            ],
        },
    )

    res = gateway.execute(req)
    assert res["success"] is True
    # The mathematical supremum of {PUBLIC, INTERNAL, CONFIDENTIAL} is CONFIDENTIAL
    assert res["data"]["classification"] == "CONFIDENTIAL"

    # Verify persistent label in DB
    db_label = gateway.db.get_security_label("consolidated_executive_report")
    assert db_label is not None
    assert db_label.classification == ClassificationLevel.CONFIDENTIAL
    assert "public_handbook.txt" in db_label.provenance.derived_from
    assert "confidential_merger.txt" in db_label.provenance.derived_from


# ==============================================================================
# PHASE 3: EXFILTRATION & RECIPIENT DOMAIN BOUNDARY ENFORCEMENT
# ==============================================================================

def test_e2e_exfiltration_boundaries(e2e_env):
    """Verify that sensitive information can only reach authorized corporate destinations."""
    gateway = e2e_env["gateway"]
    analyst = Subject(
        subject_id="analyst",
        name="Analyst",
        role="analyst",
        clearance=ClassificationLevel.CONFIDENTIAL,
        compartments=["FINANCE"],
    )

    # 1. Internal delivery of internal report -> ALLOWED
    int_req = ActionRequest(
        request_id="deliv_int_valid",
        action_type=ActionType.DELIVER_INBOX,
        subject=analyst,
        target_resource="inbox:team@company.com",
        payload={
            "recipient_id": "team",
            "recipient_address": "team@company.com",
            "subject": "Roadmap Sync",
            "body": "Roadmap update for team.",
            "attached_document_ids": ["internal_roadmap.txt"],
        },
    )
    res_int = gateway.execute(int_req)
    assert res_int["success"] is True
    assert res_int["decision"] == "ALLOW"

    # 2. External delivery of internal document -> BLOCKED
    ext_req = ActionRequest(
        request_id="deliv_ext_leak",
        action_type=ActionType.DELIVER_INBOX,
        subject=analyst,
        target_resource="inbox:analyst-personal@gmail.com",
        payload={
            "recipient_id": "personal",
            "recipient_address": "analyst-personal@gmail.com",
            "subject": "Forwarding roadmap to personal email",
            "body": "Sending copy home.",
            "attached_document_ids": ["internal_roadmap.txt"],
        },
    )
    res_ext = gateway.execute(ext_req)
    assert res_ext["success"] is False
    assert res_ext["decision"] == "BLOCK"
    assert "Information-flow restriction violation" in res_ext["reason"]

    # 3. External delivery of confidential merger doc -> BLOCKED
    conf_ext_req = ActionRequest(
        request_id="deliv_conf_ext_leak",
        action_type=ActionType.DELIVER_INBOX,
        subject=analyst,
        target_resource="inbox:adversary@competitor.com",
        payload={
            "recipient_id": "competitor",
            "recipient_address": "adversary@competitor.com",
            "subject": "M&A target info",
            "body": "Here is the valuation report.",
            "attached_document_ids": ["confidential_merger.txt"],
        },
    )
    res_conf_ext = gateway.execute(conf_ext_req)
    assert res_conf_ext["success"] is False
    assert res_conf_ext["decision"] == "BLOCK"

    # Invariant: External mock inboxes received 0 messages
    gmail_msgs = gateway.db.get_mock_inbox_messages("analyst-personal@gmail.com")
    competitor_msgs = gateway.db.get_mock_inbox_messages("adversary@competitor.com")
    assert len(gmail_msgs) == 0
    assert len(competitor_msgs) == 0


# ==============================================================================
# PHASE 4: WORKFLOW CHECKPOINTING, SERIALIZATION & RESUMPTION
# ==============================================================================

def test_e2e_workflow_lifecycle_persistence(e2e_env):
    """Verify that workflow sessions maintain active taint across pause, restart, and resumption."""
    gateway1 = e2e_env["gateway"]
    db = e2e_env["db"]
    docs_dir = e2e_env["docs_dir"]

    session_id = f"e2e_session_{uuid.uuid4().hex[:8]}"
    analyst = Subject(
        subject_id="analyst",
        name="Analyst",
        role="analyst",
        clearance=ClassificationLevel.CONFIDENTIAL,
        compartments=["FINANCE"],
    )

    # 1. Initialize session and read Confidential Document
    gateway1.create_session(session_id, analyst)
    res_read = gateway1.execute(
        ActionRequest(
            request_id="wf_read_1",
            action_type=ActionType.READ_DOCUMENT,
            subject=analyst,
            session_id=session_id,
            target_resource="confidential_merger.txt",
            payload={"document_id": "confidential_merger.txt"},
        )
    )
    assert res_read["success"] is True

    # 2. Checkpoint session
    gateway1.pause_session(session_id)

    # 3. Simulate process shutdown and reboot (new Gateway instance from SQLite)
    gateway2 = AgentGate(db=db, base_dir=str(docs_dir))
    resumed = gateway2.resume_session(session_id)
    assert resumed.status == "ACTIVE"
    assert resumed.highest_active_classification == ClassificationLevel.CONFIDENTIAL
    assert "confidential_merger.txt" in resumed.loaded_document_ids

    # 4. Attempt to deliver an unclassified/plain message to external recipient in this session
    # Even though body does not mention secrets, the session is TAINTED with CONFIDENTIAL context!
    leak_proposal = ActionRequest(
        request_id="wf_leak_tainted_context",
        action_type=ActionType.DELIVER_INBOX,
        subject=analyst,
        session_id=session_id,
        target_resource="inbox:leak@adversary.org",
        payload={
            "recipient_id": "adversary",
            "recipient_address": "leak@adversary.org",
            "subject": "Greetings",
            "body": "Just checking in.",
        },
    )

    res_tainted_leak = gateway2.execute(leak_proposal)
    # MUST BE BLOCKED: Tainted session cannot leak to external destinations!
    assert res_tainted_leak["success"] is False
    assert res_tainted_leak["decision"] == "BLOCK"
    assert "Information-flow restriction violation" in res_tainted_leak["reason"]


# ==============================================================================
# PHASE 5: PROMPT INJECTION MITIGATION VERIFICATION
# ==============================================================================

def test_e2e_prompt_injection_killchain(e2e_env):
    """Simulate a complete 3-step prompt injection attack and verify the gateway halts each unauthorized step."""
    gateway = e2e_env["gateway"]
    untrusted_llm = Subject(
        subject_id="autonomous_agent",
        name="Auto Agent",
        role="agent",
        clearance=ClassificationLevel.INTERNAL,
        compartments=[],
    )

    # Step 1: LLM processes untrusted invoice
    s1 = gateway.execute(
        ActionRequest(
            request_id="pi_step_1",
            action_type=ActionType.READ_DOCUMENT,
            subject=untrusted_llm,
            target_resource="untrusted_vendor_invoice.txt",
            payload={"document_id": "untrusted_vendor_invoice.txt"},
        )
    )
    assert s1["success"] is True  # Invoice is public, reading is allowed

    # Step 2: Injected prompt commands LLM to access KMS master keys
    s2 = gateway.execute(
        ActionRequest(
            request_id="pi_step_2_keys",
            action_type=ActionType.READ_DOCUMENT,
            subject=untrusted_llm,
            target_resource="restricted_keys.txt",
            payload={"document_id": "restricted_keys.txt"},
        )
    )
    # BLOCKED: LLM lacks RESTRICTED clearance and SECURITY compartment
    assert s2["success"] is False
    assert s2["decision"] == "BLOCK"
    assert s2["data"] is None

    # Step 3: Injected prompt commands LLM to exfiltrate to adversary
    s3 = gateway.execute(
        ActionRequest(
            request_id="pi_step_3_leak",
            action_type=ActionType.DELIVER_INBOX,
            subject=untrusted_llm,
            target_resource="inbox:hacker@darkweb.io",
            payload={
                "recipient_id": "hacker",
                "recipient_address": "hacker@darkweb.io",
                "subject": "Exfiltrated System Info",
                "body": "Exfiltrated content.",
            },
        )
    )
    # BLOCKED: External delivery is blocked
    assert s3["success"] is False
    assert s3["decision"] == "BLOCK"


# ==============================================================================
# PHASE 6: AUDIT TRAIL INTEGRITY & NON-REPUDIATION
# ==============================================================================

def test_e2e_audit_trail_invariants(e2e_env):
    """Verify that every single evaluated request generates a corresponding immutable audit event."""
    gateway = e2e_env["gateway"]
    db = e2e_env["db"]

    # Initial audit count
    initial_events = db.get_audit_events(limit=500)
    initial_count = len(initial_events)

    # Execute 3 actions: 1 allowed, 2 blocked
    subject = Subject(subject_id="auditor", name="Auditor", role="analyst", clearance=ClassificationLevel.INTERNAL)

    # Action 1: Allowed read
    gateway.execute(
        ActionRequest(
            request_id="audit_check_1",
            action_type=ActionType.READ_DOCUMENT,
            subject=subject,
            target_resource="public_handbook.txt",
            payload={"document_id": "public_handbook.txt"},
        )
    )

    # Action 2: Blocked read
    gateway.execute(
        ActionRequest(
            request_id="audit_check_2",
            action_type=ActionType.READ_DOCUMENT,
            subject=subject,
            target_resource="restricted_keys.txt",
            payload={"document_id": "restricted_keys.txt"},
        )
    )

    # Action 3: Blocked external delivery
    gateway.execute(
        ActionRequest(
            request_id="audit_check_3",
            action_type=ActionType.DELIVER_INBOX,
            subject=subject,
            target_resource="inbox:leak@test.com",
            payload={
                "recipient_id": "leak",
                "recipient_address": "leak@test.com",
                "subject": "Test",
                "body": "Body",
                "attached_document_ids": ["internal_roadmap.txt"],
            },
        )
    )

    # Verify audit entries
    new_events = db.get_audit_events(limit=500)
    assert len(new_events) > initial_count

    # Check each event has non-empty fields
    for evt in new_events:
        assert evt["event_id"].startswith("evt_")
        assert evt["timestamp"] is not None
        assert evt["subject_id"] is not None
        assert evt["action_type"] in ["read_document", "save_report", "deliver_inbox", "create_session", "pause_session", "resume_session"]
        assert evt["decision"] in ["ALLOW", "BLOCK", "SUCCESS", "FAILURE", "ERROR"]
        assert len(evt["reason"]) > 0

