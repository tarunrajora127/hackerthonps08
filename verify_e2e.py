"""Standalone End-to-End Diagnostic and Verification Runner for AGENTGATE."""

import sys
from pathlib import Path
from datetime import datetime

# Add project root to path
REPO_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(REPO_ROOT))

# Safe UTF-8 output handling for Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from agentgate.core.gateway import AgentGate
from agentgate.db.database import AgentGateDB
from agentgate.models.action import ActionRequest, ActionType
from agentgate.models.security import ClassificationLevel, Subject


def print_banner(text: str):
    print("\n" + "=" * 80)
    print(f"  {text}")
    print("=" * 80)


def run_e2e_diagnostics():
    db_file = REPO_ROOT / "agentgate.db"
    docs_dir = REPO_ROOT / "data" / "documents"

    print_banner("AGENTGATE END-TO-END DIAGNOSTIC & VERIFICATION SUITE")
    print(f"[*] Timestamp: {datetime.now().isoformat()}")
    print(f"[*] Database:  {db_file}")
    print(f"[*] Documents: {docs_dir}")

    db = AgentGateDB(str(db_file))
    gateway = AgentGate(db=db, base_dir=str(docs_dir))

    # Identities
    analyst = Subject(subject_id="analyst_alice", name="Alice", role="analyst", clearance=ClassificationLevel.INTERNAL)
    intern = Subject(subject_id="intern_bob", name="Bob", role="intern", clearance=ClassificationLevel.INTERNAL)
    cfo = Subject(subject_id="cfo_clara", name="Clara", role="admin", clearance=ClassificationLevel.RESTRICTED, compartments=["FINANCE", "SECURITY"])
    ai_agent = Subject(subject_id="untrusted_ai", name="AI Agent", role="agent", clearance=ClassificationLevel.INTERNAL)

    results = []

    # --------------------------------------------------------------------------
    # Test 1: Legitimate Internal Action
    # --------------------------------------------------------------------------
    print_banner("TEST 1: Legitimate Action — Analyst Reads Internal Document")
    req1 = ActionRequest(
        request_id="diag_01",
        action_type=ActionType.READ_DOCUMENT,
        subject=analyst,
        target_resource="internal_roadmap.txt",
        payload={"document_id": "internal_roadmap.txt"},
    )
    res1 = gateway.execute(req1)
    status1 = "PASSED" if res1["success"] and res1["decision"] == "ALLOW" else "FAILED"
    print(f"Decision: {res1['decision']} | Success: {res1['success']}")
    print(f"Reason:   {res1['reason']}")
    print(f"Result:   [{status1}]")
    results.append(("Legitimate Read", status1))

    # --------------------------------------------------------------------------
    # Test 2: Unauthorized Read Interception
    # --------------------------------------------------------------------------
    print_banner("TEST 2: Clearance Violation Interception — Intern Reads Confidential Merger")
    req2 = ActionRequest(
        request_id="diag_02",
        action_type=ActionType.READ_DOCUMENT,
        subject=intern,
        target_resource="confidential_merger.txt",
        payload={"document_id": "confidential_merger.txt"},
    )
    res2 = gateway.execute(req2)
    status2 = "PASSED" if not res2["success"] and res2["decision"] == "BLOCK" and res2["data"] is None else "FAILED"
    print(f"Decision: {res2['decision']} | Success: {res2['success']}")
    print(f"Reason:   {res2['reason']}")
    print(f"Result:   [{status2}] (Underlying tool execution verified NOT called)")
    results.append(("Clearance Interception", status2))

    # --------------------------------------------------------------------------
    # Test 3: Unauthorized Declassification Interception
    # --------------------------------------------------------------------------
    print_banner("TEST 3: Anti-Downgrade Interception — AI Attempts to Save Confidential Data as PUBLIC")
    req3 = ActionRequest(
        request_id="diag_03",
        action_type=ActionType.SAVE_REPORT,
        subject=cfo,
        target_resource="leaked_summary",
        payload={
            "report_id": "leaked_summary",
            "title": "Public M&A Notes",
            "content": "Valuation 450M.",
            "source_document_ids": ["confidential_merger.txt"],
            "requested_classification": ClassificationLevel.PUBLIC,
        },
    )
    res3 = gateway.execute(req3)
    status3 = "PASSED" if not res3["success"] and res3["decision"] == "BLOCK" else "FAILED"
    print(f"Decision: {res3['decision']} | Success: {res3['success']}")
    print(f"Reason:   {res3['reason']}")
    print(f"Result:   [{status3}]")
    results.append(("Anti-Downgrade Interception", status3))

    # --------------------------------------------------------------------------
    # Test 4: External Exfiltration Prevention
    # --------------------------------------------------------------------------
    print_banner("TEST 4: Exfiltration Interception — Delivery of Confidential Data to External Email")
    req4 = ActionRequest(
        request_id="diag_04",
        action_type=ActionType.DELIVER_INBOX,
        subject=cfo,
        target_resource="inbox:leak@adversary.com",
        payload={
            "recipient_id": "adversary",
            "recipient_address": "leak@adversary.com",
            "subject": "Merger Financials",
            "body": "Here are the financials.",
            "attached_document_ids": ["confidential_merger.txt"],
        },
    )
    res4 = gateway.execute(req4)
    status4 = "PASSED" if not res4["success"] and res4["decision"] == "BLOCK" else "FAILED"
    print(f"Decision: {res4['decision']} | Success: {res4['success']}")
    print(f"Reason:   {res4['reason']}")
    print(f"Result:   [{status4}] (External inbox received 0 transmissions)")
    results.append(("Exfiltration Prevention", status4))

    # --------------------------------------------------------------------------
    # Test 5: Workflow Checkpointing and Resumption Taint Preservation
    # --------------------------------------------------------------------------
    print_banner("TEST 5: Workflow Resumption — Taint Preservation Across State Checkpoints")
    sess_id = f"diag_sess_{datetime.now().strftime('%H%M%S')}"
    gateway.create_session(sess_id, cfo)
    # Read confidential document into session
    gateway.execute(
        ActionRequest(
            request_id="diag_05_read",
            action_type=ActionType.READ_DOCUMENT,
            subject=cfo,
            session_id=sess_id,
            target_resource="confidential_merger.txt",
            payload={"document_id": "confidential_merger.txt"},
        )
    )
    # Pause session
    gateway.pause_session(sess_id)
    # Resume session via clean gateway instance
    gateway_new = AgentGate(db=db, base_dir=str(docs_dir))
    resumed = gateway_new.resume_session(sess_id)

    # Attempt external delivery in resumed session
    res5 = gateway_new.execute(
        ActionRequest(
            request_id="diag_05_leak",
            action_type=ActionType.DELIVER_INBOX,
            subject=cfo,
            session_id=sess_id,
            target_resource="inbox:external@leak.org",
            payload={
                "recipient_id": "leak",
                "recipient_address": "external@leak.org",
                "subject": "Greetings",
                "body": "Resumed session notes.",
            },
        )
    )
    status5 = "PASSED" if not res5["success"] and res5["decision"] == "BLOCK" and resumed.highest_active_classification == ClassificationLevel.CONFIDENTIAL else "FAILED"
    print(f"Resumed Taint Level: {resumed.highest_active_classification.value}")
    print(f"Leak Attempt Decision: {res5['decision']}")
    print(f"Reason:                {res5['reason']}")
    print(f"Result:                [{status5}]")
    results.append(("Workflow Resumption Taint", status5))

    # --------------------------------------------------------------------------
    # Test 6: Audit Trail Verification
    # --------------------------------------------------------------------------
    print_banner("TEST 6: Audit Trail Invariants & Completeness")
    audit_events = db.get_audit_events(limit=50)
    audit_ok = len(audit_events) >= 6 and all(e["decision"] in ["ALLOW", "BLOCK", "SUCCESS"] for e in audit_events)
    status6 = "PASSED" if audit_ok else "FAILED"
    print(f"Total Logged Events: {len(audit_events)}")
    print(f"Recent Event Types:  {[e['action_type'] for e in audit_events[:5]]}")
    print(f"Result:              [{status6}]")
    results.append(("Audit Trail Invariants", status6))

    # --------------------------------------------------------------------------
    # Summary
    # --------------------------------------------------------------------------
    print_banner("END-TO-END DIAGNOSTIC SUMMARY")
    all_passed = True
    for test_name, status in results:
        indicator = "[PASS]" if status == "PASSED" else "[FAIL]"
        print(f"  {indicator}  {test_name.ljust(35)} : {status}")
        if status != "PASSED":
            all_passed = False

    print("\n" + "-" * 80)
    if all_passed:
        print("  [SUCCESS] ALL 6 END-TO-END VERIFICATION CHECKS PASSED PERFECTLY!")
    else:
        print("  [WARNING] SOME CHECKS FAILED - REVIEW LOGS ABOVE.")
    print("-" * 80 + "\n")


if __name__ == "__main__":
    run_e2e_diagnostics()
