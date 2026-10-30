"""AGENTGATE: Zero-Trust Security Gateway for AI Actions and Information-Flow Control."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from agentgate.core.policy_engine import PolicyEngine
from agentgate.db.database import AgentGateDB
from agentgate.models.action import ActionRequest, ActionType
from agentgate.models.audit import (
    AuditEvent,
    AuthorizationDecision,
    DecisionType,
    WorkflowSessionState,
)
from agentgate.models.security import (
    ClassificationLevel,
    ProvenanceMetadata,
    SecurityLabel,
    Subject,
)
from agentgate.tools.doc_reader import DocumentReaderTool
from agentgate.tools.mock_inbox import MockInboxDeliveryTool
from agentgate.tools.report_saver import ReportSaverTool


class AuthorizationBlockedException(Exception):
    """Exception raised when an action is blocked by AGENTGATE."""

    def __init__(self, decision: AuthorizationDecision):
        self.decision = decision
        super().__init__(f"Action BLOCKED: {decision.reason}")


class AgentGate:
    """The central security gateway intercepting all tool proposals before execution."""

    def __init__(
        self,
        db: Optional[AgentGateDB] = None,
        policy_engine: Optional[PolicyEngine] = None,
        base_dir: Optional[str] = None,
    ):
        self.db = db or AgentGateDB()
        self.policy_engine = policy_engine or PolicyEngine()

        # Initialize the three protected tools
        self.doc_reader = DocumentReaderTool(self.db, base_dir=base_dir)
        self.report_saver = ReportSaverTool(self.db)
        self.mock_inbox = MockInboxDeliveryTool(self.db)

    # --- Workflow Session Management ---

    def create_session(self, session_id: str, subject: Subject) -> WorkflowSessionState:
        """Create a new workflow session context."""
        session = WorkflowSessionState(
            session_id=session_id,
            active_subject_id=subject.subject_id,
            loaded_document_ids=[],
            highest_active_classification=ClassificationLevel.PUBLIC,
            active_compartments=[],
            status="ACTIVE",
        )
        self.db.save_workflow_session(session)
        self._record_audit(
            event_type="WORKFLOW_CREATE",
            session_id=session_id,
            subject_id=subject.subject_id,
            action_type="create_session",
            decision="SUCCESS",
            target_resource=session_id,
            classification=session.highest_active_classification.value,
            reason=f"New workflow session '{session_id}' initialized for subject '{subject.subject_id}'",
        )
        return session

    def pause_session(self, session_id: str) -> Optional[WorkflowSessionState]:
        """Pause and checkpoint an active workflow session."""
        session = self.db.get_workflow_session(session_id)
        if session:
            session.status = "PAUSED"
            session.updated_at = datetime.now(timezone.utc)
            self.db.save_workflow_session(session)
            self._record_audit(
                event_type="WORKFLOW_PAUSE",
                session_id=session_id,
                subject_id=session.active_subject_id,
                action_type="pause_session",
                decision="SUCCESS",
                target_resource=session_id,
                classification=session.highest_active_classification.value,
                reason=f"Workflow session '{session_id}' checkpointed and paused",
            )
        return session

    def resume_session(self, session_id: str) -> Optional[WorkflowSessionState]:
        """Resume a workflow session, restoring its tainted labels and security restrictions."""
        session = self.db.get_workflow_session(session_id)
        if session:
            session.status = "ACTIVE"
            session.updated_at = datetime.now(timezone.utc)
            self.db.save_workflow_session(session)
            self._record_audit(
                event_type="WORKFLOW_RESUME",
                session_id=session_id,
                subject_id=session.active_subject_id,
                action_type="resume_session",
                decision="SUCCESS",
                target_resource=session_id,
                classification=session.highest_active_classification.value,
                reason=(
                    f"Workflow session '{session_id}' resumed with persistent classification "
                    f"'{session.highest_active_classification.value}' and {len(session.loaded_document_ids)} active documents"
                ),
            )
        return session

    # --- Gateway Evaluation & Enforcement ---

    def evaluate_request(self, request: ActionRequest) -> AuthorizationDecision:
        """Evaluate an action request against policies and security labels without executing tools."""
        # 1. Fetch existing labels for target and sources
        target_label = self.db.get_security_label(request.target_resource)

        source_labels: Dict[str, SecurityLabel] = {}
        session_taint = ClassificationLevel.PUBLIC

        # Load session state if session_id is provided
        if request.session_id:
            session = self.db.get_workflow_session(request.session_id)
            if session:
                session_taint = session.highest_active_classification
                for doc_id in session.loaded_document_ids:
                    lbl = self.db.get_security_label(doc_id)
                    if lbl:
                        source_labels[doc_id] = lbl

        # Also load explicit tainted sources from request
        for src_id in request.tainted_by_sources:
            lbl = self.db.get_security_label(src_id)
            if lbl:
                source_labels[src_id] = lbl

        # If saving report, load labels of source documents specified in payload
        if request.action_type == ActionType.SAVE_REPORT:
            save_payload = request.get_save_payload()
            for src_id in save_payload.source_document_ids:
                lbl = self.db.get_security_label(src_id)
                if lbl:
                    source_labels[src_id] = lbl

        # If delivering inbox, load labels of attached documents
        if request.action_type == ActionType.DELIVER_INBOX:
            deliv_payload = request.get_deliver_payload()
            for doc_id in deliv_payload.attached_document_ids:
                lbl = self.db.get_security_label(doc_id)
                if lbl:
                    source_labels[doc_id] = lbl

        # 2. Run Policy Engine evaluation
        eval_result = self.policy_engine.evaluate(
            request=request,
            target_label=target_label,
            source_labels=source_labels,
            session_taint_level=session_taint,
        )

        decision_id = f"dec_{uuid.uuid4().hex[:12]}"
        decision_type = DecisionType.ALLOW if eval_result.is_allowed else DecisionType.BLOCK

        recipient_addr = None
        if request.action_type == ActionType.DELIVER_INBOX:
            recipient_addr = request.get_deliver_payload().recipient_address

        decision = AuthorizationDecision(
            decision_id=decision_id,
            request_id=request.request_id,
            decision=decision_type,
            action_type=request.action_type,
            subject_id=request.subject.subject_id,
            subject_role=request.subject.role,
            target_resource=request.target_resource,
            recipient_address=recipient_addr,
            enforced_classification=eval_result.enforced_classification,
            reason=eval_result.decision_reason,
            matched_rule_id=eval_result.matched_rule_id,
            timestamp=datetime.now(timezone.utc),
        )

        # 3. Record immutable audit event
        self._record_audit(
            event_type="AUTHORIZATION_DECISION",
            session_id=request.session_id,
            subject_id=request.subject.subject_id,
            action_type=request.action_type.value,
            decision=decision_type.value,
            target_resource=request.target_resource,
            classification=eval_result.enforced_classification.value,
            reason=eval_result.decision_reason,
            details={
                "decision_id": decision_id,
                "request_id": request.request_id,
                "matched_rule_id": eval_result.matched_rule_id,
                "violation_code": eval_result.violation_code,
                "recipient": recipient_addr,
            },
        )

        return decision

    def execute(self, request: ActionRequest) -> Dict[str, Any]:
        """Intercept and evaluate action proposal. If authorized, dispatch to protected tool."""
        # Step 1: Intercept and evaluate
        decision = self.evaluate_request(request)

        # Step 2: Strict enforcement - Block unauthorized actions before execution
        if decision.decision == DecisionType.BLOCK:
            # Under NO circumstances does the underlying tool execute when blocked!
            return {
                "success": False,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "enforced_classification": decision.enforced_classification.value,
                "data": None,
                "audit_recorded": True,
            }

        # Step 3: Action is authorized -> Execute protected tool
        tool_result: Dict[str, Any] = {}
        try:
            if request.action_type == ActionType.READ_DOCUMENT:
                read_payload = request.get_read_payload()
                tool_result = self.doc_reader.execute(read_payload)

                # Taint propagation into session context
                if request.session_id:
                    self._update_session_taint(
                        request.session_id,
                        doc_id=read_payload.document_id,
                        doc_classification=decision.enforced_classification,
                        compartments=tool_result.get("compartments", []),
                    )

            elif request.action_type == ActionType.SAVE_REPORT:
                save_payload = request.get_save_payload()

                # Construct inherited security label
                inherited_label = SecurityLabel(
                    classification=decision.enforced_classification,
                    compartments=[],
                    provenance=ProvenanceMetadata(
                        source_id=save_payload.report_id,
                        source_classification=decision.enforced_classification,
                        derived_from=save_payload.source_document_ids,
                        transformations=["ai_analysis", "summarized"],
                        created_at=datetime.now(timezone.utc),
                    ),
                )
                tool_result = self.report_saver.execute(save_payload, inherited_label)

                # Add report to session context if applicable
                if request.session_id:
                    self._update_session_taint(
                        request.session_id,
                        doc_id=save_payload.report_id,
                        doc_classification=decision.enforced_classification,
                        compartments=[],
                    )

            elif request.action_type == ActionType.DELIVER_INBOX:
                deliv_payload = request.get_deliver_payload()
                tool_result = self.mock_inbox.execute(
                    payload=deliv_payload,
                    sender_id=request.subject.subject_id,
                    enforced_classification=decision.enforced_classification,
                )

            # Record tool execution success in audit trail
            self._record_audit(
                event_type="TOOL_EXECUTE_SUCCESS",
                session_id=request.session_id,
                subject_id=request.subject.subject_id,
                action_type=request.action_type.value,
                decision="SUCCESS",
                target_resource=request.target_resource,
                classification=decision.enforced_classification.value,
                reason=f"Protected tool '{request.action_type.value}' executed successfully",
                details=tool_result,
            )

            return {
                "success": True,
                "decision": decision.decision.value,
                "reason": decision.reason,
                "enforced_classification": decision.enforced_classification.value,
                "data": tool_result,
                "audit_recorded": True,
            }

        except Exception as e:
            self._record_audit(
                event_type="TOOL_EXECUTE_ERROR",
                session_id=request.session_id,
                subject_id=request.subject.subject_id,
                action_type=request.action_type.value,
                decision="ERROR",
                target_resource=request.target_resource,
                classification=decision.enforced_classification.value,
                reason=f"Tool execution failed with exception: {str(e)}",
                details={"error": str(e)},
            )
            raise

    # --- Internal Helpers ---

    def _update_session_taint(
        self,
        session_id: str,
        doc_id: str,
        doc_classification: ClassificationLevel,
        compartments: List[str],
    ) -> None:
        """Update workflow session taint level and active documents."""
        session = self.db.get_workflow_session(session_id)
        if session:
            if doc_id not in session.loaded_document_ids:
                session.loaded_document_ids.append(doc_id)
            if doc_classification > session.highest_active_classification:
                session.highest_active_classification = doc_classification
            for c in compartments:
                if c not in session.active_compartments:
                    session.active_compartments.append(c)
            session.updated_at = datetime.now(timezone.utc)
            self.db.save_workflow_session(session)

    def _record_audit(
        self,
        event_type: str,
        session_id: Optional[str],
        subject_id: str,
        action_type: str,
        decision: str,
        target_resource: str,
        classification: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        event = AuditEvent(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            session_id=session_id,
            subject_id=subject_id,
            action_type=action_type,
            decision=decision,
            target_resource=target_resource,
            classification=classification,
            reason=reason,
            details=details or {},
        )
        self.db.record_audit_event(event)

