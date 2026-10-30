"""Policy engine enforcing authorization, Bell-LaPadula multilevel security, and information flow."""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Set
from agentgate.models.action import (
    ActionRequest,
    ActionType,
    DeliverInboxPayload,
    ReadDocumentPayload,
    SaveReportPayload,
)
from agentgate.models.policy import (
    PolicyEffect,
    PolicyEvaluationResult,
    PolicyRule,
    PolicySet,
)
from agentgate.models.security import (
    ClassificationLevel,
    SecurityLabel,
    Subject,
)


def get_default_enterprise_policy() -> PolicySet:
    """Standard enterprise policy implementing Bell-LaPadula and information-flow restrictions."""
    return PolicySet(
        policy_id="enterprise_v1",
        name="Enterprise Information-Flow & Access Policy",
        default_effect=PolicyEffect.DENY,
        rules=[
            # 1. Document Reading Rules
            PolicyRule(
                rule_id="RULE_READ_AUTHORIZED",
                description="Allow subjects to read documents matching or below their clearance",
                priority=10,
                subject_roles=["*"],
                action_types=[ActionType.READ_DOCUMENT],
                target_resource_pattern="*",
                effect=PolicyEffect.ALLOW,
            ),
            # 2. Report Saving Rules
            PolicyRule(
                rule_id="RULE_SAVE_REPORT_AUTHORIZED",
                description="Allow saving reports that preserve source classification without unauthorized declassification",
                priority=20,
                subject_roles=["analyst", "agent", "admin", "auditor"],
                action_types=[ActionType.SAVE_REPORT],
                target_resource_pattern="*",
                effect=PolicyEffect.ALLOW,
            ),
            # 3. Internal Delivery Rules
            PolicyRule(
                rule_id="RULE_DELIVER_INTERNAL",
                description="Allow delivery of internal and public information to corporate inboxes",
                priority=30,
                subject_roles=["analyst", "agent", "admin"],
                action_types=[ActionType.DELIVER_INBOX],
                target_resource_pattern="*",
                max_classification_allowed=ClassificationLevel.INTERNAL,
                allowed_recipient_domains=["@company.com", "@syntaxis.internal", "@corp.local"],
                block_external_delivery=True,
                effect=PolicyEffect.ALLOW,
            ),
            # 4. Confidential Delivery Rules (requires authorized recipient domain)
            PolicyRule(
                rule_id="RULE_DELIVER_CONFIDENTIAL_INTERNAL_ONLY",
                description="Deliver confidential documents only to verified executive/internal recipients",
                priority=35,
                subject_roles=["analyst", "admin"],
                action_types=[ActionType.DELIVER_INBOX],
                target_resource_pattern="*",
                max_classification_allowed=ClassificationLevel.CONFIDENTIAL,
                allowed_recipient_domains=["@company.com", "@syntaxis.internal"],
                block_external_delivery=True,
                effect=PolicyEffect.ALLOW,
            ),
        ],
    )


class PolicyEngine:
    """Evaluates proposed actions against security labels, clearance levels, and policy sets."""

    def __init__(self, policy_set: Optional[PolicySet] = None):
        self.policy_set = policy_set or get_default_enterprise_policy()

    def evaluate(
        self,
        request: ActionRequest,
        target_label: Optional[SecurityLabel] = None,
        source_labels: Optional[Dict[str, SecurityLabel]] = None,
        session_taint_level: ClassificationLevel = ClassificationLevel.PUBLIC,
    ) -> PolicyEvaluationResult:
        """Evaluate an ActionRequest and return an auditable PolicyEvaluationResult."""
        source_labels = source_labels or {}
        subject = request.subject

        if request.action_type == ActionType.READ_DOCUMENT:
            return self._evaluate_read(request, subject, target_label)
        elif request.action_type == ActionType.SAVE_REPORT:
            return self._evaluate_save(request, subject, source_labels, session_taint_level)
        elif request.action_type == ActionType.DELIVER_INBOX:
            return self._evaluate_deliver(request, subject, source_labels, session_taint_level)
        else:
            return PolicyEvaluationResult(
                is_allowed=False,
                decision_reason=f"Unsupported action type '{request.action_type}'",
                enforced_classification=ClassificationLevel.RESTRICTED,
                violation_code="UNSUPPORTED_ACTION",
            )

    def _evaluate_read(
        self,
        request: ActionRequest,
        subject: Subject,
        target_label: Optional[SecurityLabel],
    ) -> PolicyEvaluationResult:
        doc_classification = target_label.classification if target_label else ClassificationLevel.INTERNAL

        # Bell-LaPadula Simple Security Property: No read up
        if subject.clearance < doc_classification:
            return PolicyEvaluationResult(
                is_allowed=False,
                matched_rule_id="RULE_BELL_LAPADULA_NO_READ_UP",
                decision_reason=(
                    f"BLOCKED: Clearance violation. Subject '{subject.subject_id}' "
                    f"has clearance '{subject.clearance.value}', but document '{request.target_resource}' "
                    f"is classified as '{doc_classification.value}'."
                ),
                enforced_classification=doc_classification,
                violation_code="INSUFFICIENT_CLEARANCE",
            )

        # Compartment authorization check
        if target_label and target_label.compartments:
            missing_compartments = set(target_label.compartments) - set(subject.compartments)
            if missing_compartments:
                return PolicyEvaluationResult(
                    is_allowed=False,
                    matched_rule_id="RULE_COMPARTMENT_MISMATCH",
                    decision_reason=(
                        f"BLOCKED: Subject '{subject.subject_id}' lacks required compartments: "
                        f"{sorted(list(missing_compartments))}."
                    ),
                    enforced_classification=doc_classification,
                    violation_code="MISSING_COMPARTMENTS",
                )

        return PolicyEvaluationResult(
            is_allowed=True,
            matched_rule_id="RULE_READ_AUTHORIZED",
            decision_reason=(
                f"AUTHORIZED: Subject '{subject.subject_id}' (Clearance: {subject.clearance.value}) "
                f"is authorized to read '{request.target_resource}' (Classification: {doc_classification.value})."
            ),
            enforced_classification=doc_classification,
        )

    def _evaluate_save(
        self,
        request: ActionRequest,
        subject: Subject,
        source_labels: Dict[str, SecurityLabel],
        session_taint_level: ClassificationLevel,
    ) -> PolicyEvaluationResult:
        payload = request.get_save_payload()

        # Calculate effective required classification (supremum of all source docs and session taint)
        effective_classification = session_taint_level
        for doc_id, label in source_labels.items():
            if label.classification > effective_classification:
                effective_classification = label.classification

        # Check for unauthorized declassification attempt
        if payload.requested_classification is not None:
            if payload.requested_classification < effective_classification:
                return PolicyEvaluationResult(
                    is_allowed=False,
                    matched_rule_id="RULE_PREVENT_UNAUTHORIZED_DECLASSIFICATION",
                    decision_reason=(
                        f"BLOCKED: Unauthorized declassification detected! Proposed report classification "
                        f"'{payload.requested_classification.value}' is lower than required source classification "
                        f"'{effective_classification.value}'. Summarization or saving cannot downgrade security labels."
                    ),
                    enforced_classification=effective_classification,
                    violation_code="UNAUTHORIZED_DECLASSIFICATION",
                )

        # Check if subject is cleared to produce artifacts at this level (*-property)
        if subject.clearance < effective_classification:
            return PolicyEvaluationResult(
                is_allowed=False,
                matched_rule_id="RULE_INSUFFICIENT_CREATOR_CLEARANCE",
                decision_reason=(
                    f"BLOCKED: Subject '{subject.subject_id}' has clearance '{subject.clearance.value}' "
                    f"which is insufficient to manage '{effective_classification.value}' data."
                ),
                enforced_classification=effective_classification,
                violation_code="INSUFFICIENT_CREATOR_CLEARANCE",
            )

        return PolicyEvaluationResult(
            is_allowed=True,
            matched_rule_id="RULE_SAVE_REPORT_AUTHORIZED",
            decision_reason=(
                f"AUTHORIZED: Report '{payload.report_id}' approved for saving with persistent "
                f"classification '{effective_classification.value}' derived from {len(source_labels)} sources."
            ),
            enforced_classification=effective_classification,
        )

    def _evaluate_deliver(
        self,
        request: ActionRequest,
        subject: Subject,
        source_labels: Dict[str, SecurityLabel],
        session_taint_level: ClassificationLevel,
    ) -> PolicyEvaluationResult:
        payload = request.get_deliver_payload()
        recipient_addr = payload.recipient_address.lower().strip()

        # 1. Determine effective sensitivity of the payload / attached content
        effective_classification = session_taint_level
        for doc_id, label in source_labels.items():
            if label.classification > effective_classification:
                effective_classification = label.classification

        # Check for confidential keywords in body as DLP heuristic
        body_lower = payload.body.lower()
        if "confidential" in body_lower or "proprietary" in body_lower or "merger" in body_lower:
            if effective_classification < ClassificationLevel.CONFIDENTIAL:
                effective_classification = ClassificationLevel.CONFIDENTIAL

        # 2. Check corporate domain authorization
        is_corporate_recipient = any(
            recipient_addr.endswith(domain)
            for domain in ["@company.com", "@syntaxis.internal", "@corp.local", "@agency.gov"]
        )

        # 3. Enforcement of external delivery boundary
        if not is_corporate_recipient:
            # External delivery is strictly forbidden for INTERNAL, CONFIDENTIAL, and RESTRICTED data
            if effective_classification > ClassificationLevel.PUBLIC:
                return PolicyEvaluationResult(
                    is_allowed=False,
                    matched_rule_id="RULE_BLOCK_EXTERNAL_SENSITIVE_DELIVERY",
                    decision_reason=(
                        f"BLOCKED: Information-flow restriction violation! Cannot deliver data classified as "
                        f"'{effective_classification.value}' to external recipient '{recipient_addr}'. "
                        f"External delivery is restricted exclusively to PUBLIC data."
                    ),
                    enforced_classification=effective_classification,
                    violation_code="EXTERNAL_LEAK_PREVENTED",
                )

        # 4. Check policy rules for matching delivery permissions
        for rule in sorted(self.policy_set.rules, key=lambda r: r.priority):
            if ActionType.DELIVER_INBOX in rule.action_types or not rule.action_types:
                # Check classification ceiling of the rule
                if rule.max_classification_allowed is not None:
                    if effective_classification > rule.max_classification_allowed:
                        continue  # Rule ceiling too low, keep evaluating

                # Check recipient domains if restricted
                if rule.allowed_recipient_domains:
                    if not any(recipient_addr.endswith(d) for d in rule.allowed_recipient_domains):
                        continue

                # Matched rule
                if rule.effect == PolicyEffect.ALLOW:
                    return PolicyEvaluationResult(
                        is_allowed=True,
                        matched_rule_id=rule.rule_id,
                        decision_reason=(
                            f"AUTHORIZED: Delivery to '{recipient_addr}' permitted under rule '{rule.rule_id}' "
                            f"(Content sensitivity: '{effective_classification.value}')."
                        ),
                        enforced_classification=effective_classification,
                    )
                else:
                    return PolicyEvaluationResult(
                        is_allowed=False,
                        matched_rule_id=rule.rule_id,
                        decision_reason=f"BLOCKED by explicit deny rule '{rule.rule_id}'.",
                        enforced_classification=effective_classification,
                        violation_code="EXPLICIT_DENY_RULE",
                    )

        # Zero-trust fallback: Default Deny
        return PolicyEvaluationResult(
            is_allowed=False,
            matched_rule_id="RULE_DEFAULT_DENY",
            decision_reason=(
                f"BLOCKED: No authorizing policy rule found for delivery of "
                f"'{effective_classification.value}' content to '{recipient_addr}'. Default-Deny enforced."
            ),
            enforced_classification=effective_classification,
            violation_code="DEFAULT_DENY",
        )

