"""Policy structures, rules, and evaluation results."""

from __future__ import annotations
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field
from agentgate.models.action import ActionType
from agentgate.models.security import ClassificationLevel


class PolicyEffect(str, Enum):
    """Authorization outcome for a rule."""
    ALLOW = "ALLOW"
    DENY = "DENY"


class PolicyRule(BaseModel):
    """Explicit authorization rule evaluated by AGENTGATE."""
    rule_id: str = Field(..., description="Unique rule identifier")
    description: str = Field(..., description="Human-readable description of rule purpose")
    priority: int = Field(default=100, description="Evaluation priority (lower numbers evaluate earlier)")
    subject_roles: List[str] = Field(
        default_factory=lambda: ["*"],
        description="List of roles this rule applies to ('*' matches all)",
    )
    action_types: List[ActionType] = Field(
        default_factory=list,
        description="Action types governed by this rule",
    )
    target_resource_pattern: str = Field(
        default="*",
        description="Resource pattern or prefix ('*' matches all)",
    )
    max_classification_allowed: Optional[ClassificationLevel] = Field(
        None,
        description="Maximum classification level permitted for this operation",
    )
    allowed_recipient_domains: List[str] = Field(
        default_factory=list,
        description="Allowed recipient domain suffixes (e.g. '@acme.internal')",
    )
    block_external_delivery: bool = Field(
        default=False,
        description="Strictly block any delivery to external or unvetted recipients",
    )
    allow_declassification: bool = Field(
        default=False,
        description="Whether this rule permits explicitly downgrading a security classification",
    )
    effect: PolicyEffect = Field(
        default=PolicyEffect.ALLOW,
        description="Effect applied if all rule conditions are satisfied",
    )


class PolicySet(BaseModel):
    """Complete collection of active authorization policies."""
    policy_id: str = Field(default="default_policy_v1", description="Policy configuration identifier")
    name: str = Field(default="Standard Enterprise Policy", description="Friendly policy name")
    default_effect: PolicyEffect = Field(
        default=PolicyEffect.DENY,
        description="Default zero-trust fallback if no rule explicitly matches",
    )
    rules: List[PolicyRule] = Field(
        default_factory=list,
        description="Ordered list of policy rules",
    )


class PolicyEvaluationResult(BaseModel):
    """Result of evaluating a proposed action against the policy set."""
    is_allowed: bool = Field(..., description="Whether the action was approved for execution")
    matched_rule_id: Optional[str] = Field(None, description="Rule ID that determined the outcome")
    decision_reason: str = Field(..., description="Auditable explanation for why action was allowed or blocked")
    enforced_classification: ClassificationLevel = Field(
        ..., description="Effective security classification calculated for the operation"
    )
    violation_code: Optional[str] = Field(
        None, description="Machine-readable violation tag (e.g., INSUFFICIENT_CLEARANCE, UNAUTHORIZED_RECIPIENT)"
    )

