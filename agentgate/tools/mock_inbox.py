"""Protected Mock Inbox Delivery Tool."""

from __future__ import annotations
import uuid
from typing import Any, Dict, List, Optional

from agentgate.db.database import AgentGateDB
from agentgate.models.action import DeliverInboxPayload
from agentgate.models.security import ClassificationLevel


class MockInboxDeliveryTool:
    """Protected local tool for delivering reports/messages to a mock recipient inbox."""

    def __init__(self, db: AgentGateDB):
        self.db = db

    def execute(
        self,
        payload: DeliverInboxPayload,
        sender_id: str,
        enforced_classification: ClassificationLevel,
    ) -> Dict[str, Any]:
        """Execute mock inbox delivery after gateway authorization."""
        message_id = f"msg_{uuid.uuid4().hex[:12]}"

        self.db.deliver_to_mock_inbox(
            message_id=message_id,
            sender_id=sender_id,
            recipient_address=payload.recipient_address,
            subject=payload.subject,
            body=payload.body,
            enforced_classification=enforced_classification,
            attachments=payload.attached_document_ids,
        )

        return {
            "status": "DELIVERED",
            "message_id": message_id,
            "recipient_address": payload.recipient_address,
            "subject": payload.subject,
            "sender_id": sender_id,
            "enforced_classification": enforced_classification.value,
            "attachments_delivered": payload.attached_document_ids,
        }

