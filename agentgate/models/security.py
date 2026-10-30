"""Security classifications, clearances, provenance metadata, and security labels."""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, field_validator


class ClassificationLevel(str, Enum):
    """Hierarchical sensitivity classification levels (Bell-LaPadula lattice)."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"

    @property
    def level(self) -> int:
        levels = {
            ClassificationLevel.PUBLIC: 0,
            ClassificationLevel.INTERNAL: 1,
            ClassificationLevel.CONFIDENTIAL: 2,
            ClassificationLevel.RESTRICTED: 3,
        }
        return levels[self]

    def __ge__(self, other: ClassificationLevel) -> bool:
        if isinstance(other, ClassificationLevel):
            return self.level >= other.level
        return NotImplemented

    def __gt__(self, other: ClassificationLevel) -> bool:
        if isinstance(other, ClassificationLevel):
            return self.level > other.level
        return NotImplemented

    def __le__(self, other: ClassificationLevel) -> bool:
        if isinstance(other, ClassificationLevel):
            return self.level <= other.level
        return NotImplemented

    def __lt__(self, other: ClassificationLevel) -> bool:
        if isinstance(other, ClassificationLevel):
            return self.level < other.level
        return NotImplemented


# Clearance level maps directly to the same classification lattice
ClearanceLevel = ClassificationLevel


class Subject(BaseModel):
    """Identity requesting or executing an action."""
    subject_id: str = Field(..., description="Unique subject identifier (user, agent, system)")
    name: str = Field(..., description="Display name of the subject")
    role: str = Field(..., description="Role assigned (e.g., analyst, agent, admin, guest)")
    clearance: ClearanceLevel = Field(
        default=ClassificationLevel.INTERNAL,
        description="Maximum security classification this subject is cleared to access",
    )
    compartments: List[str] = Field(
        default_factory=list,
        description="Security compartments/categories permitted (e.g. HR, FINANCE)",
    )
    is_external: bool = Field(
        default=False,
        description="Whether this subject is an external party (e.g. external recipient/client)",
    )


class ProvenanceMetadata(BaseModel):
    """Origin, lineage, and transformation history of an information asset."""
    source_id: str = Field(..., description="Primary identifier of source artifact")
    source_uri: Optional[str] = Field(None, description="Path or URI of source document")
    source_classification: ClassificationLevel = Field(
        default=ClassificationLevel.INTERNAL,
        description="Original classification of source document",
    )
    derived_from: List[str] = Field(
        default_factory=list,
        description="List of document IDs or hashes contributing to this artifact",
    )
    transformations: List[str] = Field(
        default_factory=list,
        description="Sequence of operations applied (e.g., summarized, translated, filtered)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Creation timestamp in UTC",
    )
    content_sha256: Optional[str] = Field(
        None, description="SHA256 checksum of document content"
    )


class SecurityLabel(BaseModel):
    """Persistent security classification and provenance tag attached to artifacts."""
    classification: ClassificationLevel = Field(
        default=ClassificationLevel.INTERNAL,
        description="Current classification level",
    )
    compartments: List[str] = Field(
        default_factory=list,
        description="Compartments required to read this artifact",
    )
    provenance: Optional[ProvenanceMetadata] = Field(
        None, description="Lineage metadata for tracking provenance"
    )
    declassification_authorized_by: Optional[str] = Field(
        None, description="Identity of authority that modified or declassified label"
    )

    def combine_with(self, other: SecurityLabel) -> SecurityLabel:
        """Combine two security labels taking the supremum (highest sensitivity)

        and merging provenance lineage.
        """
        # Highest classification level
        combined_classification = (
            self.classification if self.classification >= other.classification else other.classification
        )

        # Union of compartments
        combined_compartments = sorted(list(set(self.compartments + other.compartments)))

        # Merge derived provenance
        derived: List[str] = []
        if self.provenance:
            derived.append(self.provenance.source_id)
            derived.extend(self.provenance.derived_from)
        if other.provenance:
            derived.append(other.provenance.source_id)
            derived.extend(other.provenance.derived_from)
        unique_derived = sorted(list(set(derived)))

        combined_provenance = ProvenanceMetadata(
            source_id=f"derived_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            source_classification=combined_classification,
            derived_from=unique_derived,
            transformations=["merged_sources"],
            created_at=datetime.now(timezone.utc),
        )

        return SecurityLabel(
            classification=combined_classification,
            compartments=combined_compartments,
            provenance=combined_provenance,
        )

