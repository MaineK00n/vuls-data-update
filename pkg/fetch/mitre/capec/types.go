package capec

import (
	"encoding/json/jsontext"
	"time"
)

// Field shapes follow the STIX 2.1 OASIS specification
// (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).
// STIX-required fields are modeled as value types; STIX-optional
// fields use *T / []T so that a missing property stays distinguishable
// from a present-but-zero value during parsing. omitempty then drops
// nil/empty fields when re-encoding each object to disk.
//
// Not modeled (complex nested or CAPEC-unused): granular_markings,
// extensions, kill_chain_phases, and the RESERVED course-of-action
// action_type / os_execution_envs / action_bin / action_reference.

// bundle is the top-level STIX bundle returned by CAPEC. Used only
// during fetch to split the bundle into per-object files.
type bundle struct {
	Type    string           `json:"type"`
	ID      string           `json:"id"`
	Objects []jsontext.Value `json:"objects"`
}

// object is the minimal envelope used to discriminate STIX object types
// before decoding into a concrete struct.
type object struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// ExternalReference is the STIX external_reference embedded object.
type ExternalReference struct {
	Description *string `json:"description,omitempty"`
	ExternalID  *string `json:"external_id,omitempty"`
	SourceName  string  `json:"source_name"`
	URL         *string `json:"url,omitempty"`
}

// SkillsRequired is the STIX x_capec_skills_required nested object.
type SkillsRequired struct {
	High   *string `json:"High,omitempty"`
	Low    *string `json:"Low,omitempty"`
	Medium *string `json:"Medium,omitempty"`
}

// AttackPattern represents a STIX 2.1 attack-pattern SDO with CAPEC
// custom properties. Per STIX 2.1, "name" became optional (was required
// in 2.0); CAPEC always provides it but we model it as pointer to match
// the spec.
type AttackPattern struct {
	Type                      string              `json:"type"`
	ID                        string              `json:"id"`
	Aliases                   []string            `json:"aliases,omitempty"`
	Confidence                *int                `json:"confidence,omitempty"`
	Created                   time.Time           `json:"created"`
	CreatedByRef              *string             `json:"created_by_ref,omitempty"`
	Description               *string             `json:"description,omitempty"`
	ExternalReferences        []ExternalReference `json:"external_references,omitempty"`
	Labels                    []string            `json:"labels,omitempty"`
	Lang                      *string             `json:"lang,omitempty"`
	Modified                  time.Time           `json:"modified"`
	Name                      *string             `json:"name,omitempty"`
	ObjectMarkingRefs         []string            `json:"object_marking_refs,omitempty"`
	Revoked                   *bool               `json:"revoked,omitempty"`
	SpecVersion               string              `json:"spec_version"`
	XCapecAbstraction         *string             `json:"x_capec_abstraction,omitempty"`
	XCapecAlternateTerms      []string            `json:"x_capec_alternate_terms,omitempty"`
	XCapecCanFollowRefs       []string            `json:"x_capec_can_follow_refs,omitempty"`
	XCapecCanPrecedeRefs      []string            `json:"x_capec_can_precede_refs,omitempty"`
	XCapecChildOfRefs         []string            `json:"x_capec_child_of_refs,omitempty"`
	XCapecConsequences        map[string][]string `json:"x_capec_consequences,omitempty"`
	XCapecDomains             []string            `json:"x_capec_domains,omitempty"`
	XCapecExampleInstances    []string            `json:"x_capec_example_instances,omitempty"`
	XCapecExecutionFlow       *string             `json:"x_capec_execution_flow,omitempty"`
	XCapecExtendedDescription *string             `json:"x_capec_extended_description,omitempty"`
	XCapecLikelihoodOfAttack  *string             `json:"x_capec_likelihood_of_attack,omitempty"`
	XCapecParentOfRefs        []string            `json:"x_capec_parent_of_refs,omitempty"`
	XCapecPeerOfRefs          []string            `json:"x_capec_peer_of_refs,omitempty"`
	XCapecPrerequisites       []string            `json:"x_capec_prerequisites,omitempty"`
	XCapecResourcesRequired   []string            `json:"x_capec_resources_required,omitempty"`
	XCapecSkillsRequired      *SkillsRequired     `json:"x_capec_skills_required,omitempty"`
	XCapecStatus              *string             `json:"x_capec_status,omitempty"`
	XCapecTypicalSeverity     *string             `json:"x_capec_typical_severity,omitempty"`
	XCapecVersion             *string             `json:"x_capec_version,omitempty"`
}

// CourseOfAction represents a STIX 2.1 course-of-action SDO (CAPEC
// mitigation). "name" is optional in STIX 2.1.
type CourseOfAction struct {
	Type               string              `json:"type"`
	ID                 string              `json:"id"`
	Confidence         *int                `json:"confidence,omitempty"`
	Created            time.Time           `json:"created"`
	CreatedByRef       *string             `json:"created_by_ref,omitempty"`
	Description        *string             `json:"description,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	Labels             []string            `json:"labels,omitempty"`
	Lang               *string             `json:"lang,omitempty"`
	Modified           time.Time           `json:"modified"`
	Name               *string             `json:"name,omitempty"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs,omitempty"`
	Revoked            *bool               `json:"revoked,omitempty"`
	SpecVersion        string              `json:"spec_version"`
	XCapecVersion      *string             `json:"x_capec_version,omitempty"`
}

// Relationship represents a STIX 2.1 SRO. relationship_type, source_ref
// and target_ref are required for SROs.
type Relationship struct {
	Type               string              `json:"type"`
	ID                 string              `json:"id"`
	Confidence         *int                `json:"confidence,omitempty"`
	Created            time.Time           `json:"created"`
	CreatedByRef       *string             `json:"created_by_ref,omitempty"`
	Description        *string             `json:"description,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	Labels             []string            `json:"labels,omitempty"`
	Lang               *string             `json:"lang,omitempty"`
	Modified           time.Time           `json:"modified"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs,omitempty"`
	RelationshipType   string              `json:"relationship_type"`
	Revoked            *bool               `json:"revoked,omitempty"`
	SourceRef          string              `json:"source_ref"`
	SpecVersion        string              `json:"spec_version"`
	StartTime          *time.Time          `json:"start_time,omitempty"`
	StopTime           *time.Time          `json:"stop_time,omitempty"`
	TargetRef          string              `json:"target_ref"`
	XCapecVersion      *string             `json:"x_capec_version,omitempty"`
}

// Identity represents a STIX 2.1 identity SDO. "name" is required.
type Identity struct {
	Type               string              `json:"type"`
	ID                 string              `json:"id"`
	Confidence         *int                `json:"confidence,omitempty"`
	ContactInformation *string             `json:"contact_information,omitempty"`
	Created            time.Time           `json:"created"`
	CreatedByRef       *string             `json:"created_by_ref,omitempty"`
	Description        *string             `json:"description,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	IdentityClass      *string             `json:"identity_class,omitempty"`
	Labels             []string            `json:"labels,omitempty"`
	Lang               *string             `json:"lang,omitempty"`
	Modified           time.Time           `json:"modified"`
	Name               string              `json:"name"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs,omitempty"`
	Revoked            *bool               `json:"revoked,omitempty"`
	Roles              []string            `json:"roles,omitempty"`
	Sectors            []string            `json:"sectors,omitempty"`
	SpecVersion        string              `json:"spec_version"`
}

// MarkingDefinition represents a STIX 2.1 marking-definition. It is not
// an SDO and has no modified/revoked/labels/confidence/lang. CAPEC uses
// the legacy definition_type + definition (statement) form rather than
// v2.1 extensions, but both fields are technically optional per spec.
type MarkingDefinition struct {
	Type               string              `json:"type"`
	ID                 string              `json:"id"`
	Created            time.Time           `json:"created"`
	CreatedByRef       *string             `json:"created_by_ref,omitempty"`
	Definition         *MarkingStatement   `json:"definition,omitempty"`
	DefinitionType     *string             `json:"definition_type,omitempty"`
	ExternalReferences []ExternalReference `json:"external_references,omitempty"`
	Name               *string             `json:"name,omitempty"`
	ObjectMarkingRefs  []string            `json:"object_marking_refs,omitempty"`
	SpecVersion        string              `json:"spec_version"`
}

// MarkingStatement is the legacy statement-marking object referenced by
// MarkingDefinition.Definition when DefinitionType == "statement".
type MarkingStatement struct {
	Statement string `json:"statement"`
}
