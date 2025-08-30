package capec

import "time"

type capec struct {
	ID      string  `json:"id"`
	Type    string  `json:"type"`
	Objects []Capec `json:"objects"`
}

type Capec struct {
	Type         string    `json:"type"`
	ID           string    `json:"id"`
	Created      time.Time `json:"created"`
	CreatedByRef *string   `json:"created_by_ref,omitempty"`
	Definition   *struct {
		Statement string `json:"statement"`
	} `json:"definition,omitempty"`
	DefinitionType     *string `json:"definition_type,omitempty"`
	Description        *string `json:"description,omitempty"`
	ExternalReferences []struct {
		Description *string `json:"description,omitempty"`
		ExternalID  *string `json:"external_id,omitempty"`
		SourceName  string  `json:"source_name"`
		URL         *string `json:"url,omitempty"`
	} `json:"external_references,omitempty"`
	IdentityClass             *string             `json:"identity_class,omitempty"`
	Modified                  *time.Time          `json:"modified,omitempty"`
	Name                      *string             `json:"name,omitempty"`
	ObjectMarkingRefs         []string            `json:"object_marking_refs,omitempty"`
	RelationshipType          *string             `json:"relationship_type,omitempty"`
	SourceRef                 *string             `json:"source_ref,omitempty"`
	SpecVersion               string              `json:"spec_version"`
	TargetRef                 *string             `json:"target_ref,omitempty"`
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
	XCapecSkillsRequired      *struct {
		High   *string `json:"High,omitempty"`
		Low    *string `json:"Low,omitempty"`
		Medium *string `json:"Medium,omitempty"`
	} `json:"x_capec_skills_required,omitempty"`
	XCapecStatus          *string `json:"x_capec_status,omitempty"`
	XCapecTypicalSeverity *string `json:"x_capec_typical_severity,omitempty"`
	XCapecVersion         *string `json:"x_capec_version,omitempty"`
}
