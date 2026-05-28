package attack

import (
	"encoding/json/jsontext"
	"time"
)

// Field shapes follow the STIX 2.1 OASIS specification
// (https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html) plus
// MITRE ATT&CK's x_mitre_* extensions. STIX-required fields are modeled
// as value types; STIX-optional fields use *T / []T so a missing
// property stays distinguishable from a present-but-zero value during
// parsing. omitempty then drops nil/empty fields when re-encoding each
// object to disk.

// bundle is the top-level STIX bundle returned for each ATT&CK domain.
// Used only during fetch to split the bundle into per-object files.
type bundle struct {
	Type        string           `json:"type"`
	ID          string           `json:"id"`
	SpecVersion string           `json:"spec_version"`
	Objects     []jsontext.Value `json:"objects"`
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

// KillChainPhase is the STIX kill_chain_phase embedded object.
type KillChainPhase struct {
	KillChainName string `json:"kill_chain_name"`
	PhaseName     string `json:"phase_name"`
}

// MarkingStatement is the legacy statement-marking object referenced by
// MarkingDefinition.Definition when DefinitionType == "statement".
type MarkingStatement struct {
	Statement string `json:"statement"`
}

// LogSource is the embedded x_mitre_log_sources entry on
// AttackPattern and XMitreDataComponent.
type LogSource struct {
	Name    string `json:"name"`
	Channel string `json:"channel"`
}

// LogSourceReference is the embedded x_mitre_log_source_references entry
// on AttackPattern and XMitreAnalytic.
type LogSourceReference struct {
	XMitreDataComponentRef string `json:"x_mitre_data_component_ref"`
	Name                   string `json:"name"`
	Channel                string `json:"channel"`
}

// MutableElement is the embedded x_mitre_mutable_elements entry on
// AttackPattern and XMitreAnalytic.
type MutableElement struct {
	Field       string `json:"field"`
	Description string `json:"description"`
}

// CollectionContent is the embedded x_mitre_contents entry on
// XMitreCollection.
type CollectionContent struct {
	ObjectModified time.Time `json:"object_modified"`
	ObjectRef      string    `json:"object_ref"`
}

// RelatedAsset is the embedded x_mitre_related_assets entry on
// XMitreAsset.
type RelatedAsset struct {
	Description         string   `json:"description,omitempty"`
	Name                string   `json:"name"`
	RelatedAssetSectors []string `json:"related_asset_sectors,omitempty"`
}

// AttackPattern represents a STIX 2.1 attack-pattern (ATT&CK Technique).
type AttackPattern struct {
	Type                       string               `json:"type"`
	ID                         string               `json:"id"`
	Created                    time.Time            `json:"created"`
	CreatedByRef               *string              `json:"created_by_ref,omitempty"`
	Description                *string              `json:"description,omitempty"`
	ExternalReferences         []ExternalReference  `json:"external_references,omitempty"`
	KillChainPhases            []KillChainPhase     `json:"kill_chain_phases,omitempty"`
	Labels                     []string             `json:"labels,omitempty"`
	Modified                   time.Time            `json:"modified"`
	Name                       *string              `json:"name,omitempty"`
	ObjectMarkingRefs          []string             `json:"object_marking_refs,omitempty"`
	Revoked                    *bool                `json:"revoked,omitempty"`
	SpecVersion                string               `json:"spec_version"`
	TacticRefs                 []string             `json:"tactic_refs,omitempty"`
	XMitreAnalyticRefs         []string             `json:"x_mitre_analytic_refs,omitempty"`
	XMitreAttackSpecVersion    string               `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors         []string             `json:"x_mitre_contributors,omitempty"`
	XMitreDataSources          []string             `json:"x_mitre_data_sources,omitempty"`
	XMitreDefenseBypassed      []string             `json:"x_mitre_defense_bypassed,omitempty"`
	XMitreDeprecated           *bool                `json:"x_mitre_deprecated,omitempty"`
	XMitreDetection            *string              `json:"x_mitre_detection,omitempty"`
	XMitreDomains              []string             `json:"x_mitre_domains,omitempty"`
	XMitreEffectivePermissions []string             `json:"x_mitre_effective_permissions,omitempty"`
	XMitreImpactType           []string             `json:"x_mitre_impact_type,omitempty"`
	XMitreIsSubtechnique       *bool                `json:"x_mitre_is_subtechnique,omitempty"`
	XMitreLogSourceReferences  []LogSourceReference `json:"x_mitre_log_source_references,omitempty"`
	XMitreLogSources           []LogSource          `json:"x_mitre_log_sources,omitempty"`
	XMitreModifiedByRef        *string              `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreMutableElements      []MutableElement     `json:"x_mitre_mutable_elements,omitempty"`
	XMitreNetworkRequirements  *bool                `json:"x_mitre_network_requirements,omitempty"`
	XMitrePermissionsRequired  []string             `json:"x_mitre_permissions_required,omitempty"`
	XMitrePlatforms            []string             `json:"x_mitre_platforms,omitempty"`
	XMitreRemoteSupport        *bool                `json:"x_mitre_remote_support,omitempty"`
	XMitreSystemRequirements   []string             `json:"x_mitre_system_requirements,omitempty"`
	XMitreTacticType           []string             `json:"x_mitre_tactic_type,omitempty"`
	XMitreVersion              *string              `json:"x_mitre_version,omitempty"`
}

// Campaign represents a STIX 2.1 campaign object.
type Campaign struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Aliases                 []string            `json:"aliases,omitempty"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	FirstSeen               *time.Time          `json:"first_seen,omitempty"`
	LastSeen                *time.Time          `json:"last_seen,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreFirstSeenCitation *string             `json:"x_mitre_first_seen_citation,omitempty"`
	XMitreLastSeenCitation  *string             `json:"x_mitre_last_seen_citation,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// CourseOfAction represents a STIX 2.1 course-of-action object
// (ATT&CK Mitigation).
type CourseOfAction struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Labels                  []string            `json:"labels,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreOldAttackID       *string             `json:"x_mitre_old_attack_id,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// IntrusionSet represents a STIX 2.1 intrusion-set object (ATT&CK Group).
type IntrusionSet struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Aliases                 []string            `json:"aliases,omitempty"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	FirstSeen               *time.Time          `json:"first_seen,omitempty"`
	LastSeen                *time.Time          `json:"last_seen,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAliases           []string            `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreFirstSeenCitation *string             `json:"x_mitre_first_seen_citation,omitempty"`
	XMitreLastSeenCitation  *string             `json:"x_mitre_last_seen_citation,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// Malware represents a STIX 2.1 malware object (ATT&CK Software).
type Malware struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Aliases                 []string            `json:"aliases,omitempty"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	IsFamily                *bool               `json:"is_family,omitempty"`
	Labels                  []string            `json:"labels,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAliases           []string            `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreOldAttackID       *string             `json:"x_mitre_old_attack_id,omitempty"`
	XMitrePlatforms         []string            `json:"x_mitre_platforms,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// Tool represents a STIX 2.1 tool object (ATT&CK Software). Structurally
// identical to Malware except the absence of is_family.
type Tool struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Aliases                 []string            `json:"aliases,omitempty"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Labels                  []string            `json:"labels,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAliases           []string            `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreOldAttackID       *string             `json:"x_mitre_old_attack_id,omitempty"`
	XMitrePlatforms         []string            `json:"x_mitre_platforms,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// Relationship represents a STIX 2.1 SRO. relationship_type, source_ref
// and target_ref are required for SROs.
type Relationship struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	RelationshipType        string              `json:"relationship_type"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SourceRef               string              `json:"source_ref"`
	SpecVersion             string              `json:"spec_version"`
	TargetRef               string              `json:"target_ref"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreTactic represents an ATT&CK Tactic (custom STIX type).
type XMitreTactic struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	SpecVersion             string              `json:"spec_version"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreShortname         *string             `json:"x_mitre_shortname,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// Identity represents a STIX 2.1 identity SDO. ATT&CK's identity objects
// omit spec_version.
type Identity struct {
	Type                    string    `json:"type"`
	ID                      string    `json:"id"`
	Created                 time.Time `json:"created"`
	IdentityClass           *string   `json:"identity_class,omitempty"`
	Modified                time.Time `json:"modified"`
	Name                    string    `json:"name"`
	ObjectMarkingRefs       []string  `json:"object_marking_refs,omitempty"`
	XMitreAttackSpecVersion string    `json:"x_mitre_attack_spec_version,omitempty"`
}

// MarkingDefinition represents a STIX 2.1 marking-definition. ATT&CK uses
// the legacy definition_type + definition (statement) form. STIX 2.1
// marking-definition has no modified field, and ATT&CK's instances also
// omit spec_version.
type MarkingDefinition struct {
	Type           string            `json:"type"`
	ID             string            `json:"id"`
	Created        time.Time         `json:"created"`
	CreatedByRef   *string           `json:"created_by_ref,omitempty"`
	Definition     *MarkingStatement `json:"definition,omitempty"`
	DefinitionType *string           `json:"definition_type,omitempty"`
}

// XMitreAnalytic represents ATT&CK's x-mitre-analytic custom object.
type XMitreAnalytic struct {
	Type                      string               `json:"type"`
	ID                        string               `json:"id"`
	Created                   time.Time            `json:"created"`
	CreatedByRef              *string              `json:"created_by_ref,omitempty"`
	Description               *string              `json:"description,omitempty"`
	ExternalReferences        []ExternalReference  `json:"external_references,omitempty"`
	Modified                  time.Time            `json:"modified"`
	Name                      *string              `json:"name,omitempty"`
	ObjectMarkingRefs         []string             `json:"object_marking_refs,omitempty"`
	Revoked                   *bool                `json:"revoked,omitempty"`
	XMitreAttackSpecVersion   string               `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDeprecated          *bool                `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains             []string             `json:"x_mitre_domains,omitempty"`
	XMitreLogSourceReferences []LogSourceReference `json:"x_mitre_log_source_references,omitempty"`
	XMitreModifiedByRef       *string              `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreMutableElements     []MutableElement     `json:"x_mitre_mutable_elements,omitempty"`
	XMitrePlatforms           []string             `json:"x_mitre_platforms,omitempty"`
	XMitreVersion             *string              `json:"x_mitre_version,omitempty"`
}

// XMitreAsset represents ATT&CK's x-mitre-asset custom object (ICS only).
type XMitreAsset struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitrePlatforms         []string            `json:"x_mitre_platforms,omitempty"`
	XMitreRelatedAssets     []RelatedAsset      `json:"x_mitre_related_assets,omitempty"`
	XMitreSectors           []string            `json:"x_mitre_sectors,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreCollection represents ATT&CK's x-mitre-collection custom object
// that describes a domain's content set.
type XMitreCollection struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	SpecVersion             string              `json:"spec_version,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreContents          []CollectionContent `json:"x_mitre_contents,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreDataComponent represents ATT&CK's x-mitre-data-component object.
type XMitreDataComponent struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDataSourceRef     *string             `json:"x_mitre_data_source_ref,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreLogSources        []LogSource         `json:"x_mitre_log_sources,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreDataSource represents ATT&CK's x-mitre-data-source object.
type XMitreDataSource struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreCollectionLayers  []string            `json:"x_mitre_collection_layers,omitempty"`
	XMitreContributors      []string            `json:"x_mitre_contributors,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitrePlatforms         []string            `json:"x_mitre_platforms,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreDetectionStrategy represents ATT&CK's x-mitre-detection-strategy
// object that ties analytics to attack-patterns.
type XMitreDetectionStrategy struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	XMitreAnalyticRefs      []string            `json:"x_mitre_analytic_refs,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreDomains           []string            `json:"x_mitre_domains,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}

// XMitreMatrix represents ATT&CK's x-mitre-matrix custom object that
// describes the kill chain matrix for a domain.
type XMitreMatrix struct {
	Type                    string              `json:"type"`
	ID                      string              `json:"id"`
	Created                 time.Time           `json:"created"`
	CreatedByRef            *string             `json:"created_by_ref,omitempty"`
	Description             *string             `json:"description,omitempty"`
	ExternalReferences      []ExternalReference `json:"external_references,omitempty"`
	Modified                time.Time           `json:"modified"`
	Name                    *string             `json:"name,omitempty"`
	ObjectMarkingRefs       []string            `json:"object_marking_refs,omitempty"`
	Revoked                 *bool               `json:"revoked,omitempty"`
	TacticRefs              []string            `json:"tactic_refs,omitempty"`
	XMitreAttackSpecVersion string              `json:"x_mitre_attack_spec_version,omitempty"`
	XMitreDeprecated        *bool               `json:"x_mitre_deprecated,omitempty"`
	XMitreModifiedByRef     *string             `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreVersion           *string             `json:"x_mitre_version,omitempty"`
}
