package attack

import (
	"time"
)

type enterprise struct {
	Type        string       `json:"type"`
	ID          string       `json:"id"`
	SpecVersion string       `json:"spec_version"`
	Objects     []Enterprise `json:"objects"`
}

type Enterprise struct {
	Type         string    `json:"type"`
	ID           string    `json:"id"`
	Aliases      []string  `json:"aliases,omitempty"`
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
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	IdentityClass   *string    `json:"identity_class,omitempty"`
	IsFamily        *bool      `json:"is_family,omitempty"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases,omitempty"`
	LastSeen                *time.Time `json:"last_seen,omitempty"`
	Modified                *time.Time `json:"modified,omitempty"`
	Name                    *string    `json:"name,omitempty"`
	ObjectMarkingRefs       []string   `json:"object_marking_refs,omitempty"`
	RelationshipType        *string    `json:"relationship_type,omitempty"`
	Revoked                 *bool      `json:"revoked,omitempty"`
	SourceRef               *string    `json:"source_ref,omitempty"`
	SpecVersion             string     `json:"spec_version"`
	TacticRefs              []string   `json:"tactic_refs,omitempty"`
	TargetRef               *string    `json:"target_ref,omitempty"`
	XMitreAliases           []string   `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string     `json:"x_mitre_attack_spec_version"`
	XMitreCollectionLayers  []string   `json:"x_mitre_collection_layers,omitempty"`
	XMitreContents          []struct {
		ObjectModified time.Time `json:"object_modified"`
		ObjectRef      string    `json:"object_ref"`
	} `json:"x_mitre_contents,omitempty"`
	XMitreContributors         []string `json:"x_mitre_contributors,omitempty"`
	XMitreDataSourceRef        *string  `json:"x_mitre_data_source_ref,omitempty"`
	XMitreDataSources          []string `json:"x_mitre_data_sources,omitempty"`
	XMitreDefenseBypassed      []string `json:"x_mitre_defense_bypassed,omitempty"`
	XMitreDeprecated           *bool    `json:"x_mitre_deprecated,omitempty"`
	XMitreDetection            *string  `json:"x_mitre_detection,omitempty"`
	XMitreDomains              []string `json:"x_mitre_domains,omitempty"`
	XMitreEffectivePermissions []string `json:"x_mitre_effective_permissions,omitempty"`
	XMitreFirstSeenCitation    *string  `json:"x_mitre_first_seen_citation,omitempty"`
	XMitreImpactType           []string `json:"x_mitre_impact_type,omitempty"`
	XMitreIsSubtechnique       *bool    `json:"x_mitre_is_subtechnique,omitempty"`
	XMitreLastSeenCitation     *string  `json:"x_mitre_last_seen_citation,omitempty"`
	XMitreModifiedByRef        *string  `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreNetworkRequirements  *bool    `json:"x_mitre_network_requirements,omitempty"`
	XMitrePermissionsRequired  []string `json:"x_mitre_permissions_required,omitempty"`
	XMitrePlatforms            []string `json:"x_mitre_platforms,omitempty"`
	XMitreRemoteSupport        *bool    `json:"x_mitre_remote_support,omitempty"`
	XMitreShortname            *string  `json:"x_mitre_shortname,omitempty"`
	XMitreSystemRequirements   []string `json:"x_mitre_system_requirements,omitempty"`
	XMitreVersion              *string  `json:"x_mitre_version,omitempty"`
}

type ics struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	SpecVersion string `json:"spec_version"`
	Objects     []ICS  `json:"objects"`
}

type ICS struct {
	Type         string    `json:"type"`
	ID           string    `json:"id"`
	Aliases      []string  `json:"aliases,omitempty"`
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
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	IdentityClass   *string    `json:"identity_class,omitempty"`
	IsFamily        *bool      `json:"is_family,omitempty"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases,omitempty"`
	Labels                  []string   `json:"labels,omitempty"`
	LastSeen                *time.Time `json:"last_seen,omitempty"`
	Modified                *time.Time `json:"modified,omitempty"`
	Name                    *string    `json:"name,omitempty"`
	ObjectMarkingRefs       []string   `json:"object_marking_refs,omitempty"`
	RelationshipType        *string    `json:"relationship_type,omitempty"`
	Revoked                 *bool      `json:"revoked,omitempty"`
	SourceRef               *string    `json:"source_ref,omitempty"`
	SpecVersion             string     `json:"spec_version"`
	TacticRefs              []string   `json:"tactic_refs,omitempty"`
	TargetRef               *string    `json:"target_ref,omitempty"`
	XMitreAliases           []string   `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string     `json:"x_mitre_attack_spec_version"`
	XMitreCollectionLayers  []string   `json:"x_mitre_collection_layers,omitempty"`
	XMitreContents          []struct {
		ObjectModified time.Time `json:"object_modified"`
		ObjectRef      string    `json:"object_ref"`
	} `json:"x_mitre_contents,omitempty"`
	XMitreContributors        []string `json:"x_mitre_contributors,omitempty"`
	XMitreDataSourceRef       *string  `json:"x_mitre_data_source_ref,omitempty"`
	XMitreDataSources         []string `json:"x_mitre_data_sources,omitempty"`
	XMitreDeprecated          *bool    `json:"x_mitre_deprecated,omitempty"`
	XMitreDetection           *string  `json:"x_mitre_detection,omitempty"`
	XMitreDomains             []string `json:"x_mitre_domains,omitempty"`
	XMitreFirstSeenCitation   *string  `json:"x_mitre_first_seen_citation,omitempty"`
	XMitreIsSubtechnique      *bool    `json:"x_mitre_is_subtechnique,omitempty"`
	XMitreLastSeenCitation    *string  `json:"x_mitre_last_seen_citation,omitempty"`
	XMitreModifiedByRef       *string  `json:"x_mitre_modified_by_ref,omitempty"`
	XMitrePermissionsRequired []string `json:"x_mitre_permissions_required,omitempty"`
	XMitrePlatforms           []string `json:"x_mitre_platforms,omitempty"`
	XMitreRelatedAssets       []struct {
		Description         string   `json:"description"`
		Name                string   `json:"name"`
		RelatedAssetSectors []string `json:"related_asset_sectors"`
	} `json:"x_mitre_related_assets,omitempty"`
	XMitreSectors   []string `json:"x_mitre_sectors,omitempty"`
	XMitreShortname *string  `json:"x_mitre_shortname,omitempty"`
	XMitreVersion   *string  `json:"x_mitre_version,omitempty"`
}

type mobile struct {
	Type        string   `json:"type"`
	ID          string   `json:"id"`
	SpecVersion string   `json:"spec_version"`
	Objects     []Mobile `json:"objects"`
}

type Mobile struct {
	Type         string    `json:"type"`
	ID           string    `json:"id"`
	Aliases      []string  `json:"aliases,omitempty"`
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
	FirstSeen       *time.Time `json:"first_seen,omitempty"`
	IdentityClass   *string    `json:"identity_class,omitempty"`
	IsFamily        *bool      `json:"is_family,omitempty"`
	KillChainPhases []struct {
		KillChainName string `json:"kill_chain_name"`
		PhaseName     string `json:"phase_name"`
	} `json:"kill_chain_phases,omitempty"`
	LastSeen                *time.Time `json:"last_seen,omitempty"`
	Modified                *time.Time `json:"modified,omitempty"`
	Name                    *string    `json:"name,omitempty"`
	ObjectMarkingRefs       []string   `json:"object_marking_refs,omitempty"`
	RelationshipType        *string    `json:"relationship_type,omitempty"`
	Revoked                 *bool      `json:"revoked,omitempty"`
	SourceRef               *string    `json:"source_ref,omitempty"`
	SpecVersion             string     `json:"spec_version"`
	TacticRefs              []string   `json:"tactic_refs,omitempty"`
	TargetRef               *string    `json:"target_ref,omitempty"`
	XMitreAliases           []string   `json:"x_mitre_aliases,omitempty"`
	XMitreAttackSpecVersion string     `json:"x_mitre_attack_spec_version"`
	XMitreCollectionLayers  []string   `json:"x_mitre_collection_layers,omitempty"`
	XMitreContents          []struct {
		ObjectModified time.Time `json:"object_modified"`
		ObjectRef      string    `json:"object_ref"`
	} `json:"x_mitre_contents,omitempty"`
	XMitreContributors      []string `json:"x_mitre_contributors,omitempty"`
	XMitreDataSourceRef     *string  `json:"x_mitre_data_source_ref,omitempty"`
	XMitreDeprecated        *bool    `json:"x_mitre_deprecated,omitempty"`
	XMitreDetection         *string  `json:"x_mitre_detection,omitempty"`
	XMitreDomains           []string `json:"x_mitre_domains,omitempty"`
	XMitreFirstSeenCitation *string  `json:"x_mitre_first_seen_citation,omitempty"`
	XMitreIsSubtechnique    *bool    `json:"x_mitre_is_subtechnique,omitempty"`
	XMitreLastSeenCitation  *string  `json:"x_mitre_last_seen_citation,omitempty"`
	XMitreModifiedByRef     *string  `json:"x_mitre_modified_by_ref,omitempty"`
	XMitreOldAttackID       *string  `json:"x_mitre_old_attack_id,omitempty"`
	XMitrePlatforms         []string `json:"x_mitre_platforms,omitempty"`
	XMitreShortname         *string  `json:"x_mitre_shortname,omitempty"`
	XMitreTacticType        []string `json:"x_mitre_tactic_type,omitempty"`
	XMitreVersion           *string  `json:"x_mitre_version,omitempty"`
}
