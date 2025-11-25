package enrichment

type Enrichment struct {
	AdditionalMetadata struct {
		CNA        string   `json:"cna,omitempty"`
		CVEID      string   `json:"cveId"`
		Ignored    bool     `json:"ignored,omitzero"`
		Reason     string   `json:"reason"`
		References []string `json:"references,omitempty"`
		Solutions  []string `json:"solutions,omitempty"`
		Upstream   struct {
			DatePublished   string `json:"datePublished,omitempty"`
			DateReserved    string `json:"dateReserved,omitempty"`
			DateUpdated     string `json:"dateUpdated,omitempty"`
			Digest          string `json:"digest,omitempty"`
			DigestAlgorithm string `json:"digest_algorithm,omitempty"`
		} `json:"upstream,omitzero"`
		NeedsReview bool `json:"needsReview,omitzero"`
		Disputed    bool `json:"disputed,omitzero"`
		Rejection   struct {
			Date   string `json:"date"`
			Reason string `json:"reason"`
		} `json:"rejection,omitzero"`
	} `json:"additionalMetadata"`
	ADP struct {
		ProviderMetadata ProviderMetadata `json:"providerMetadata"`
		Title            *string          `json:"title,omitempty"`
		Descriptions     []Description    `json:"descriptions,omitempty"`
		Affected         []Product        `json:"affected,omitempty"`
		ProblemTypes     []ProblemType    `json:"problemTypes,omitempty"`
		Impacts          []Impact         `json:"impacts,omitempty"`
		Metrics          []Metric         `json:"metrics,omitempty"`
		Workarounds      []Description    `json:"workarounds,omitempty"`
		Solutions        []Description    `json:"solutions,omitempty"`
		Exploits         []Description    `json:"exploits,omitempty"`
		Configurations   []Description    `json:"configurations,omitempty"`
		References       []Reference      `json:"references,omitempty"`
		Timeline         Timeline         `json:"timeline,omitempty"`
		Credits          Credits          `json:"credits,omitempty"`
		Source           interface{}      `json:"source,omitempty"`
		Tags             []string         `json:"tags,omitempty"`
		TaxonomyMappings TaxonomyMappings `json:"taxonomyMappings,omitzero"`
		DatePublic       *string          `json:"datePublic,omitempty"`
	} `json:"adp,omitzero"`
}

type CVEMetadata struct {
	CVEID             string  `json:"cveId"`
	AssignerOrgID     string  `json:"assignerOrgId"`
	AssignerShortName *string `json:"assignerShortName,omitempty"`
	RequesterUserID   *string `json:"requesterUserId,omitempty"`
	Serial            *int    `json:"serial,omitempty"`
	State             string  `json:"state"`
	DatePublished     *string `json:"datePublished,omitempty"`
	DateUpdated       *string `json:"dateUpdated,omitempty"`
	DateReserved      *string `json:"dateReserved,omitempty"`
	DateRejected      *string `json:"dateRejected,omitempty"`
}

type ProviderMetadata struct {
	OrgID       string  `json:"orgId"`
	ShortName   *string `json:"shortName,omitempty"`
	DateUpdated *string `json:"dateUpdated,omitempty"`
}

type Description struct {
	Lang            string `json:"lang"`
	Value           string `json:"value"`
	SupportingMedia []struct {
		Type   string `json:"type"`
		Base64 *bool  `json:"base64,omitempty"`
		Value  string `json:"value"`
	} `json:"supportingMedia,omitempty"`
}

type Product struct {
	Vendor          *string  `json:"vendor,omitempty"`
	Product         *string  `json:"product,omitempty"`
	CollectionURL   *string  `json:"collectionURL,omitempty"`
	PackageName     *string  `json:"packageName,omitempty"`
	Cpes            []string `json:"cpes,omitempty"`
	Modules         []string `json:"modules,omitempty"`
	ProgramFiles    []string `json:"programFiles,omitempty"`
	ProgramRoutines []struct {
		Name string `json:"name"`
	} `json:"programRoutines,omitempty"`
	Platforms     []string `json:"platforms,omitempty"`
	Repo          *string  `json:"repo,omitempty"`
	DefaultStatus *string  `json:"defaultStatus,omitempty"`
	Versions      []struct {
		Status          string  `json:"status"`
		VersionType     *string `json:"versionType,omitempty"`
		Version         string  `json:"version"`
		LessThan        *string `json:"lessThan,omitempty"`
		LessThanOrEqual *string `json:"lessThanOrEqual,omitempty"`
		Changes         []struct {
			At     string `json:"at"`
			Status string `json:"status"`
		} `json:"changes,omitempty"`
	} `json:"versions,omitempty"`
}

type ProblemType struct {
	Descriptions []struct {
		Type        *string     `json:"type,omitempty"`
		Lang        string      `json:"lang"`
		Description string      `json:"description"`
		CweID       *string     `json:"cweId,omitempty"`
		References  []Reference `json:"references,omitempty"`
	} `json:"descriptions"`
}

type Impact struct {
	Descriptions []Description `json:"descriptions"`
	CapecID      *string       `json:"capecId,omitempty"`
}

type Metric struct {
	Format    *string `json:"format,omitempty"`
	Scenarios []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"scenarios,omitempty"`
	CVSSv2  *CVSSv2  `json:"cvssV2_0,omitempty"`
	CVSSv30 *CVSSv30 `json:"cvssV3_0,omitempty"`
	CVSSv31 *CVSSv31 `json:"cvssV3_1,omitempty"`
	CVSSv40 *CVSSv40 `json:"cvssV4_0,omitempty"`
	Other   *struct {
		Type    string      `json:"type"`
		Content interface{} `json:"content"`
	} `json:"other,omitempty"`
}

type CVSSv2 struct {
	Version                    string   `json:"version"`
	VectorString               string   `json:"vectorString"`
	AccessVector               *string  `json:"accessVector,omitempty"`
	AccessComplexity           *string  `json:"accessComplexity,omitempty"`
	Authentication             *string  `json:"authentication,omitempty"`
	ConfidentialityImpact      *string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact            *string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact         *string  `json:"availabilityImpact,omitempty"`
	BaseScore                  float64  `json:"baseScore"`
	Exploitability             *string  `json:"exploitability,omitempty"`
	RemediationLevel           *string  `json:"remediationLevel,omitempty"`
	ReportConfidence           *string  `json:"reportConfidence,omitempty"`
	TemporalScore              *float64 `json:"temporalScore,omitempty"`
	CollateralDamagePotential  *string  `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         *string  `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement *string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement       *string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement    *string  `json:"availabilityRequirement,omitempty"`
	EnvironmentalScore         *float64 `json:"environmentalScore,omitempty"`
}

type CVSSv30 struct {
	Version                       string   `json:"version"`
	VectorString                  string   `json:"vectorString"`
	AttackVector                  *string  `json:"attackVector,omitempty"`
	AttackComplexity              *string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
	UserInteraction               *string  `json:"userInteraction,omitempty"`
	Scope                         *string  `json:"scope,omitempty"`
	ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
	BaseScore                     float64  `json:"baseScore"`
	BaseSeverity                  string   `json:"baseSeverity"`
	ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              *string  `json:"remediationLevel,omitempty"`
	ReportConfidence              *string  `json:"reportConfidence,omitempty"`
	TemporalScore                 *float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
}

type CVSSv31 struct {
	Version                       string   `json:"version"`
	VectorString                  string   `json:"vectorString"`
	AttackVector                  *string  `json:"attackVector,omitempty"`
	AttackComplexity              *string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired            *string  `json:"privilegesRequired,omitempty"`
	UserInteraction               *string  `json:"userInteraction,omitempty"`
	Scope                         *string  `json:"scope,omitempty"`
	ConfidentialityImpact         *string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               *string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            *string  `json:"availabilityImpact,omitempty"`
	BaseScore                     float64  `json:"baseScore"`
	BaseSeverity                  string   `json:"baseSeverity"`
	ExploitCodeMaturity           *string  `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              *string  `json:"remediationLevel,omitempty"`
	ReportConfidence              *string  `json:"reportConfidence,omitempty"`
	TemporalScore                 *float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              *string  `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    *string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          *string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       *string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          *string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      *string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    *string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       *string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 *string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact *string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       *string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    *string  `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         *string  `json:"environmentalSeverity,omitempty"`
}

type CVSSv40 struct {
	Version                           string   `json:"version"`
	VectorString                      string   `json:"vectorString"`
	BaseScore                         float64  `json:"baseScore"`
	BaseSeverity                      string   `json:"baseSeverity"`
	AttackVector                      *string  `json:"attackVector,omitempty"`
	AttackComplexity                  *string  `json:"attackComplexity,omitempty"`
	AttackRequirements                *string  `json:"attackRequirements,omitempty"`
	PrivilegesRequired                *string  `json:"privilegesRequired,omitempty"`
	UserInteraction                   *string  `json:"userInteraction,omitempty"`
	VulnConfidentialityImpact         *string  `json:"vulnConfidentialityImpact,omitempty"`
	VulnIntegrityImpact               *string  `json:"vulnIntegrityImpact,omitempty"`
	VulnAvailabilityImpact            *string  `json:"vulnAvailabilityImpact,omitempty"`
	SubConfidentialityImpact          *string  `json:"subConfidentialityImpact,omitempty"`
	SubIntegrityImpact                *string  `json:"subIntegrityImpact,omitempty"`
	SubAvailabilityImpact             *string  `json:"subAvailabilityImpact,omitempty"`
	ExploitMaturity                   *string  `json:"exploitMaturity,omitempty"`
	ConfidentialityRequirement        *string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement              *string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement           *string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector              *string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity          *string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedAttackRequirements        *string  `json:"modifiedAttackRequirements,omitempty"`
	ModifiedPrivilegesRequired        *string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction           *string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedVulnConfidentialityImpact *string  `json:"modifiedVulnConfidentialityImpact,omitempty"`
	ModifiedVulnIntegrityImpact       *string  `json:"modifiedVulnIntegrityImpact,omitempty"`
	ModifiedVulnAvailabilityImpact    *string  `json:"modifiedVulnAvailabilityImpact,omitempty"`
	ModifiedSubConfidentialityImpact  *string  `json:"modifiedSubConfidentialityImpact,omitempty"`
	ModifiedSubIntegrityImpact        *string  `json:"modifiedSubIntegrityImpact,omitempty"`
	ModifiedSubAvailabilityImpact     *string  `json:"modifiedSubAvailabilityImpact,omitempty"`
	Safety                            *string  `json:"Safety,omitempty"`
	Automatable                       *string  `json:"Automatable,omitempty"`
	Recovery                          *string  `json:"Recovery,omitempty"`
	ValueDensity                      *string  `json:"valueDensity,omitempty"`
	VulnerabilityResponseEffort       *string  `json:"vulnerabilityResponseEffort,omitempty"`
	ProviderUrgency                   *string  `json:"providerUrgency,omitempty"`
	ThreatScore                       *float64 `json:"threatScore,omitempty"`
	ThreatSeverity                    *string  `json:"threatSeverity,omitempty"`
	EnvironmentalScore                *float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity             *string  `json:"environmentalSeverity,omitempty"`
}

// https://github.com/CERTCC/SSVC/blob/a34a9768ef75209f8c1dd1bc2cf0523ba4d243c8/data/schema/SSVC_Computed.schema.json for other:ssvc
type SSVC struct {
	ID           string        `json:"id"`
	Role         string        `json:"role"`
	Version      string        `json:"version"`
	Schema       *string       `json:"$schema,omitempty"`
	Computed     *string       `json:"computed,omitempty"`
	Options      []interface{} `json:"options"`
	DecisionTree *struct {
		Version        string        `json:"version"`
		Lang           string        `json:"lang"`
		Title          *string       `json:"title,omitempty"`
		Roles          []string      `json:"roles,omitempty"`
		DecisionTable  []interface{} `json:"decision_table"`
		DecisionPoints []struct {
			DecisionType string  `json:"decision_type"`
			Label        string  `json:"label"`
			Key          *string `json:"key,omitempty"`
			Options      []struct {
				Label       string  `json:"label"`
				Key         *string `json:"key,omitempty"`
				Color       *string `json:"color,omitempty"`
				Description string  `json:"description"`
			} `json:"options"`
			Children []struct {
				Label string  `json:"label"`
				Key   *string `json:"key,omitempty"`
			} `json:"children,omitempty"`
		} `json:"decision_points"`
	} `json:"decision_tree,omitempty"`
	DecisionTreeURL *string `json:"decision_tree_url,omitempty"`
	Generator       *string `json:"generator,omitempty"`
	Timestamp       string  `json:"timestamp"`
}

// for other:kev
type KEV struct {
	DateAdded string `json:"date_added"`
	Reference string `json:"reference"`
}

type Reference struct {
	Name *string  `json:"name,omitempty"`
	Tags []string `json:"tags,omitempty"`
	URL  string   `json:"url"`
}

type Timeline []struct {
	Time  string `json:"time"`
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Credits []struct {
	Type  *string `json:"type,omitempty"`
	Lang  string  `json:"lang"`
	User  *string `json:"user,omitempty"`
	Value string  `json:"value"`
}

type TaxonomyMappings []struct {
	TaxonomyVersion   *string `json:"taxonomyVersion,omitempty"`
	TaxonomyName      string  `json:"taxonomyName"`
	TaxonomyRelations []struct {
		TaxonomyID        string `json:"taxonomyId"`
		RelationshipName  string `json:"relationshipName"`
		RelationshipValue string `json:"relationshipValue"`
	} `json:"taxonomyRelations"`
}
