package cve

// https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
type CVEAPI20 struct {
	ResultsPerPage  int       `json:"resultsPerPage"`
	StartIndex      int       `json:"startIndex"`
	TotalResults    int       `json:"totalResults"`
	Format          string    `json:"format"`
	Version         string    `json:"version"`
	Timestamp       string    `json:"timestamp"`
	Vulnerabilities []CVEItem `json:"vulnerabilities"`
}

type CVEItem struct {
	CVE CVE `json:"cve"`
}

type CVE struct {
	ID                    string          `json:"id"`
	SourceIdentifier      string          `json:"sourceIdentifier,omitempty"`
	VulnStatus            string          `json:"vulnStatus,omitempty"`
	Published             string          `json:"published"`
	LastModified          string          `json:"lastModified"`
	EvaluatorComment      string          `json:"evaluatorComment,omitempty"`
	EvaluatorSolution     string          `json:"evaluatorSolution,omitempty"`
	EvaluatorImpact       string          `json:"evaluatorImpact,omitempty"`
	CISAExploitAdd        string          `json:"cisaExploitAdd,omitempty"`
	CISAActionDue         string          `json:"cisaActionDue,omitempty"`
	CISARequiredAction    string          `json:"cisaRequiredAction,omitempty"`
	CISAVulnerabilityName string          `json:"cisaVulnerabilityName,omitempty"`
	Descriptions          []LangString    `json:"descriptions"`
	References            []Reference     `json:"references"`
	Metrics               Metrics         `json:"metrics,omitempty"`
	Weaknesses            []Weakness      `json:"weaknesses,omitempty"`
	Configurations        []Config        `json:"configurations,omitempty"`
	VendorComments        []VendorComment `json:"vendorComments,omitempty"`
}

type LangString struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference struct {
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	URL    string   `json:"url"`
}

// Metric scores for a vulnerability as found on NVD.
type Metrics struct {
	// CVSS V2.0 score.
	CVSSMetricV2 []CVSSMetricV2 `json:"cvssMetricV2,omitempty"`
	// CVSS V3.0 score.
	CVSSMetricV30 []CVSSMetricV30 `json:"cvssMetricV30,omitempty"`
	// CVSS V3.1 score.
	CVSSMetricV31 []CVSSMetricV31 `json:"cvssMetricV31,omitempty"`
}

type CVSSMetricV2 struct {
	Source                  string  `json:"source"`
	Type                    string  `json:"type"`
	CvssData                CVSSV20 `json:"cvssData"`
	BaseSeverity            string  `json:"baseSeverity,omitempty"`
	ExploitabilityScore     float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore             float64 `json:"impactScore,omitempty"`
	ACInsufInfo             bool    `json:"acInsufInfo,omitempty"`
	ObtainAllPrivilege      bool    `json:"obtainAllPrivilege,omitempty"`
	ObtainUserPrivilege     bool    `json:"obtainUserPrivilege,omitempty"`
	ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege,omitempty"`
	UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
}

type Config struct {
	Operator string `json:"operator,omitempty"`
	Negate   bool   `json:"negate,omitempty"`
	Nodes    []Node `json:"nodes"`
}

// Defines a configuration node in an NVD applicability statement.
type Node struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate,omitempty"`
	CPEMatch []CPEMatch `json:"cpeMatch"`
}

// CPE match string or range
type CPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	MatchCriteriaID       string `json:"matchCriteriaId"`
	VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
	VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
}

type CVSSMetricV30 struct {
	Source              string  `json:"source"`
	Type                string  `json:"type"`
	CVSSData            CVSSV30 `json:"cvssData"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type CVSSMetricV31 struct {
	Source              string   `json:"source"`
	Type                string   `json:"type"`
	CVSSData            CVSSV31  `json:"cvssData"`
	ExploitabilityScore *float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         *float64 `json:"impactScore,omitempty"`
}

type VendorComment struct {
	Organization string `json:"organization"`
	Comment      string `json:"comment"`
	LastModified string `json:"lastModified"`
}

type Weakness struct {
	Source      string       `json:"source"`
	Type        string       `json:"type"`
	Description []LangString `json:"description"`
}

// https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json
type CVSSV31 struct {
	// CVSS Version
	Version                       string  `json:"version"`
	VectorString                  string  `json:"vectorString"`
	AttackVector                  string  `json:"attackVector,omitempty"`
	AttackComplexity              string  `json:"attackComplexity,omitempty"`
	PrivilegesRequired            string  `json:"privilegesRequired,omitempty"`
	UserInteraction               string  `json:"userInteraction,omitempty"`
	Scope                         string  `json:"scope,omitempty"`
	ConfidentialityImpact         string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact            string  `json:"availabilityImpact,omitempty"`
	BaseScore                     float64 `json:"baseScore"`
	BaseSeverity                  string  `json:"baseSeverity"`
	ExploitCodeMaturity           string  `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              string  `json:"remediationLevel,omitempty"`
	ReportConfidence              string  `json:"reportConfidence,omitempty"`
	TemporalScore                 float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string  `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       string  `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          string  `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      string  `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       string  `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 string  `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string  `json:"environmentalSeverity,omitempty"`
}

// https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json
type CVSSV30 struct {
	// CVSS Version
	Version                       string   `json:"version"`
	VectorString                  string   `json:"vectorString"`
	AttackVector                  string   `json:"attackVector,omitempty"`
	AttackComplexity              string   `json:"attackComplexity,omitempty"`
	PrivilegesRequired            string   `json:"privilegesRequired,omitempty"`
	UserInteraction               string   `json:"userInteraction,omitempty"`
	Scope                         string   `json:"scope,omitempty"`
	ConfidentialityImpact         string   `json:"confidentialityImpact,omitempty"`
	IntegrityImpact               string   `json:"integrityImpact,omitempty"`
	AvailabilityImpact            string   `json:"availabilityImpact,omitempty"`
	BaseScore                     float64  `json:"baseScore"`
	BaseSeverity                  string   `json:"baseSeverity"`
	ExploitCodeMaturity           string   `json:"exploitCodeMaturity,omitempty"`
	RemediationLevel              string   `json:"remediationLevel,omitempty"`
	ReportConfidence              string   `json:"reportConfidence,omitempty"`
	TemporalScore                 *float64 `json:"temporalScore,omitempty"`
	TemporalSeverity              string   `json:"temporalSeverity,omitempty"`
	ConfidentialityRequirement    string   `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement          string   `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement       string   `json:"availabilityRequirement,omitempty"`
	ModifiedAttackVector          string   `json:"modifiedAttackVector,omitempty"`
	ModifiedAttackComplexity      string   `json:"modifiedAttackComplexity,omitempty"`
	ModifiedPrivilegesRequired    string   `json:"modifiedPrivilegesRequired,omitempty"`
	ModifiedUserInteraction       string   `json:"modifiedUserInteraction,omitempty"`
	ModifiedScope                 string   `json:"modifiedScope,omitempty"`
	ModifiedConfidentialityImpact string   `json:"modifiedConfidentialityImpact,omitempty"`
	ModifiedIntegrityImpact       string   `json:"modifiedIntegrityImpact,omitempty"`
	ModifiedAvailabilityImpact    string   `json:"modifiedAvailabilityImpact,omitempty"`
	EnvironmentalScore            *float64 `json:"environmentalScore,omitempty"`
	EnvironmentalSeverity         string   `json:"environmentalSeverity,omitempty"`
}

// https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json
type CVSSV20 struct {
	// CVSS Version
	Version                    string  `json:"version"`
	VectorString               string  `json:"vectorString"`
	AccessVector               string  `json:"accessVector,omitempty"`
	AccessComplexity           string  `json:"accessComplexity,omitempty"`
	Authentication             string  `json:"authentication,omitempty"`
	ConfidentialityImpact      string  `json:"confidentialityImpact,omitempty"`
	IntegrityImpact            string  `json:"integrityImpact,omitempty"`
	AvailabilityImpact         string  `json:"availabilityImpact,omitempty"`
	BaseScore                  float64 `json:"baseScore"`
	Exploitability             string  `json:"exploitability,omitempty"`
	RemediationLevel           string  `json:"remediationLevel,omitempty"`
	ReportConfidence           string  `json:"reportConfidence,omitempty"`
	TemporalScore              float64 `json:"temporalScore,omitempty"`
	CollateralDamagePotential  string  `json:"collateralDamagePotential,omitempty"`
	TargetDistribution         string  `json:"targetDistribution,omitempty"`
	ConfidentialityRequirement string  `json:"confidentialityRequirement,omitempty"`
	IntegrityRequirement       string  `json:"integrityRequirement,omitempty"`
	AvailabilityRequirement    string  `json:"availabilityRequirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmentalScore,omitempty"`
}
