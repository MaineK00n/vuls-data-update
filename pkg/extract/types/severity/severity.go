package severity

import (
	"encoding/json"
	"fmt"
)

type Severity struct {
	Type    SeverityType `json:"type,omitempty"`
	Source  string       `json:"source,omitempty"`
	Vendor  string       `json:"vendor,omitempty"`
	CVSSv2  *CVSSv2      `json:"cvss_v2,omitempty"`
	CVSSv30 *CVSSv30     `json:"cvss_v30,omitempty"`
	CVSSv31 *CVSSv31     `json:"cvss_v31,omitempty"`
	CVSSv40 *CVSSv40     `json:"cvss_v40,omitempty"`
}

type SeverityType int

const (
	_ SeverityType = iota
	SeverityTypeVendor
	SeverityTypeCVSSv2
	SeverityTypeCVSSv30
	SeverityTypeCVSSv31
	SeverityTypeCVSSv40
)

func (t SeverityType) String() string {
	switch t {
	case SeverityTypeVendor:
		return "vendor"
	case SeverityTypeCVSSv2:
		return "cvss_v2"
	case SeverityTypeCVSSv30:
		return "cvss_v30"
	case SeverityTypeCVSSv31:
		return "cvss_v31"
	case SeverityTypeCVSSv40:
		return "cvss_v40"
	default:
		return ""
	}
}

func (t SeverityType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *SeverityType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var st SeverityType
	switch s {
	case "vendor":
		st = SeverityTypeVendor
	case "cvss_v2":
		st = SeverityTypeCVSSv2
	case "cvss_v30":
		st = SeverityTypeCVSSv30
	case "cvss_v31":
		st = SeverityTypeCVSSv31
	case "cvss_v40":
		st = SeverityTypeCVSSv40
	default:
		return fmt.Errorf("invalid SeverityType %s", s)
	}
	*t = st
	return nil
}

type CVSSv2 struct {
	Vector string `json:"vector,omitempty"`
	// Base Metrics
	AccessVector          string  `json:"access_vector,omitempty"`
	AccessComplexity      string  `json:"access_complexity,omitempty"`
	Authentication        string  `json:"authentication,omitempty"`
	ConfidentialityImpact string  `json:"confidentiality_impact,omitempty"`
	IntegrityImpact       string  `json:"integrity_impact,omitempty"`
	AvailabilityImpact    string  `json:"availability_impact,omitempty"`
	BaseScore             float64 `json:"base_score,omitempty"`
	BaseSeverity          string  `json:"base_severity,omitempty"`
	// Temporal Metrics
	Exploitability   string  `json:"exploitability,omitempty"`
	RemediationLevel string  `json:"remediation_level,omitempty"`
	ReportConfidence string  `json:"report_confidence,omitempty"`
	TemporalScore    float64 `json:"temporal_score,omitempty"`
	TemporalSeverity string  `json:"temporal_severity,omitempty"`
	// Environmental Metrics
	CollateralDamagePotential  string  `json:"collateral_damage_potential,omitempty"`
	TargetDistribution         string  `json:"target_distribution,omitempty"`
	ConfidentialityRequirement string  `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement       string  `json:"integrity_requirement,omitempty"`
	AvailabilityRequirement    string  `json:"availability_requirement,omitempty"`
	EnvironmentalScore         float64 `json:"environmental_score,omitempty"`
	EnvironmentalSeverity      string  `json:"environmental_severity,omitempty"`
}

func (cvss *CVSSv2) Parse() error {
	return nil
}

type CVSSv30 struct {
	Vector string `json:"vector,omitempty"`
	// Base Metrics
	AttackVector          string  `json:"attack_vector,omitempty"`
	AttackComplexity      string  `json:"attack_complexity,omitempty"`
	PrivilegesRequired    string  `json:"privileges_required,omitempty"`
	UserInteraction       string  `json:"user_interaction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentiality_impact,omitempty"`
	IntegrityImpact       string  `json:"integrity_impact,omitempty"`
	AvailabilityImpact    string  `json:"availability_impact,omitempty"`
	BaseScore             float64 `json:"base_score,omitempty"`
	BaseSeverity          string  `json:"base_severity,omitempty"`
	// Temporal Metrics
	ExploitCodeMaturity string  `json:"exploit_code_maturity,omitempty"`
	RemediationLevel    string  `json:"remediation_level,omitempty"`
	ReportConfidence    string  `json:"report_confidence,omitempty"`
	TemporalScore       float64 `json:"temporal_score,omitempty"`
	TemporalSeverity    string  `json:"temporal_severity,omitempty"`
	// Environmental Metrics
	ConfidentialityRequirement    string  `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement          string  `json:"integrity_requirement,omitempty"`
	AvailabilityRequirement       string  `json:"availability_requirement,omitempty"`
	ModifiedAttackVector          string  `json:"modified_attack_vector,omitempty"`
	ModifiedAttackComplexity      string  `json:"modified_attack_complexity,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modified_privileges_required,omitempty"`
	ModifiedUserInteraction       string  `json:"modified_user_interaction,omitempty"`
	ModifiedScope                 string  `json:"modified_scope,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modified_confidentiality_impact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modified_integrity_impact,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modified_availability_impact,omitempty"`
	EnvironmentalScore            float64 `json:"environmental_score,omitempty"`
	EnvironmentalSeverity         string  `json:"environmental_severity,omitempty"`
}

func (cvss *CVSSv30) Parse() error {
	return nil
}

type CVSSv31 struct {
	Vector string `json:"vector,omitempty"`
	// Base Metrics
	AttackVector          string  `json:"attack_vector,omitempty"`
	AttackComplexity      string  `json:"attack_complexity,omitempty"`
	PrivilegesRequired    string  `json:"privileges_required,omitempty"`
	UserInteraction       string  `json:"user_interaction,omitempty"`
	Scope                 string  `json:"scope,omitempty"`
	ConfidentialityImpact string  `json:"confidentiality_impact,omitempty"`
	IntegrityImpact       string  `json:"integrity_impact,omitempty"`
	AvailabilityImpact    string  `json:"availability_impact,omitempty"`
	BaseScore             float64 `json:"base_score,omitempty"`
	BaseSeverity          string  `json:"base_severity,omitempty"`
	// Temporal Metrics
	ExploitCodeMaturity string  `json:"exploit_code_maturity,omitempty"`
	RemediationLevel    string  `json:"remediation_level,omitempty"`
	ReportConfidence    string  `json:"report_confidence,omitempty"`
	TemporalScore       float64 `json:"temporal_score,omitempty"`
	TemporalSeverity    string  `json:"temporal_severity,omitempty"`
	// Environmental Metrics
	ConfidentialityRequirement    string  `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement          string  `json:"integrity_requirement,omitempty"`
	AvailabilityRequirement       string  `json:"availability_requirement,omitempty"`
	ModifiedAttackVector          string  `json:"modified_attack_vector,omitempty"`
	ModifiedAttackComplexity      string  `json:"modified_attack_complexity,omitempty"`
	ModifiedPrivilegesRequired    string  `json:"modified_privileges_required,omitempty"`
	ModifiedUserInteraction       string  `json:"modified_user_interaction,omitempty"`
	ModifiedScope                 string  `json:"modified_scope,omitempty"`
	ModifiedConfidentialityImpact string  `json:"modified_confidentiality_impact,omitempty"`
	ModifiedIntegrityImpact       string  `json:"modified_integrity_impact,omitempty"`
	ModifiedAvailabilityImpact    string  `json:"modified_availability_impact,omitempty"`
	EnvironmentalScore            float64 `json:"environmental_score,omitempty"`
	EnvironmentalSeverity         string  `json:"environmental_severity,omitempty"`
}

func (cvss *CVSSv31) Parse() error {
	return nil
}

type CVSSv40 struct {
	Vector string `json:"vector,omitempty"`
	// Base Metrics
	AttackVector                          string  `json:"attack_vector,omitempty"`
	AttackComplexity                      string  `json:"attack_complexity,omitempty"`
	AttackRequirements                    string  `json:"attack_requirements,omitempty"`
	PrivilegesRequired                    string  `json:"privileges_required,omitempty"`
	UserInteraction                       string  `json:"user_interaction,omitempty"`
	VulnerableSystemConfidentialityImpact string  `json:"vulnerable_system_confidentiality_impact,omitempty"`
	SubsequentSystemConfidentialityImpact string  `json:"subsequent_system_confidentiality_impact,omitempty"`
	VulnerableSystemIntegrityImpact       string  `json:"vulnerable_system_integrity_impact,omitempty"`
	SubsequentSystemIntegrityImpact       string  `json:"subsequent_system_integrity_impact,omitempty"`
	VulnerableSystemAvailabilityImpact    string  `json:"vulnerable_system_availability_impact,omitempty"`
	SubsequentSystemAvailabilityImpact    string  `json:"subsequent_system_availability_impact,omitempty"`
	BaseScore                             float64 `json:"base_score,omitempty"`
	BaseSeverity                          string  `json:"base_severity,omitempty"`
	// Threat Metrics
	ExploitMaturity    string  `json:"exploit_maturity,omitempty"`
	BaseThreatScore    float64 `json:"base_threat_score,omitempty"`
	BaseThreatSeverity string  `json:"base_threat_severity,omitempty"`
	// Environmental Metrics
	ModifiedAttackVector                          string  `json:"modified_attack_vector,omitempty"`
	ModifiedAttackComplexity                      string  `json:"modified_attack_complexity,omitempty"`
	ModifiedAttackRequirements                    string  `json:"modified_attack_requirements,omitempty"`
	ModifiedPrivilegesRequired                    string  `json:"modified_privileges_required,omitempty"`
	ModifiedUserInteraction                       string  `json:"modified_user_interaction,omitempty"`
	ModifiedVulnerableSystemConfidentialityImpact string  `json:"modified_vulnerable_system_confidentiality_impact,omitempty"`
	ModifiedSubsequentSystemConfidentialityImpact string  `json:"modified_subsequent_system_confidentiality_impact,omitempty"`
	ModifiedVulnerableSystemIntegrityImpact       string  `json:"modified_vulnerable_system_integrity_impact,omitempty"`
	ModifiedSubsequentSystemIntegrityImpact       string  `json:"modified_subsequent_system_integrity_impact,omitempty"`
	ModifiedVulnerableSystemAvailabilityImpact    string  `json:"modified_vulnerable_system_availability_impact,omitempty"`
	ModifiedSubsequentSystemAvailabilityImpact    string  `json:"modified_subsequent_system_availability_impact,omitempty"`
	ConfidentialityRequirement                    string  `json:"confidentiality_requirement,omitempty"`
	IntegrityRequirement                          string  `json:"integrity_requirement,omitempty"`
	AvailabilityRequirement                       string  `json:"availability_requirement,omitempty"`
	BaseEnvironmentaltScore                       float64 `json:"base_environmentalt_score,omitempty"`
	BaseEnvironmentalSeverity                     string  `json:"base_environmental_severity,omitempty"`
	BaseThreatEnvironmentaltScore                 float64 `json:"base_threat_environmentalt_score,omitempty"`
	BaseThreatEnvironmentalSeverity               string  `json:"base_threat_environmental_severity,omitempty"`
	// Supplemental Metrics
	Safety                      string `json:"safety,omitempty"`
	Automatable                 string `json:"automatable,omitempty"`
	Recovery                    string `json:"recovery,omitempty"`
	ValueDensity                string `json:"value_density,omitempty"`
	VulnerabilityResponseEffort string `json:"vulnerability_response_effort,omitempty"`
	ProviderUrgency             string `json:"provider_urgency,omitempty"`
}

func (cvss *CVSSv40) Parse() error {
	return nil
}
