package v1

// https://csrc.nist.gov/schema/nvd/feed/1.1/nvd_cve_feed_json_1.1.schema
type doc struct {
	CVEDataType         string    `json:"CVE_data_type"`
	CVEDataFormat       string    `json:"CVE_data_format"`
	CVEDataVersion      string    `json:"CVE_data_version"`
	CVEDataNumberOfCVEs string    `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string    `json:"CVE_data_timestamp"`
	CVEItems            []CVEItem `json:"CVE_Items"`
}

type CVEItem struct {
	Cve              CVE            `json:"cve"`
	Configurations   Configurations `json:"configurations,omitzero"`
	Impact           Impact         `json:"impact,omitzero"`
	PublishedDate    string         `json:"publishedDate,omitempty"`
	LastModifiedDate string         `json:"lastModifiedDate,omitempty"`
}

// https://csrc.nist.gov/schema/nvd/feed/1.1/CVE_JSON_4.0_min_1.1.schema
type CVE struct {
	DataType    string `json:"data_type,omitempty"`
	DataFormat  string `json:"data_format,omitempty"`
	DataVersion string `json:"data_version,omitempty"`
	CVEDataMeta struct {
		ID       string `json:"ID"`
		ASSIGNER string `json:"ASSIGNER"`
		STATE    string `json:"STATE,omitempty"`
	} `json:"CVE_data_meta,omitzero"`
	Affects struct {
		Vendor struct {
			VendorData []struct {
				VendorName string `json:"vendor_name"`
				Product    struct {
					ProductData []struct {
						ProductName string `json:"product_name"`
						Version     struct {
							VersionData []struct {
								VersionValue    string `json:"version_value"`
								VersionAffected string `json:"version_affected,omitempty"`
							} `json:"version_data"`
						} `json:"version"`
					} `json:"product_data"`
				} `json:"product"`
			} `json:"vendor_data"`
		} `json:"vendor"`
	} `json:"affects,omitzero"`
	Problemtype struct {
		ProblemtypeData []struct {
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"problemtype_data"`
	} `json:"problemtype"`
	References struct {
		ReferenceData []struct {
			URL       string   `json:"url"`
			Name      string   `json:"name,omitempty"`
			Refsource string   `json:"refsource,omitempty"`
			Tags      []string `json:"tags,omitempty"`
		} `json:"reference_data"`
	} `json:"references"`
	Description struct {
		DescriptionData []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description_data"`
	} `json:"description"`
}

type Configurations struct {
	CVEDataVersion string `json:"CVE_data_version"`
	Nodes          []Node `json:"nodes,omitempty"`
}

type Node struct {
	Operator string     `json:"operator,omitempty"`
	Negate   bool       `json:"negate,omitempty"`
	Children []Node     `json:"children,omitempty"`
	CpeMatch []CPEMatch `json:"cpe_match,omitempty"`
}

type CPEMatch struct {
	Cpe22URI              string  `json:"cpe22Uri,omitempty"`
	Cpe23URI              string  `json:"cpe23Uri"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	Vulnerable            bool    `json:"vulnerable"`
	CPEName               []struct {
		Cpe22URI         string `json:"cpe22Uri,omitempty"`
		Cpe23URI         string `json:"cpe23Uri"`
		LastModifiedDate string `json:"lastModifiedDate,omitempty"`
	} `json:"cpe_name,omitempty"`
}

type Impact struct {
	BaseMetricV2 *struct {
		CvssV2 struct { // https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v2.0.json
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
		} `json:"cvssV2,omitzero"`
		Severity                string  `json:"severity,omitempty"`
		ExploitabilityScore     float64 `json:"exploitabilityScore,omitempty"`
		ImpactScore             float64 `json:"impactScore,omitempty"`
		AcInsufInfo             bool    `json:"acInsufInfo,omitempty"`
		ObtainAllPrivilege      bool    `json:"obtainAllPrivilege,omitempty"`
		ObtainUserPrivilege     bool    `json:"obtainUserPrivilege,omitempty"`
		ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege,omitempty"`
		UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
	} `json:"baseMetricV2,omitempty"`
	BaseMetricV3 *struct {
		CvssV3 struct { // https://csrc.nist.gov/schema/nvd/feed/1.1/cvss-v3.x.json
			Version                       string  `json:"version"`
			VectorString                  string  `json:"vectorString,omitempty"`
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
		} `json:"cvssV3,omitzero"`
		ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
		ImpactScore         float64 `json:"impactScore,omitempty"`
	} `json:"baseMetricV3,omitempty"`
}
