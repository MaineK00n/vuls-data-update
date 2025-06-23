package v1

type doc struct {
	CVEDataFormat       string `json:"CVE_data_format"`
	CVEDataNumberOfCVEs string `json:"CVE_data_numberOfCVEs"`
	CVEDataTimestamp    string `json:"CVE_data_timestamp"`
	CVEDataType         string `json:"CVE_data_type"`
	CVEDataVersion      string `json:"CVE_data_version"`
	CVEItems            []struct {
		Cve              CVEItemCVE            `json:"cve,omitempty"`
		Impact           CVEItemImpact         `json:"impact,omitempty"`
		Configurations   CVEItemConfigurations `json:"configurations,omitempty"`
		LastModifiedDate string                `json:"lastModifiedDate,omitempty"`
		PublishedDate    string                `json:"publishedDate,omitempty"`
	} `json:"CVE_Items"`
}

type CVEItem struct {
	Cve              CVEItemCVE            `json:"cve,omitempty"`
	Impact           CVEItemImpact         `json:"impact,omitempty"`
	Configurations   CVEItemConfigurations `json:"configurations,omitempty"`
	LastModifiedDate string                `json:"lastModifiedDate,omitempty"`
	PublishedDate    string                `json:"publishedDate,omitempty"`
}

type CVEItemCVE struct {
	CVEDataMeta struct {
		ASSIGNER string `json:"ASSIGNER,omitempty"`
		ID       string `json:"ID,omitempty"`
	} `json:"CVE_data_meta,omitempty"`
	DataFormat  string `json:"data_format,omitempty"`
	DataType    string `json:"data_type,omitempty"`
	DataVersion string `json:"data_version,omitempty"`
	Description struct {
		DescriptionData []struct {
			Lang  string `json:"lang,omitempty"`
			Value string `json:"value,omitempty"`
		} `json:"description_data,omitempty"`
	} `json:"description,omitempty"`
	Problemtype struct {
		ProblemtypeData []struct {
			Description []struct {
				Lang  string `json:"lang,omitempty"`
				Value string `json:"value,omitempty"`
			} `json:"description,omitempty"`
		} `json:"problemtype_data,omitempty"`
	} `json:"problemtype,omitempty"`
	References struct {
		ReferenceData []struct {
			Name      string   `json:"name,omitempty"`
			Refsource string   `json:"refsource,omitempty"`
			Tags      []string `json:"tags,omitempty"`
			URL       string   `json:"url,omitempty"`
		} `json:"reference_data,omitempty"`
	} `json:"references,omitempty"`
}

type CVEItemImpact struct {
	BaseMetricV2 *struct {
		AcInsufInfo bool `json:"acInsufInfo,omitempty"`
		CvssV2      struct {
			AccessComplexity      string  `json:"accessComplexity,omitempty"`
			AccessVector          string  `json:"accessVector,omitempty"`
			Authentication        string  `json:"authentication,omitempty"`
			AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
			BaseScore             float64 `json:"baseScore,omitempty"`
			ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
			IntegrityImpact       string  `json:"integrityImpact,omitempty"`
			VectorString          string  `json:"vectorString,omitempty"`
			Version               string  `json:"version,omitempty"`
		} `json:"cvssV2,omitempty"`
		ExploitabilityScore     float64 `json:"exploitabilityScore,omitempty"`
		ImpactScore             float64 `json:"impactScore,omitempty"`
		ObtainAllPrivilege      bool    `json:"obtainAllPrivilege,omitempty"`
		ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege,omitempty"`
		ObtainUserPrivilege     bool    `json:"obtainUserPrivilege,omitempty"`
		Severity                string  `json:"severity,omitempty"`
		UserInteractionRequired bool    `json:"userInteractionRequired,omitempty"`
	} `json:"baseMetricV2,omitempty"`
	BaseMetricV3 *struct {
		CvssV3 struct {
			AttackComplexity      string  `json:"attackComplexity,omitempty"`
			AttackVector          string  `json:"attackVector,omitempty"`
			AvailabilityImpact    string  `json:"availabilityImpact,omitempty"`
			BaseScore             float64 `json:"baseScore,omitempty"`
			BaseSeverity          string  `json:"baseSeverity,omitempty"`
			ConfidentialityImpact string  `json:"confidentialityImpact,omitempty"`
			IntegrityImpact       string  `json:"integrityImpact,omitempty"`
			PrivilegesRequired    string  `json:"privilegesRequired,omitempty"`
			Scope                 string  `json:"scope,omitempty"`
			UserInteraction       string  `json:"userInteraction,omitempty"`
			VectorString          string  `json:"vectorString,omitempty"`
			Version               string  `json:"version,omitempty"`
		} `json:"cvssV3,omitempty"`
		ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
		ImpactScore         float64 `json:"impactScore,omitempty"`
	} `json:"baseMetricV3,omitempty"`
}

type CVEItemConfigurations struct {
	CVEDataVersion string `json:"CVE_data_version,omitempty"`
	Nodes          []struct {
		Children []struct {
			CpeMatch []struct {
				Cpe23URI              string   `json:"cpe23Uri,omitempty"`
				VersionEndExcluding   *string  `json:"versionEndExcluding,omitempty"`
				VersionEndIncluding   *string  `json:"versionEndIncluding,omitempty"`
				VersionStartExcluding *string  `json:"versionStartExcluding,omitempty"`
				VersionStartIncluding *string  `json:"versionStartIncluding,omitempty"`
				Vulnerable            bool     `json:"vulnerable,omitempty"`
				CPEName               []string `json:"cpe_name,omitempty"`
			} `json:"cpe_match,omitempty"`
			Operator string `json:"operator,omitempty"`
		} `json:"children,omitempty"`
		CpeMatch []struct {
			Cpe23URI              string   `json:"cpe23Uri,omitempty"`
			VersionEndExcluding   *string  `json:"versionEndExcluding,omitempty"`
			VersionEndIncluding   *string  `json:"versionEndIncluding,omitempty"`
			VersionStartExcluding *string  `json:"versionStartExcluding,omitempty"`
			VersionStartIncluding *string  `json:"versionStartIncluding,omitempty"`
			Vulnerable            bool     `json:"vulnerable,omitempty"`
			CPEName               []string `json:"cpe_name,omitempty"`
		} `json:"cpe_match,omitempty"`
		Operator string `json:"operator,omitempty"`
	} `json:"nodes,omitempty"`
}
