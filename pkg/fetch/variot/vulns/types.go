package vulns

type vulns struct {
	Count    int     `json:"count"`
	Next     *string `json:"next,omitempty"`
	Previous *string `json:"previous,omitempty"`
	Results  []Vuln  `json:"results,omitempty"`
}

type Vuln struct {
	ID               string `json:"id"`
	AffectedProducts struct {
		Data []struct {
			Model   *string `json:"model"`
			Scope   *string `json:"scope"`
			Trust   float64 `json:"trust"`
			Vendor  string  `json:"vendor"`
			Version *string `json:"version"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"affected_products"`
	Configurations *struct {
		Data []struct {
			CVEDataVersion string `json:"CVE_data_version"`
			Nodes          []struct {
				CpeMatch []struct {
					Cpe22URI   *string `json:"cpe22Uri,omitempty"`
					Cpe23URI   *string `json:"cpe23Uri,omitempty"`
					Vulnerable bool    `json:"vulnerable"`
				} `json:"cpe_match"`
				Operator string `json:"operator"`
			} `json:"nodes"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"configurations,omitempty"`
	Credits struct {
		Data    string `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"credits"`
	Cve  *string `json:"cve,omitempty"`
	Cvss *struct {
		Data []struct {
			CvssV2 []struct {
				AccessComplexity      *string  `json:"accessComplexity"`
				AccessVector          *string  `json:"accessVector"`
				Authentication        *string  `json:"authentication"`
				Author                string   `json:"author"`
				AvailabilityImpact    *string  `json:"availabilityImpact"`
				BaseScore             *float64 `json:"baseScore"`
				ConfidentialityImpact *string  `json:"confidentialityImpact"`
				ExploitabilityScore   *float64 `json:"exploitabilityScore"`
				ID                    string   `json:"id"`
				ImpactScore           *float64 `json:"impactScore"`
				IntegrityImpact       *string  `json:"integrityImpact"`
				Severity              *string  `json:"severity"`
				Trust                 float64  `json:"trust"`
				VectorString          *string  `json:"vectorString"`
				Version               string   `json:"version"`
			} `json:"cvssV2"`
			CvssV3 []struct {
				AttackComplexity      string   `json:"attackComplexity"`
				AttackVector          string   `json:"attackVector"`
				Author                string   `json:"author"`
				AvailabilityImpact    string   `json:"availabilityImpact"`
				BaseScore             float64  `json:"baseScore"`
				BaseSeverity          string   `json:"baseSeverity"`
				ConfidentialityImpact string   `json:"confidentialityImpact"`
				ExploitabilityScore   *float64 `json:"exploitabilityScore"`
				ID                    string   `json:"id"`
				ImpactScore           *float64 `json:"impactScore"`
				IntegrityImpact       string   `json:"integrityImpact"`
				PrivilegesRequired    string   `json:"privilegesRequired"`
				Scope                 string   `json:"scope"`
				Trust                 float64  `json:"trust"`
				UserInteraction       string   `json:"userInteraction"`
				VectorString          string   `json:"vectorString"`
				Version               string   `json:"version"`
			} `json:"cvssV3"`
			Severity []struct {
				Author string  `json:"author"`
				ID     string  `json:"id"`
				Trust  float64 `json:"trust"`
				Value  string  `json:"value"`
			} `json:"severity"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"cvss,omitempty"`
	Description struct {
		Data    string `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"description"`
	ExploitAvailability *struct {
		Data []struct {
			Reference string  `json:"reference"`
			Trust     float64 `json:"trust"`
			Type      string  `json:"type"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"exploit_availability,omitempty"`
	ExternalIds struct {
		Data []struct {
			Db    string  `json:"db"`
			ID    string  `json:"id"`
			Trust float64 `json:"trust"`
		} `json:"data"`
		Sources []struct {
			Db string  `json:"db"`
			ID *string `json:"id"`
		} `json:"sources"`
	} `json:"external_ids"`
	Iot struct {
		Data    bool `json:"data"`
		Sources []struct {
			Db string  `json:"db"`
			ID *string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"iot"`
	IotTaxonomy *struct {
		Data []struct {
			Category    interface{} `json:"category"`
			SubCategory *string     `json:"sub_category"`
			Trust       float64     `json:"trust"`
		} `json:"data"`
		Sources []struct {
			Db string  `json:"db"`
			ID *string `json:"id"`
		} `json:"sources"`
	} `json:"iot_taxonomy,omitempty"`
	LastUpdateDate string `json:"last_update_date"`
	Patch          *struct {
		Data []struct {
			Title string  `json:"title"`
			Trust float64 `json:"trust"`
			URL   string  `json:"url"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"patch,omitempty"`
	ProblemtypeData *struct {
		Data []struct {
			Problemtype string  `json:"problemtype"`
			Trust       float64 `json:"trust"`
		} `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
	} `json:"problemtype_data,omitempty"`
	References struct {
		Data []struct {
			Trust float64 `json:"trust"`
			URL   string  `json:"url"`
		} `json:"data"`
		Sources []struct {
			Db string  `json:"db"`
			ID *string `json:"id"`
		} `json:"sources"`
	} `json:"references"`
	Sources struct {
		Data []struct {
			Db string  `json:"db"`
			ID *string `json:"id"`
		} `json:"data"`
	} `json:"sources"`
	SourcesReleaseDate struct {
		Data []struct {
			Date string `json:"date"`
			Db   string `json:"db"`
			ID   string `json:"id"`
		} `json:"data"`
	} `json:"sources_release_date"`
	SourcesUpdateDate struct {
		Data []struct {
			Date string `json:"date"`
			Db   string `json:"db"`
			ID   string `json:"id"`
		} `json:"data"`
	} `json:"sources_update_date"`
	ThreatType *struct {
		Data    string `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"threat_type,omitempty"`
	Title struct {
		Data    string `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"title"`
	Type *struct {
		Data    string `json:"data"`
		Sources []struct {
			Db string `json:"db"`
			ID string `json:"id"`
		} `json:"sources"`
		Trust float64 `json:"trust"`
	} `json:"type,omitempty"`
}
