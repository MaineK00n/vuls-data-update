package vex

type VEX struct {
	Document struct {
		AggregateSeverity struct {
			Namespace string `json:"namespace"`
			Text      string `json:"text"`
		} `json:"aggregate_severity"`
		Category     string `json:"category"`
		CsafVersion  string `json:"csaf_version"`
		Distribution struct {
			Text string `json:"text"`
			Tlp  struct {
				Label string `json:"label"`
				URL   string `json:"url"`
			} `json:"tlp"`
		} `json:"distribution"`
		Lang  string `json:"lang"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
			Title    string `json:"title"`
		} `json:"notes"`
		Publisher  map[string]string `json:"publisher"`
		References []struct {
			Category string `json:"category"`
			Summary  string `json:"summary"`
			URL      string `json:"url"`
		} `json:"references"`
		Title    string `json:"title"`
		Tracking struct {
			CurrentReleaseDate string `json:"current_release_date"`
			Generator          struct {
				Date   string `json:"date"`
				Engine struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"engine"`
			} `json:"generator"`
			ID                 string `json:"id"`
			InitialReleaseDate string `json:"initial_release_date"`
			RevisionHistory    []struct {
				Date    string `json:"date"`
				Number  string `json:"number"`
				Summary string `json:"summary"`
			} `json:"revision_history"`
			Status  string `json:"status"`
			Version string `json:"version"`
		} `json:"tracking"`
	} `json:"document"`
	ProductTree struct {
		Branches []struct {
			Branches []struct {
				Branches []struct {
					Category string `json:"category"`
					Name     string `json:"name"`
					Product  struct {
						Name                        string `json:"name"`
						ProductID                   string `json:"product_id"`
						ProductIdentificationHelper struct {
							Cpe  *string `json:"cpe,omitempty"`
							Purl *string `json:"purl,omitempty"`
						} `json:"product_identification_helper"`
					} `json:"product"`
				} `json:"branches,omitempty"`
				Category string `json:"category"`
				Name     string `json:"name"`
				Product  *struct {
					Name                        string `json:"name"`
					ProductID                   string `json:"product_id"`
					ProductIdentificationHelper *struct {
						Cpe  *string `json:"cpe,omitempty"`
						Purl *string `json:"purl,omitempty"`
					} `json:"product_identification_helper,omitempty"`
				} `json:"product,omitempty"`
			} `json:"branches"`
			Category string `json:"category"`
			Name     string `json:"name"`
		} `json:"branches"`
		Relationships []struct {
			Category        string `json:"category"`
			FullProductName struct {
				Name      string `json:"name"`
				ProductID string `json:"product_id"`
			} `json:"full_product_name"`
			ProductReference          string `json:"product_reference"`
			RelatesToProductReference string `json:"relates_to_product_reference"`
		} `json:"relationships,omitempty"`
	} `json:"product_tree"`
	Vulnerabilities []struct {
		Acknowledgments []struct {
			Names        []string `json:"names"`
			Organization *string  `json:"organization,omitempty"`
			Summary      *string  `json:"summary,omitempty"`
		} `json:"acknowledgments,omitempty"`
		Cve string `json:"cve"`
		Cwe *struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"cwe,omitempty"`
		DiscoveryDate *string `json:"discovery_date,omitempty"`
		Flags         []struct {
			Label      string   `json:"label"`
			ProductIds []string `json:"product_ids"`
		} `json:"flags,omitempty"`
		Ids []struct {
			SystemName string `json:"system_name"`
			Text       string `json:"text"`
		} `json:"ids"`
		Notes []struct {
			Category string `json:"category"`
			Text     string `json:"text"`
			Title    string `json:"title"`
		} `json:"notes"`
		ProductStatus struct {
			Fixed              []string `json:"fixed,omitempty"`
			KnownAffected      []string `json:"known_affected,omitempty"`
			KnownNotAffected   []string `json:"known_not_affected,omitempty"`
			UnderInvestigation []string `json:"under_investigation,omitempty"`
		} `json:"product_status"`
		References []struct {
			Category string `json:"category"`
			Summary  string `json:"summary"`
			URL      string `json:"url"`
		} `json:"references"`
		ReleaseDate  string `json:"release_date"`
		Remediations []struct {
			Category   string   `json:"category"`
			Details    string   `json:"details"`
			ProductIds []string `json:"product_ids"`
			URL        *string  `json:"url,omitempty"`
		} `json:"remediations,omitempty"`
		Scores []struct {
			CvssV2 *struct {
				AccessComplexity      string  `json:"accessComplexity"`
				AccessVector          string  `json:"accessVector"`
				Authentication        string  `json:"authentication"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				VectorString          string  `json:"vectorString"`
				Version               string  `json:"version"`
			} `json:"cvss_v2,omitempty"`
			CvssV3 *struct {
				AttackComplexity      string  `json:"attackComplexity"`
				AttackVector          string  `json:"attackVector"`
				AvailabilityImpact    string  `json:"availabilityImpact"`
				BaseScore             float64 `json:"baseScore"`
				BaseSeverity          string  `json:"baseSeverity"`
				ConfidentialityImpact string  `json:"confidentialityImpact"`
				IntegrityImpact       string  `json:"integrityImpact"`
				PrivilegesRequired    string  `json:"privilegesRequired"`
				Scope                 string  `json:"scope"`
				UserInteraction       string  `json:"userInteraction"`
				VectorString          string  `json:"vectorString"`
				Version               string  `json:"version"`
			} `json:"cvss_v3,omitempty"`
			Products []string `json:"products"`
		} `json:"scores,omitempty"`
		Threats []struct {
			Category   string   `json:"category"`
			Date       *string  `json:"date,omitempty"`
			Details    string   `json:"details"`
			ProductIds []string `json:"product_ids,omitempty"`
		} `json:"threats,omitempty"`
		Title string `json:"title"`
	} `json:"vulnerabilities"`
}
