package csaf

import "time"

type CSAF struct {
	Document struct {
		AggregateSeverity struct {
			Namespace string `json:"namespace,omitempty"`
			Text      string `json:"text,omitempty"`
		} `json:"aggregate_severity,omitempty"`
		Category     string `json:"category,omitempty"`
		CsafVersion  string `json:"csaf_version,omitempty"`
		Distribution struct {
			Text string `json:"text,omitempty"`
			Tlp  struct {
				Label string `json:"label,omitempty"`
				URL   string `json:"url,omitempty"`
			} `json:"tlp,omitempty"`
		} `json:"distribution,omitempty"`
		Lang  string `json:"lang,omitempty"`
		Notes []struct {
			Category string `json:"category,omitempty"`
			Text     string `json:"text,omitempty"`
			Title    string `json:"title,omitempty"`
		} `json:"notes,omitempty"`
		Publisher struct {
			Category       string `json:"category,omitempty"`
			ContactDetails string `json:"contact_details,omitempty"`
			Name           string `json:"name,omitempty"`
			Namespace      string `json:"namespace,omitempty"`
		} `json:"publisher,omitempty"`
		References []struct {
			Category string `json:"category,omitempty"`
			Summary  string `json:"summary,omitempty"`
			URL      string `json:"url,omitempty"`
		} `json:"references,omitempty"`
		Title    string `json:"title,omitempty"`
		Tracking struct {
			CurrentReleaseDate time.Time `json:"current_release_date,omitempty"`
			Generator          struct {
				Date   time.Time `json:"date,omitempty"`
				Engine struct {
					Name    string `json:"name,omitempty"`
					Version string `json:"version,omitempty"`
				} `json:"engine,omitempty"`
			} `json:"generator,omitempty"`
			ID                 string    `json:"id,omitempty"`
			InitialReleaseDate time.Time `json:"initial_release_date,omitempty"`
			RevisionHistory    []struct {
				Date    time.Time `json:"date,omitempty"`
				Number  string    `json:"number,omitempty"`
				Summary string    `json:"summary,omitempty"`
			} `json:"revision_history,omitempty"`
			Status  string `json:"status,omitempty"`
			Version string `json:"version,omitempty"`
		} `json:"tracking,omitempty"`
	} `json:"document,omitempty"`
	ProductTree struct {
		Branches []struct {
			Branches []struct {
				Branches []struct {
					Category string `json:"category,omitempty"`
					Name     string `json:"name,omitempty"`
					Product  struct {
						Name                        string `json:"name,omitempty"`
						ProductID                   string `json:"product_id,omitempty"`
						ProductIdentificationHelper *struct {
							Cpe string `json:"cpe,omitempty"`
						} `json:"product_identification_helper,omitempty"`
					} `json:"product,omitempty"`
				} `json:"branches,omitempty"`
				Category string `json:"category,omitempty"`
				Name     string `json:"name,omitempty"`
			} `json:"branches,omitempty"`
			Category string `json:"category,omitempty"`
			Name     string `json:"name,omitempty"`
		} `json:"branches,omitempty"`
		Relationships []struct {
			Category        string `json:"category,omitempty"`
			FullProductName struct {
				Name      string `json:"name,omitempty"`
				ProductID string `json:"product_id,omitempty"`
			} `json:"full_product_name,omitempty"`
			ProductReference          string `json:"product_reference,omitempty"`
			RelatesToProductReference string `json:"relates_to_product_reference,omitempty"`
		} `json:"relationships,omitempty"`
	} `json:"product_tree,omitempty"`
	Vulnerabilities []struct {
		Cve string `json:"cve,omitempty"`
		Ids []struct {
			SystemName string `json:"system_name,omitempty"`
			Text       string `json:"text,omitempty"`
		} `json:"ids,omitempty"`
		Notes []struct {
			Category string `json:"category,omitempty"`
			Text     string `json:"text,omitempty"`
			Title    string `json:"title,omitempty"`
		} `json:"notes,omitempty"`
		ProductStatus struct {
			Fixed            []string `json:"fixed,omitempty"`
			Knownnotaffected []string `json:"known not affected,omitempty"`
		} `json:"product_status,omitempty"`
		References []struct {
			Category string `json:"category,omitempty"`
			Summary  string `json:"summary,omitempty"`
			URL      string `json:"url,omitempty"`
		} `json:"references,omitempty"`
		Remediations []struct {
			Category   string   `json:"category,omitempty"`
			Details    string   `json:"details,omitempty"`
			ProductIds []string `json:"product_ids,omitempty"`
		} `json:"remediations,omitempty"`
		Scores []struct {
			CvssV3 struct {
				BaseScore    float64 `json:"baseScore,omitempty"`
				BaseSeverity string  `json:"baseSeverity,omitempty"`
				VectorString string  `json:"vectorString,omitempty"`
				Version      string  `json:"version,omitempty"`
			} `json:"cvss_v3,omitempty"`
			Products []string `json:"products,omitempty"`
		} `json:"scores,omitempty"`
		Threats []struct {
			Category string    `json:"category,omitempty"`
			Date     time.Time `json:"date,omitempty"`
			Details  string    `json:"details,omitempty"`
		} `json:"threats,omitempty"`
		Title string `json:"title,omitempty"`
	} `json:"vulnerabilities,omitempty"`
}
