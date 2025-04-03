package cve

type response struct {
	Cves         []CVE `json:"cves"`
	Limit        int   `json:"limit"`
	Offset       int   `json:"offset"`
	TotalResults int   `json:"total_results"`
}

type CVE struct {
	Bugs        []string `json:"bugs"`
	Codename    *string  `json:"codename"`
	CVSS3       *float64 `json:"cvss3"`
	Description string   `json:"description"`
	ID          string   `json:"id"`
	Impact      *struct {
		BaseMetricV3 struct {
			CvssV3 struct {
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
			} `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
	} `json:"impact"`
	Mitigation *string `json:"mitigation"`
	Notes      []struct {
		Author string `json:"author"`
		Note   string `json:"note"`
	} `json:"notes"`
	Notices []struct {
		CvesIds         []string `json:"cves_ids"`
		Description     string   `json:"description"`
		ID              string   `json:"id"`
		Instructions    string   `json:"instructions"`
		IsHidden        bool     `json:"is_hidden"`
		Published       string   `json:"published"`
		References      []string `json:"references"`
		ReleasePackages map[string][]struct {
			Channel     *string `json:"channel,omitempty"`
			Description *string `json:"description,omitempty"`
			IsSource    bool    `json:"is_source"`
			IsVisible   *bool   `json:"is_visible,omitempty"`
			Name        string  `json:"name"`
			PackageType *string `json:"package_type,omitempty"`
			Pocket      *string `json:"pocket,omitempty"`
			SourceLink  *string `json:"source_link,omitempty"`
			Version     string  `json:"version"`
			VersionLink *string `json:"version_link,omitempty"`
		} `json:"release_packages"`
		Summary string `json:"summary"`
		Title   string `json:"title"`
		Type    string `json:"type"`
	} `json:"notices"`
	NoticesIds []string `json:"notices_ids"`
	Packages   []struct {
		Debian   string `json:"debian"`
		Name     string `json:"name"`
		Source   string `json:"source"`
		Statuses []struct {
			Component       *string `json:"component"`
			Description     string  `json:"description"`
			Pocket          string  `json:"pocket"`
			ReleaseCodename string  `json:"release_codename"`
			Status          string  `json:"status"`
		} `json:"statuses"`
		Ubuntu string `json:"ubuntu"`
	} `json:"packages"`
	Patches           map[string][]string `json:"patches"`
	Priority          string              `json:"priority"`
	Published         *string             `json:"published"`
	References        []string            `json:"references"`
	Status            string              `json:"status"`
	Tags              map[string][]string `json:"tags"`
	UbuntuDescription string              `json:"ubuntu_description"`
	UpdatedAt         string              `json:"updated_at"`
}
