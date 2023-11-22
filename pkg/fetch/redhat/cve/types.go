package cve

type entry struct {
	ResourceURL string `json:"resource_url"`
}

type CVE struct {
	Name           string  `json:"name"`
	ThreatSeverity *string `json:"threat_severity,omitempty"`
	PublicDate     string  `json:"public_date"`
	Bugzilla       struct {
		Description string `json:"description"`
		ID          string `json:"id"`
		URL         string `json:"url"`
	} `json:"bugzilla"`
	Cvss *struct {
		CvssBaseScore     string `json:"cvss_base_score"`
		CvssScoringVector string `json:"cvss_scoring_vector"`
		Status            string `json:"status"`
	} `json:"cvss,omitempty"`
	Cvss3 *struct {
		Cvss3BaseScore     string `json:"cvss3_base_score"`
		Cvss3ScoringVector string `json:"cvss3_scoring_vector"`
		Status             string `json:"status"`
	} `json:"cvss3,omitempty"`
	Cwe             *string  `json:"cwe,omitempty"`
	Details         []string `json:"details"`
	Statement       *string  `json:"statement,omitempty"`
	References      []string `json:"references,omitempty"`
	Acknowledgement *string  `json:"acknowledgement,omitempty"`
	Mitigation      *struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"mitigation,omitempty"`
	AffectedRelease []struct {
		Advisory    string  `json:"advisory"`
		Cpe         string  `json:"cpe"`
		Impact      *string `json:"impact,omitempty"`
		Package     *string `json:"package,omitempty"`
		ProductName string  `json:"product_name"`
		ReleaseDate string  `json:"release_date"`
	} `json:"affected_release,omitempty"`
	PackageState []map[string]string `json:"package_state,omitempty"`
	UpstreamFix  *string             `json:"upstream_fix,omitempty"`
	CSAw         bool                `json:"csaw"`
}
