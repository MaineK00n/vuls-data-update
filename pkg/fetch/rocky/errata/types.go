package errata

// https://apollo.build.resf.org/docs#/advisories/get_advisory_api_v3_advisories__advisory_name__get
type advisories struct {
	Advisories []Advisory `json:"advisories"`
	Total      int        `json:"total"`
	Page       int        `json:"page"`
	Size       int        `json:"size"`
	Links      struct {
		First string `json:"first"`
		Last  string `json:"last"`
		Self  string `json:"self"`
		Next  string `json:"next,omitempty"`
		Prev  string `json:"prev,omitempty"`
	} `json:"links"`
	LastUpdatedAt string `json:"last_updated_at,omitempty"`
}

type Advisory struct {
	ID               int    `json:"id"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at,omitempty"`
	PublishedAt      string `json:"published_at"`
	Name             string `json:"name"`
	Synopsis         string `json:"synopsis"`
	Description      string `json:"description"`
	Kind             string `json:"kind"`
	Severity         string `json:"severity"`
	Topic            string `json:"topic"`
	RedHatAdvisoryID int    `json:"red_hat_advisory_id"`
	AffectedProducts []struct {
		ID           int    `json:"id"`
		Variant      string `json:"variant"`
		Name         string `json:"name"`
		MajorVersion int    `json:"major_version"`
		MinorVersion int    `json:"minor_version,omitzero"`
		Arch         string `json:"arch"`
	} `json:"affected_products"`
	CVEs []struct {
		ID                 int    `json:"id"`
		CVE                string `json:"cve"`
		CVSS3ScoringVector string `json:"cvss3_scoring_vector,omitempty"`
		CVSS3BaseScore     string `json:"cvss3_base_score,omitempty"`
		CWE                string `json:"cwe,omitempty"`
	} `json:"cves"`
	Fixes []struct {
		ID          int    `json:"id"`
		TicketID    string `json:"ticket_id"`
		Source      string `json:"source"`
		Description string `json:"description,omitempty"`
	} `json:"fixes"`
	Packages []struct {
		ID            int     `json:"id"`
		NEVRA         string  `json:"nevra"`
		Checksum      string  `json:"checksum"`
		ChecksumType  string  `json:"checksum_type"`
		ModuleContext *string `json:"module_context,omitempty"`
		ModuleName    *string `json:"module_name,omitempty"`
		ModuleStream  *string `json:"module_stream,omitempty"`
		ModuleVersion *string `json:"module_version,omitempty"`
		RepoName      string  `json:"repo_name"`
		ProductName   string  `json:"product_name"`
	} `json:"packages"`
}
