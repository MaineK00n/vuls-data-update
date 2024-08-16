package kev

import "time"

type backupResponse struct {
	Benchmark float64 `json:"_benchmark"`
	Meta      struct {
		Timestamp time.Time `json:"timestamp"`
		Index     string    `json:"index"`
	} `json:"_meta"`
	Data []struct {
		Filename      string    `json:"filename"`
		Sha256        string    `json:"sha256"`
		DateAdded     time.Time `json:"date_added"`
		URL           string    `json:"url"`
		URLTTLMinutes int       `json:"url_ttl_minutes"`
		URLExpires    time.Time `json:"url_expires"`
	} `json:"data"`
}

// https://docs.vulncheck.com/community/vulncheck-kev/schema
type VulnCheckKEV struct {
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	Description                string `json:"shortDescription"`
	Name                       string `json:"vulnerabilityName"`
	RequiredAction             string `json:"required_action"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`

	CVE []string `json:"cve"`

	VulnCheckXDB                  []XDB             `json:"vulncheck_xdb"`
	VulnCheckReportedExploitation []ReportedExploit `json:"vulncheck_reported_exploitation"`

	DueDate       *time.Time `json:"dueDate,omitempty"`
	CisaDateAdded *time.Time `json:"cisa_date_added,omitempty"`
	DateAdded     time.Time  `json:"date_added"`
}

type ReportedExploit struct {
	Url       string    `json:"url"`
	DateAdded time.Time `json:"date_added"`
}

type XDB struct {
	XDBID       string    `json:"xdb_id"`
	XDBURL      string    `json:"xdb_url"`
	DateAdded   time.Time `json:"date_added"`
	ExploitType string    `json:"exploit_type"`
	CloneSSHURL string    `json:"clone_ssh_url"`
}
