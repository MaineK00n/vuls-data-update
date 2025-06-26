package kev

import "time"

type catalog struct {
	CatalogVersion  string          `json:"catalogVersion"`
	Count           int             `json:"count"`
	DateReleased    time.Time       `json:"dateReleased"`
	Title           string          `json:"title"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID                      string   `json:"cveID,omitempty"`
	VendorProject              string   `json:"vendorProject,omitempty"`
	Product                    string   `json:"product,omitempty"`
	VulnerabilityName          string   `json:"vulnerabilityName,omitempty"`
	ShortDescription           string   `json:"shortDescription,omitempty"`
	RequiredAction             string   `json:"requiredAction,omitempty"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string   `json:"notes,omitempty"`
	DateAdded                  string   `json:"dateAdded,omitempty"`
	DueDate                    string   `json:"dueDate,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
}
