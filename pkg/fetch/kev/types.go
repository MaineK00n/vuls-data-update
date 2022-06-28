package kev

import "time"

type catalog struct {
	CatalogVersion  string    `json:"catalogVersion"`
	Count           int       `json:"count"`
	DateReleased    time.Time `json:"dateReleased"`
	Title           string    `json:"title"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		Notes                      string `json:"notes"`
		Product                    string `json:"product"`
		RequiredAction             string `json:"requiredAction"`
		ShortDescription           string `json:"shortDescription"`
		VendorProject              string `json:"vendorProject"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID                      string `json:"cveID,omitempty"`
	VendorProject              string `json:"vendorProject,omitempty"`
	Product                    string `json:"product,omitempty"`
	VulnerabilityName          string `json:"vulnerabilityName,omitempty"`
	ShortDescription           string `json:"shortDescription,omitempty"`
	RequiredAction             string `json:"requiredAction,omitempty"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse,omitempty"`
	Notes                      string `json:"notes,omitempty"`
	DateAdded                  string `json:"dateAdded,omitempty"`
	DueDate                    string `json:"dueDate,omitempty"`
}
