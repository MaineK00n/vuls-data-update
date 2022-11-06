package kev

import "time"

type catalog struct {
	CatalogVersion  string    `json:"catalogVersion"`
	Count           int       `json:"count"`
	DateReleased    time.Time `json:"dateReleased"`
	Title           string    `json:"title"`
	Vulnerabilities []struct {
		CveID             string `json:"cveID"`
		DateAdded         string `json:"dateAdded"`
		DueDate           string `json:"dueDate"`
		Notes             string `json:"notes"`
		Product           string `json:"product"`
		RequiredAction    string `json:"requiredAction"`
		ShortDescription  string `json:"shortDescription"`
		VendorProject     string `json:"vendorProject"`
		VulnerabilityName string `json:"vulnerabilityName"`
	} `json:"vulnerabilities"`
}

type Vulnerability struct {
	CveID             string     `json:"cveID,omitempty"`
	VendorProject     string     `json:"vendorProject,omitempty"`
	Product           string     `json:"product,omitempty"`
	VulnerabilityName string     `json:"vulnerabilityName,omitempty"`
	ShortDescription  string     `json:"shortDescription,omitempty"`
	RequiredAction    string     `json:"requiredAction,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	DateAdded         *time.Time `json:"dateAdded,omitempty"`
	DueDate           *time.Time `json:"dueDate,omitempty"`
}
