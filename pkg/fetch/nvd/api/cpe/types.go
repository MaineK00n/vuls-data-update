package cpe

// Top level structure for CVE JSON API 2.0 data
// https://csrc.nist.gov/schema/nvd/api/2.0/cpe_api_json_2.0.schema
type api20 struct {
	StartIndex     int       `json:"startIndex"`
	ResultsPerPage int       `json:"resultsPerPage"`
	TotalResults   int       `json:"totalResults"`
	Format         string    `json:"format"`
	Version        string    `json:"version"`
	Timestamp      string    `json:"timestamp"`
	Products       []Product `json:"products"`
}

// Top level structure that fetch command stores CPE json files
type Product struct {
	CPE CPE `json:"cpe"`
}

type CPE struct {
	Deprecated   bool           `json:"deprecated"`
	Name         string         `json:"cpeName"`
	NameID       string         `json:"cpeNameId"`
	Created      string         `json:"created"`
	LastModified string         `json:"lastModified"`
	Titles       []Title        `json:"titles,omitempty"`
	Refs         []DefReference `json:"refs,omitempty"`
	DeprecatedBy []DeprecatedBy `json:"deprecatedBy,omitempty"`
	Deprecates   []Deprecate    `json:"deprecates,omitempty"`
}

type DeprecatedBy struct {
	CPEName   *string `json:"cpeName,omitempty"`
	CPENameID *string `json:"cpeNameId,omitempty"`
}

type Deprecate struct {
	CPEName   *string `json:"cpeName,omitempty"`
	CPENameID *string `json:"cpeNameId,omitempty"`
}

// Internet resource for CPE
type DefReference struct {
	Ref  string `json:"ref"`
	Type string `json:"type,omitempty"`
}

// Human readable title for CPE
type Title struct {
	Title string `json:"title"`
	Lang  string `json:"lang"`
}
