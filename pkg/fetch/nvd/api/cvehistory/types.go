package cvehistory

import "encoding/json/jsontext"

// Top level structure for CVE History JSON API 2.0 data
// https://csrc.nist.gov/schema/nvd/api/2.0/cve_history_api_json_2.0.schema
type api20 struct {
	ResultsPerPage int    `json:"resultsPerPage"`
	StartIndex     int    `json:"startIndex"`
	TotalResults   int    `json:"totalResults"`
	Format         string `json:"format"`
	Version        string `json:"version"`
	Timestamp      string `json:"timestamp"`
	CVEChanges     []struct {
		Change Change `json:"change"`
	} `json:"cveChanges"`
}

// A change event of a CVE.
// Top level structure that fetch command stores CVE change history json files.
type Change struct {
	CVEID            string   `json:"cveId"`
	EventName        string   `json:"eventName"`
	CVEChangeID      string   `json:"cveChangeId"`
	SourceIdentifier string   `json:"sourceIdentifier"`
	Created          string   `json:"created,omitempty"`
	Details          []Detail `json:"details,omitempty"`
}

type Detail struct {
	Action string `json:"action,omitempty"` // enum: Added, Removed, Changed
	Type   string `json:"type"`
	// oldValue and newValue are usually a string, but e.g. the "Affected" type
	// carries the CVE v5 affected structures as an array of objects. Keep them
	// as raw JSON so that the API response is stored as is.
	OldValue jsontext.Value `json:"oldValue,omitzero"`
	NewValue jsontext.Value `json:"newValue,omitzero"`
}
