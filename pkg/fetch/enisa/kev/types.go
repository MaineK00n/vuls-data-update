package kev

// Vulnerability is an entry of eukev.json, following the EU KEV schema v1
// (https://github.com/enisaeu/CNW/tree/main/eukev/schemas/v1). Optional
// properties are omitted from the upstream JSON when they have no value.
type Vulnerability struct {
	CVEID                  string   `json:"cveID"`
	EUVDID                 string   `json:"euvdID"`
	VendorProject          string   `json:"vendorProject"`
	Product                string   `json:"product"`
	VulnerabilityName      string   `json:"vulnerabilityName,omitempty"`
	DateReported           string   `json:"dateReported"`
	DateAdded              string   `json:"dateAdded,omitempty"`
	PatchedSince           string   `json:"patchedSince,omitempty"`
	OriginSource           string   `json:"originSource"`
	ShortDescription       string   `json:"shortDescription"`
	ExploitationType       []string `json:"exploitationType"`
	ThreatActorsExploiting []string `json:"threatActorsExploiting,omitempty"`
	CWEs                   []string `json:"cwes,omitempty"`
	Notes                  string   `json:"notes,omitempty"`
}
