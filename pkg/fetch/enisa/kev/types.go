package kev

type Vulnerability struct {
	CVEID                  string `json:"cveID"`
	EUVDID                 string `json:"euvdID"`
	VendorProject          string `json:"vendorProject"`
	Product                string `json:"product"`
	VulnerabilityName      string `json:"vulnerabilityName"`
	DateReported           string `json:"dateReported"`
	PatchedSince           string `json:"patchedSince"`
	OriginSource           string `json:"originSource"`
	ShortDescription       string `json:"shortDescription"`
	ExploitationType       string `json:"exploitationType"`
	ThreatActorsExploiting string `json:"threatActorsExploiting"`
	CWEs                   string `json:"cwes"`
	Notes                  string `json:"notes"`
}
