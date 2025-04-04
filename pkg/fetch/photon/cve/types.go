package cve

type versions struct {
	Branches []string `json:"branches"`
}

type CVE struct {
	AffVer   string  `json:"aff_ver"`
	CveID    string  `json:"cve_id"`
	CveScore float64 `json:"cve_score"`
	Pkg      string  `json:"pkg"`
	ResVer   string  `json:"res_ver"`
}
