package cve

type versions struct {
	Branches []string `json:"branches"`
}

type cve struct {
	CVEID    string  `json:"cve_id"`
	Pkg      string  `json:"pkg"`
	CVEScore float64 `json:"cve_score"`
	AffVer   string  `json:"aff_ver"`
	ResVer   string  `json:"res_ver"`
	Status   string  `json:"status"`
}
