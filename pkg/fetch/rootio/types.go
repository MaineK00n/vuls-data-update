package rootio

type feed map[string][]struct {
	DistroVersion string    `json:"distroversion"`
	Packages      []Package `json:"packages"`
}

type Package struct {
	Pkg struct {
		Name string `json:"name"`
		CVEs map[string]struct {
			VulnerableRanges []string `json:"vulnerable_ranges"`
			FixedVersions    []string `json:"fixed_versions"`
		} `json:"cves"`
	} `json:"pkg"`
}
