package rootio

type feed map[string][]DistroData

type DistroData struct {
	DistroVersion string `json:"distroversion"`
	Packages      []struct {
		Pkg struct {
			Name string `json:"name"`
			CVEs map[string]struct {
				VulnerableRanges []string `json:"vulnerable_ranges"`
				FixedVersions    []string `json:"fixed_versions"`
			} `json:"cves"`
		} `json:"pkg"`
	} `json:"packages"`
}
