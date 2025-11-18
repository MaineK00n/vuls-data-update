package data

type advisories map[string]map[string]struct {
	FixedVersion string `json:"fixed_version,omitempty"`
}

type Package struct {
	Name            string          `json:"name"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
}

type Vulnerability struct {
	ID           string `json:"id"`
	FixedVersion string `json:"fixed_version,omitempty"`
}
