package echo

type advisories map[string]map[string]struct {
	Severity     string `json:"severity,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
}

type Vulnerability struct {
	ID       string    `json:"id"`
	Packages []Package `json:"packages"`
}

type Package struct {
	Name         string `json:"name"`
	Severity     string `json:"severity,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
}
