package packagemanifest

type Package struct {
	Package             string `json:"package"`
	License             string `json:"license,omitempty"`
	CompatibilityLevel  string `json:"compatibility_level,omitempty"`
	MinorReleaseVersion string `json:"minor_release_version,omitempty"`
}

type PackageTable struct {
	Major      int       `json:"major,omitempty"`
	Index      int       `json:"index"`
	Type       string    `json:"type"`
	Repository string    `json:"repository,omitempty"`
	Packages   []Package `json:"packages"`
	Source     string    `json:"source"`
}

type Module struct {
	Module             string   `json:"module"`
	Stream             string   `json:"stream"`
	CompatibilityLevel string   `json:"compatibility_level,omitempty"`
	Packages           []string `json:"packages"`
}

type ModuleTable struct {
	Major      int      `json:"major,omitempty"`
	Index      int      `json:"index"`
	Type       string   `json:"type"`
	Repository string   `json:"repository,omitempty"`
	Modules    []Module `json:"modules"`
	Source     string   `json:"source"`
}
