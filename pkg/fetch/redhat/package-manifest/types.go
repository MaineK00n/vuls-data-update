package packagemanifest

type PackageTable struct {
	Major     string    `json:"major,omitempty"`
	Type      string    `json:"type"`
	Reference string    `json:"reference,omitempty"`
	Packages  []Package `json:"packages"`
}

type Package struct {
	Package             string `json:"package"`
	License             string `json:"license,omitempty"`
	CompatibilityLevel  string `json:"compatibility_level,omitempty"`
	MinorReleaseVersion string `json:"minor_release_version,omitempty"`
}

type ModuleTable struct {
	Major     string   `json:"major,omitempty"`
	Type      string   `json:"type"`
	Reference string   `json:"reference,omitempty"`
	Modules   []Module `json:"modules"`
}

type Module struct {
	Module             string   `json:"module"`
	Stream             string   `json:"stream"`
	CompatibilityLevel string   `json:"compatibility_level,omitempty"`
	Packages           []string `json:"packages"`
}
