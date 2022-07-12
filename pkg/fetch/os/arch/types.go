package arch

type vulnerabilityGroups []VulnerabilityGroup

type VulnerabilityGroup struct {
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Status     string   `json:"status"`
	Severity   string   `json:"severity"`
	Type       string   `json:"type"`
	Affected   string   `json:"affected"`
	Fixed      string   `json:"fixed"`
	Ticket     string   `json:"ticket"`
	Issues     []string `json:"issues"`
	Advisories []string `json:"advisories"`
}
