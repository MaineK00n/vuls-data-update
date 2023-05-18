package arch

type vulnerabilityGroups []VulnerabilityGroup

type VulnerabilityGroup struct {
	Advisories []string `json:"advisories"`
	Affected   string   `json:"affected"`
	Fixed      *string  `json:"fixed"`
	Issues     []string `json:"issues"`
	Name       string   `json:"name"`
	Packages   []string `json:"packages"`
	Severity   string   `json:"severity"`
	Status     string   `json:"status"`
	Ticket     *string  `json:"ticket"`
	Type       string   `json:"type"`
}
