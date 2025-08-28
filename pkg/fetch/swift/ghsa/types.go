package ghsa

type GHSA struct {
	SchemaVersion string   `json:"schema_version,omitempty"`
	ID            string   `json:"id,omitempty"`
	Modified      string   `json:"modified,omitempty"`
	Published     string   `json:"published,omitempty"`
	Withdrawn     string   `json:"withdrawn,omitempty"`
	Aliases       []string `json:"aliases,omitempty"`
	Related       []string `json:"related,omitempty"`
	Summary       string   `json:"summary,omitempty"`
	Details       string   `json:"details,omitempty"`
	Severity      []struct {
		Type  string `json:"type,omitempty"`
		Score string `json:"score,omitempty"`
	} `json:"severity,omitempty"`
	Affected   []Affected `json:"affected,omitempty"`
	References []struct {
		Type string `json:"type,omitempty"`
		URL  string `json:"url,omitempty"`
	} `json:"references,omitempty"`
	Credits []struct {
		Name    string   `json:"name,omitempty"`
		Contact []string `json:"contact,omitempty"`
		Type    string   `json:"type,omitempty"`
	} `json:"credits,omitempty"`
	DatabaseSpecific interface{} `json:"database_specific,omitempty"`
}

type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem,omitempty"`
		Name      string `json:"name,omitempty"`
		PURL      string `json:"purl,omitempty"`
	} `json:"package,omitempty"`
	Severity []struct {
		Type  string `json:"type,omitempty"`
		Score string `json:"score,omitempty"`
	} `json:"severity,omitempty"`
	Ranges []struct {
		Type   string `json:"type,omitempty"`
		Repo   string `json:"repo,omitempty"`
		Events []struct {
			Introduced   string `json:"introduced,omitempty"`
			Fixed        string `json:"fixed,omitempty"`
			LastAffected string `json:"last_affected,omitempty"`
			Limit        string `json:"limit,omitempty"`
		} `json:"events,omitempty"`
	} `json:"ranges,omitempty"`
	Versions          []string    `json:"versions,omitempty"`
	EcosystemSpecific interface{} `json:"ecosystem_specific,omitempty"`
	DatabaseSpecific  interface{} `json:"database_specific,omitempty"`
}
