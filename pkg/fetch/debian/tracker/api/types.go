package api

type advisories map[string]map[string]struct {
	Description string `json:"description"`
	DebianBug   *int   `json:"debianbug"`
	Scope       string `json:"scope"`
	Release     map[string]struct {
		Status       string            `json:"status"`
		Repositories map[string]string `json:"repositories"`
		FixedVersion string            `json:"fixed_version"`
		Urgency      string            `json:"urgency"`
		NoDSA        string            `json:"nodsa"`
		NoDSAReason  string            `json:"nodsa_reason"`
	} `json:"releases"`
}

type Advisory struct {
	ID          string    `json:"id"`
	Description string    `json:"description,omitempty"`
	DebianBug   *int      `json:"debian_bug,omitempty"`
	Scope       string    `json:"scope,omitempty"`
	Packages    []Package `json:"packages"`
}

type Package struct {
	Name         string       `json:"name"`
	Status       string       `json:"status"`
	NoDSA        string       `json:"nodsa,omitempty"`
	NoDSAReason  string       `json:"nodsa_reason,omitempty"`
	Urgency      string       `json:"urgency"`
	FixedVersion string       `json:"fixed_version,omitempty"`
	Repository   []Repository `json:"repository"`
}

type Repository struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
