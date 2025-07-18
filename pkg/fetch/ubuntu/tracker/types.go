package tracker

type Advisory struct {
	Candidate         string              `json:"candidate"`
	Description       string              `json:"description,omitempty"`
	UbuntuDescription string              `json:"ubuntu_description,omitempty"`
	Notes             []string            `json:"notes,omitempty"`
	Priority          *Priority           `json:"priority,omitempty"`
	CVSS              map[string][]string `json:"cvss,omitempty"`
	Mitigation        []string            `json:"mitigation,omitempty"`
	Bugs              []string            `json:"bugs,omitempty"`
	References        []string            `json:"references,omitempty"`
	Tags              []string            `json:"tags,omitempty"`
	AssignedTo        string              `json:"assigned_to,omitempty"`
	DiscoveredBy      string              `json:"discovered_by,omitempty"`
	PublicDate        string              `json:"public_date,omitempty"`
	PublicDateAtUSN   string              `json:"public_date_at_usn,omitempty"`
	CRD               string              `json:"crd,omitempty"`
	Packages          map[string]Package  `json:"packages,omitempty"`
}

type Priority struct {
	Priority string   `json:"priority"`
	Reasons  []string `json:"reasons,omitempty"`
}

type Package struct {
	Priority *Priority          `json:"priority,omitempty"`
	Tags     []string           `json:"tags,omitempty"`
	Releases map[string]Release `json:"releases,omitempty"`
	Patches  []Patch            `json:"patches,omitempty"`
}

type Release struct {
	Priority *Priority `json:"priority,omitempty"`
	Tags     []string  `json:"tags,omitempty"`
	Status   string    `json:"status"`
	Note     string    `json:"note,omitempty"`
}

type Patch struct {
	Source string `json:"source"`
	Text   string `json:"text"`
}
