package tracker

type advisory struct {
	Candidate         string
	Description       []string
	UbuntuDescription []string
	Notes             []string
	Priority          string
	CVSS              []string
	Mitigation        []string
	Bugs              []string
	References        []string
	AssignedTo        string
	DiscoveredBy      string
	PublicDate        string
	PublicDateAtUSN   string
	CRD               string
	PkgPatches        map[string][]string
	PkgTags           []string
	PkgPriorities     []string
	PkgStatuses       []string
}

type Advisory struct {
	Candidate         string                        `json:"candidate"`
	Description       string                        `json:"description"`
	UbuntuDescription string                        `json:"ubuntu_description,omitempty"`
	Notes             map[string]string             `json:"notes,omitempty"`
	Priority          string                        `json:"priority"`
	CVSS              map[string]string             `json:"cvss,omitempty"`
	Mitigation        string                        `json:"mitigation,omitempty"`
	Bugs              []string                      `json:"bugs,omitempty"`
	References        []string                      `json:"references"`
	AssignedTo        string                        `json:"assigned_to,omitempty"`
	DiscoveredBy      string                        `json:"discovered_by,omitempty"`
	PublicDate        string                        `json:"public_date,omitempty"`
	PublicDateAtUSN   string                        `json:"public_date_at_usn,omitempty"`
	CRD               string                        `json:"crd,omitempty"`
	Packages          map[string]map[string]Package `json:"packages"`
}

type Package struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Note     string   `json:"note,omitempty"`
	Priority string   `json:"priority,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Patches  []Patch  `json:"patches,omitempty"`
}

type Patch struct {
	Source string `json:"source"`
	Text   string `json:"text,omitempty"`
}
