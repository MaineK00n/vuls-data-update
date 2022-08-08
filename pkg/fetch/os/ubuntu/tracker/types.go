package tracker

import "time"

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
	Candidate         string            `json:"candidate"`
	Description       string            `json:"description"`
	UbuntuDescription string            `json:"ubuntu_description,omitempty"`
	Notes             map[string]string `json:"notes,omitempty"`
	Priority          string            `json:"priority"`
	CVSS              map[string]CVSS   `json:"cvss,omitempty"`
	Mitigation        string            `json:"mitigation,omitempty"`
	Bugs              []string          `json:"bugs,omitempty"`
	References        []string          `json:"references"`
	AssignedTo        string            `json:"assigned_to,omitempty"`
	DiscoveredBy      string            `json:"discovered_by,omitempty"`
	PublicDate        *time.Time        `json:"public_date,omitempty"`
	PublicDateAtUSN   *time.Time        `json:"public_date_at_usn,omitempty"`
	CRD               *time.Time        `json:"crd,omitempty"`
	Packages          []Package         `json:"packages"`
}

type CVSS struct {
	Vector   string  `json:"vector"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
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
