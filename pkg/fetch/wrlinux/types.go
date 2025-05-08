package wrlinux

type Vulnerability struct {
	PublicDateAtUSN      string               `json:"public_date_at_usn,omitempty"`
	CRD                  string               `json:"crd,omitempty"`
	Candidate            string               `json:"candidate,omitempty"`
	PublicDate           string               `json:"public_date,omitempty"`
	References           []string             `json:"references,omitempty"`
	Description          string               `json:"description,omitempty"`
	WindRiverDescription string               `json:"wind_river_description,omitempty"`
	Notes                []string             `json:"notes,omitempty"`
	Bugs                 []string             `json:"bugs,omitempty"`
	ReleaseVersions      []string             `json:"release_versions,omitempty"`
	Priority             string               `json:"priority,omitempty"`
	Patches              map[Package]Statuses `json:"patches,omitempty"`
	UpstreamLinks        map[Package][]string `json:"upstream_links,omitempty"`
}

type Package string

type Release string

type Statuses map[Release]Status

type Status struct {
	Status string `json:"status,omitempty"`
	Note   string `json:"note,omitempty"`
}
