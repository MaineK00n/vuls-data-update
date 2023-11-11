package msf

type module struct {
	Name               string                 `json:"name,omitempty"`
	Fullname           string                 `json:"fullname,omitempty"`
	Aliases            []string               `json:"aliases,omitempty"`
	Rank               int                    `json:"rank,omitempty"`
	DisclosureDate     string                 `json:"disclosure_date,omitempty"`
	Type               string                 `json:"type,omitempty"`
	Author             []string               `json:"author,omitempty"`
	Description        string                 `json:"description,omitempty"`
	References         []string               `json:"references,omitempty"`
	Platform           string                 `json:"platform,omitempty"`
	Arch               string                 `json:"arch,omitempty"`
	Rport              interface{}            `json:"rport,omitempty"` // int or string or null
	AutofilterPorts    []int                  `json:"autofilter_ports,omitempty"`
	AutofilterServices []string               `json:"autofilter_services,omitempty"`
	Targets            []string               `json:"targets,omitempty"`
	ModTime            string                 `json:"mod_time,omitempty"`
	Path               string                 `json:"path,omitempty"`
	IsInstallPath      bool                   `json:"is_install_path,omitempty"`
	RefName            string                 `json:"ref_name,omitempty"`
	Check              bool                   `json:"check,omitempty"`
	PostAuth           bool                   `json:"post_auth,omitempty"`
	DefaultCredential  bool                   `json:"default_credential,omitempty"`
	Notes              map[string]interface{} `json:"notes,omitempty"`         // map[string]string or map[string][]string
	SessionTypes       interface{}            `json:"session_types,omitempty"` // []string or false
	NeedsCleanup       interface{}            `json:"needs_cleanup,omitempty"` // false, true, null
}

type Module struct {
	Name               string              `json:"name,omitempty"`
	Fullname           string              `json:"fullname,omitempty"`
	Aliases            []string            `json:"aliases,omitempty"`
	Rank               int                 `json:"rank,omitempty"`
	DisclosureDate     string              `json:"disclosure_date,omitempty"`
	Type               string              `json:"type,omitempty"`
	Author             []string            `json:"author,omitempty"`
	Description        string              `json:"description,omitempty"`
	References         []string            `json:"references,omitempty"`
	Platform           string              `json:"platform,omitempty"`
	Arch               string              `json:"arch,omitempty"`
	Rport              *int                `json:"rport,omitempty"`
	AutofilterPorts    []int               `json:"autofilter_ports,omitempty"`
	AutofilterServices []string            `json:"autofilter_services,omitempty"`
	Targets            []string            `json:"targets,omitempty"`
	ModTime            string              `json:"mod_time,omitempty"`
	Path               string              `json:"path,omitempty"`
	IsInstallPath      bool                `json:"is_install_path,omitempty"`
	RefName            string              `json:"ref_name,omitempty"`
	Check              bool                `json:"check,omitempty"`
	PostAuth           bool                `json:"post_auth,omitempty"`
	DefaultCredential  bool                `json:"default_credential,omitempty"`
	Notes              map[string][]string `json:"notes,omitempty"`
	SessionTypes       []string            `json:"session_types,omitempty"`
	NeedsCleanup       *bool               `json:"needs_cleanup,omitempty"`
}
