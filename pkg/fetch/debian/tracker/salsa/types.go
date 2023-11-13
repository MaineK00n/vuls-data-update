package salsa

type CPE struct {
	Line    string `json:"line,omitempty"`
	Package string `json:"package,omitempty"`
	CPE     string `json:"cpe,omitempty"`
}

type Bug struct {
	Header      *Header       `json:"header,omitempty"`
	Annotations []interface{} `json:"annotations,omitempty"`
}

type Header struct {
	Line        string `json:"line,omitempty"`
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
}

type FlagAnnotation struct {
	Line string `json:"line,omitempty"`
	Type string `json:"type,omitempty"`
}

type StringAnnotation struct {
	Line        string `json:"line,omitempty"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type XrefAnnotation struct {
	Line string   `json:"line,omitempty"`
	Type string   `json:"type,omitempty"`
	Bugs []string `json:"bugs,omitempty"`
}

type PackageAnnotation struct {
	Line        string        `json:"line,omitempty"`
	Type        string        `json:"type,omitempty"`
	Release     string        `json:"release,omitempty"`
	Package     string        `json:"package,omitempty"`
	Kind        string        `json:"kind,omitempty"`
	Version     string        `json:"version,omitempty"`
	Description string        `json:"description,omitempty"`
	Flags       []interface{} `json:"flags,omitempty"`
}

type PackageBugAnnotation struct {
	Bug int `json:"bug,omitempty"`
}

type PackageUrgencyAnnotation struct {
	Severity string `json:"severity,omitempty"`
}

type config struct {
	Distributions map[string]struct {
		Release string `json:"release"`
	} `json:"distributions"`
}
