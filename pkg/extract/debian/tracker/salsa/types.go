package salsa

import "encoding/json/jsontext"

type bug struct {
	Header *struct {
		Line        string `json:"line,omitempty"`
		Name        string `json:"name,omitempty"`
		Description string `json:"description,omitempty"`
	} `json:"header,omitempty"`
	Annotations []jsontext.Value `json:"annotations,omitempty"`
}

type baseAnnotation struct {
	Type string `json:"type"`
}

type packageAnnotation struct {
	Line        string `json:"line,omitempty"`
	Type        string `json:"type,omitempty"`
	Release     string `json:"release,omitempty"`
	Package     string `json:"package,omitempty"`
	Kind        string `json:"kind,omitempty"`
	Version     string `json:"version,omitempty"`
	Description string `json:"description,omitempty"`
	Flags       []struct {
		Bug      *int    `json:"bug,omitempty"`
		Severity *string `json:"severity,omitempty"`
	} `json:"flags,omitempty"`
}
