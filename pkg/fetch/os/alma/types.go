package alma

import "time"

type Root struct {
	// SchemaVersion string `json:"schema_version"`
	Data []erratum `json:"data"`
}

type erratum struct {
	ID          string      `json:"id,omitempty"`
	IssuedDate  int         `json:"issued_date,omitempty"`
	UpdatedDate int         `json:"updated_date,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
	Type        string      `json:"type,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	Modules     []Module    `json:"modules,omitempty"`
	References  []Reference `json:"references,omitempty"`
}

type Advisory struct {
	ID          string      `json:"id,omitempty"`
	Type        string      `json:"type,omitempty"`
	Title       string      `json:"title,omitempty"`
	Description string      `json:"description,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Packages    []Package   `json:"packages,omitempty"`
	Modules     []Module    `json:"modules,omitempty"`
	References  []Reference `json:"references,omitempty"`
	IssuedDate  *time.Time  `json:"issued_date,omitempty"`
	UpdatedDate *time.Time  `json:"updated_date,omitempty"`
}

type Package struct {
	Name            string `json:"name,omitempty"`
	Epoch           string `json:"epoch,omitempty"`
	Version         string `json:"version,omitempty"`
	Release         string `json:"release,omitempty"`
	Arch            string `json:"arch,omitempty"`
	Src             string `json:"src,omitempty"`
	Filename        string `json:"filename,omitempty"`
	Checksum        string `json:"checksum,omitempty"`
	ChecksumType    string `json:"checksum_type,omitempty"`
	RebootSuggested int    `json:"reboot_suggested"`
	Module          string `json:"module,omitempty"`
}

type Module struct {
	Name    string `json:"name,omitempty"`
	Arch    string `json:"arch,omitempty"`
	Stream  string `json:"stream,omitempty"`
	Version string `json:"version,omitempty"`
	Context string `json:"context,omitempty"`
}

type Reference struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
	Href string `json:"href,omitempty"`
}
