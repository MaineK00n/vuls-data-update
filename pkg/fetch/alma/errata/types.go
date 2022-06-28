package errata

type root struct {
	Data          []Erratum `json:"data"`
	SchemaVersion string    `json:"schema_version"`
}

type Erratum struct {
	Description string `json:"description"`
	ID          string `json:"id"`
	IssuedDate  int    `json:"issued_date"`
	Modules     []struct {
		Arch    string `json:"arch"`
		Context string `json:"context"`
		Name    string `json:"name"`
		Stream  string `json:"stream"`
		Version string `json:"version"`
	} `json:"modules"`
	Packages []struct {
		Arch            string `json:"arch"`
		Checksum        string `json:"checksum"`
		ChecksumType    string `json:"checksum_type"`
		Epoch           string `json:"epoch"`
		Filename        string `json:"filename"`
		Module          string `json:"module,omitempty"`
		Name            string `json:"name"`
		RebootSuggested int    `json:"reboot_suggested"`
		Release         string `json:"release"`
		Src             string `json:"src"`
		Version         string `json:"version"`
	} `json:"packages"`
	References []struct {
		Href string `json:"href"`
		ID   string `json:"id"`
		Type string `json:"type"`
	} `json:"references"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Type        string `json:"type"`
	UpdatedDate int    `json:"updated_date"`
}
