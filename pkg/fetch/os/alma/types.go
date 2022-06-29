package alma

type Root struct {
	// SchemaVersion string `json:"schema_version"`
	Data []Erratum `json:"data"`
}

type Erratum struct {
	ID          string `json:"id"`
	IssuedDate  int    `json:"issued_date"`
	UpdatedDate int    `json:"updated_date"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Packages    []struct {
		Name            string `json:"name"`
		Epoch           string `json:"epoch"`
		Version         string `json:"version"`
		Release         string `json:"release"`
		Arch            string `json:"arch"`
		Src             string `json:"src"`
		Filename        string `json:"filename"`
		Checksum        string `json:"checksum"`
		ChecksumType    string `json:"checksum_type"`
		RebootSuggested int    `json:"reboot_suggested"`
	} `json:"packages"`
	Modules []struct {
		Name    string `json:"name"`
		Arch    string `json:"arch"`
		Stream  string `json:"stream"`
		Version string `json:"version"`
		Context string `json:"context"`
	} `json:"modules"`
	References []struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Href string `json:"href"`
	} `json:"references"`
}
