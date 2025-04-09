package usndb

type USN struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Summary     string   `json:"summary"`
	Isummary    string   `json:"isummary"`
	Description string   `json:"description"`
	Action      string   `json:"action"`
	CVEs        []string `json:"cves"`
	Releases    map[string]struct {
		AllBinaries map[string]struct {
			Pocket  string  `json:"pocket"`
			Source  *string `json:"source,omitempty"`
			Version string  `json:"version"`
		} `json:"allbinaries"`
		Binaries map[string]struct {
			Pocket  string  `json:"pocket"`
			Source  *string `json:"source,omitempty"`
			Version string  `json:"version"`
		} `json:"binaries"`
		Archs map[string]struct {
			URLs map[string]struct {
				MD5  string `json:"md5"`
				Size int    `json:"size"`
			} `json:"urls"`
		} `json:"archs,omitempty"`
		Sources map[string]struct {
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"sources"`
	}
	Timestamp float64 `json:"timestamp"`
}
