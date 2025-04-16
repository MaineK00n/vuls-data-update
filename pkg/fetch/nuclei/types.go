package nuclei

type CVE struct {
	ID   string `json:"ID"`
	Info struct {
		Name           string `json:"Name"`
		Severity       string `json:"Severity"`
		Description    string `json:"Description"`
		Classification struct {
			CVSSScore string `json:"CVSSScore"`
		} `json:"Classification"`
	} `json:"Info"`
	FilePath string `json:"file_path"`
}
