package emb3d

type threats struct {
	Threats []Threat `json:"threats"`
}

type Threat struct {
	ID         string `json:"id"`
	Text       string `json:"text"`
	Category   string `json:"category"`
	Properties []struct {
		ID string `json:"id"`
	} `json:"properties"`
	Mitigations []struct {
		ID string `json:"id"`
	} `json:"mitigations"`
}

type mitigations struct {
	Mitigations []Mitigation `json:"mitigations"`
}

type Mitigation struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Text    string `json:"text"`
	Level   string `json:"level"`
	Threats []struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	} `json:"threats"`
}

type properties struct {
	Properties []Property `json:"properties"`
}

type Property struct {
	ID           string   `json:"id"`
	Text         string   `json:"text"`
	Category     string   `json:"category"`
	IsparentProp bool     `json:"isparentProp"`
	SubProps     []string `json:"subProps"`
	ParentProp   string   `json:"parentProp"`
	Threats      []struct {
		ID   string `json:"id"`
		Text string `json:"text"`
	} `json:"threats"`
}
