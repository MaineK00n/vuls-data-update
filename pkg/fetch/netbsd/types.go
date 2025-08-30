package netbsd

type Vulnerability struct {
	URL      string    `json:"url,omitempty"`
	Packages []Package `json:"packages,omitempty"`
}

type Package struct {
	Condition     string `json:"condition,omitempty"`
	TypeOfExploit string `json:"type_of_exploit,omitempty"`
}
