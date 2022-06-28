package netbsd

type Vulnerability struct {
	Package       string `json:"package,omitempty"`
	TypeOfExploit string `json:"type_of_exploit,omitempty"`
	URL           string `json:"url,omitempty"`
}
