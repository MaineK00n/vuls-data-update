package json

type accessTokenResponse struct {
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	AccessToken string `json:"access_token"`
	Scope       string `json:"scope"`
}

type advisories struct {
	Advisories []Advisory `json:"advisories"`
}

type Advisory struct {
	AdvisoryID     string      `json:"advisoryID"`
	AdvisoryTitle  string      `json:"advisoryTitle"`
	BugIDs         []string    `json:"bugIDs"`
	CsafURL        string      `json:"csafURL"`
	Cves           []string    `json:"cves"`
	CvrfURL        string      `json:"cvrfURL"`
	CvssBaseScore  string      `json:"cvssBaseScore"`
	Cwe            []string    `json:"cwe"`
	FirstPublished string      `json:"firstPublished"`
	IpsSignatures  interface{} `json:"ipsSignatures"`
	LastUpdated    string      `json:"lastUpdated"`
	ProductNames   []string    `json:"productNames"`
	PublicationURL string      `json:"publicationURL"`
	Sir            string      `json:"sir"`
	Status         string      `json:"status"`
	Summary        string      `json:"summary"`
	Version        string      `json:"version"`
}
