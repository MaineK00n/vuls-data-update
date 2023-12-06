package epss

type EPSS struct {
	Model     string `json:"model,omitempty"`
	ScoreDate string `json:"score_date,omitempty"`
	Data      []CVE  `json:"data,omitempty"`
}

type CVE struct {
	ID         string   `json:"id,omitempty"`
	EPSS       float64  `json:"epss,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}
