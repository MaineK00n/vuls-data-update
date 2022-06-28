package epss

type EPSS struct {
	ID         string  `json:"id,omitempty"`
	Model      string  `json:"model,omitempty"`
	ScoreDate  string  `json:"score_date,omitempty"`
	EPSS       float64 `json:"epss,omitempty"`
	Percentile float64 `json:"percentile,omitempty"`
}
