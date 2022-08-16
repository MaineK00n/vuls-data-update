package epss

import "time"

type Scores struct {
	Model     string     `json:"model"`
	ScoreDate *time.Time `json:"score_date,omitempty"`
	Scores    []EPSS     `json:"scores"`
}

type EPSS struct {
	ID         string  `json:"id"`
	EPSS       float64 `json:"epss"`
	Percentile float64 `json:"percentile"`
}
