package epss

import "time"

type EPSS struct {
	Model      string    `json:"model,omitempty"`
	ScoreDate  time.Time `json:"score_date,omitempty"`
	EPSS       float64   `json:"epss,omitempty"`
	Percentile *float64  `json:"percentile,omitempty"`
}
