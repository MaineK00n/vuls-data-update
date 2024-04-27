package epss

import (
	"cmp"
	"time"
)

type EPSS struct {
	Model      string    `json:"model,omitempty"`
	ScoreDate  time.Time `json:"score_date,omitempty"`
	EPSS       float64   `json:"epss,omitempty"`
	Percentile *float64  `json:"percentile,omitempty"`
}

func Compare(x, y EPSS) int {
	return cmp.Or(
		cmp.Compare(x.Model, y.Model),
		x.ScoreDate.Compare(y.ScoreDate),
	)
}
