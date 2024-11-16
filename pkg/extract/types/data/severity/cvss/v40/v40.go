package v40

import (
	"cmp"

	gocvss40 "github.com/pandatix/go-cvss/40"
	"github.com/pkg/errors"
)

type CVSSv40 struct {
	Vector   string  `json:"vector,omitempty"`
	Score    float64 `json:"score,omitempty"`
	Severity string  `json:"severity,omitempty"`
}

func Parse(vector string) (*CVSSv40, error) {
	c, err := gocvss40.ParseVector(vector)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", vector)
	}

	score := c.Score()
	severity, err := gocvss40.Rating(score)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", score)
	}

	cvss := CVSSv40{
		Vector:   vector,
		Score:    score,
		Severity: severity,
	}

	return &cvss, nil
}

func Compare(x, y CVSSv40) int {
	return cmp.Or(
		cmp.Compare(x.Score, y.Score),
		cmp.Compare(x.Vector, y.Vector),
	)
}
