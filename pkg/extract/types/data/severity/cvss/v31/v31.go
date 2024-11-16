package v31

import (
	"cmp"

	gocvss31 "github.com/pandatix/go-cvss/31"
	"github.com/pkg/errors"
)

type CVSSv31 struct {
	Vector                string  `json:"vector,omitempty"`
	BaseScore             float64 `json:"base_score,omitempty"`
	BaseSeverity          string  `json:"base_severity,omitempty"`
	TemporalScore         float64 `json:"temporal_score,omitempty"`
	TemporalSeverity      string  `json:"temporal_severity,omitempty"`
	EnvironmentalScore    float64 `json:"environmental_score,omitempty"`
	EnvironmentalSeverity string  `json:"environmental_severity,omitempty"`
}

func Parse(vector string) (*CVSSv31, error) {
	c, err := gocvss31.ParseVector(vector)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", vector)
	}

	bscore := c.BaseScore()
	bseverity, err := gocvss31.Rating(bscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", bscore)
	}
	tscore := c.TemporalScore()
	tseverity, err := gocvss31.Rating(tscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", tscore)
	}
	escore := c.EnvironmentalScore()
	eseverity, err := gocvss31.Rating(escore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", escore)
	}

	cvss := CVSSv31{
		Vector:                vector,
		BaseScore:             bscore,
		BaseSeverity:          bseverity,
		TemporalScore:         tscore,
		TemporalSeverity:      tseverity,
		EnvironmentalScore:    escore,
		EnvironmentalSeverity: eseverity,
	}

	return &cvss, nil
}

func Compare(x, y CVSSv31) int {
	return cmp.Or(
		cmp.Compare(x.BaseScore, y.BaseScore),
		cmp.Compare(x.TemporalScore, y.TemporalScore),
		cmp.Compare(x.EnvironmentalScore, y.EnvironmentalScore),
		cmp.Compare(x.Vector, y.Vector),
	)
}
