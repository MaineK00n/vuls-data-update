package v30

import (
	gocvss30 "github.com/pandatix/go-cvss/30"
	"github.com/pkg/errors"
)

type CVSSv30 struct {
	Vector                string  `json:"vector,omitempty"`
	BaseScore             float64 `json:"base_score,omitempty"`
	BaseSeverity          string  `json:"base_severity,omitempty"`
	TemporalScore         float64 `json:"temporal_score,omitempty"`
	TemporalSeverity      string  `json:"temporal_severity,omitempty"`
	EnvironmentalScore    float64 `json:"environmental_score,omitempty"`
	EnvironmentalSeverity string  `json:"environmental_severity,omitempty"`
}

func Parse(vector string) (*CVSSv30, error) {
	c, err := gocvss30.ParseVector(vector)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", vector)
	}

	bscore := c.BaseScore()
	bseverity, err := gocvss30.Rating(bscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", bscore)
	}
	tscore := c.TemporalScore()
	tseverity, err := gocvss30.Rating(tscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", tscore)
	}
	escore := c.EnvironmentalScore()
	eseverity, err := gocvss30.Rating(escore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", escore)
	}

	cvss := CVSSv30{
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
