package v2

import (
	"cmp"

	gocvss20 "github.com/pandatix/go-cvss/20"
	"github.com/pkg/errors"
)

type CVSSv2 struct {
	Vector                   string  `json:"vector,omitempty"`
	BaseScore                float64 `json:"base_score,omitempty"`
	NVDBaseSeverity          string  `json:"nvd_base_severity,omitempty"`
	TemporalScore            float64 `json:"temporal_score,omitempty"`
	NVDTemporalSeverity      string  `json:"nvd_temporal_severity,omitempty"`
	EnvironmentalScore       float64 `json:"environmental_score,omitempty"`
	NVDEnvironmentalSeverity string  `json:"nvd_environmental_severity,omitempty"`
}

func Parse(vector string) (*CVSSv2, error) {
	c, err := gocvss20.ParseVector(vector)
	if err != nil {
		return nil, errors.Wrapf(err, "parse %s", vector)
	}

	bscore := c.BaseScore()
	bseverity, err := rating(bscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", bscore)
	}
	tscore := c.TemporalScore()
	tseverity, err := rating(tscore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", tscore)
	}
	escore := c.EnvironmentalScore()
	eseverity, err := rating(escore)
	if err != nil {
		return nil, errors.Wrapf(err, "rating %.1f", escore)
	}

	cvss := CVSSv2{
		Vector:                   vector,
		BaseScore:                bscore,
		NVDBaseSeverity:          bseverity,
		TemporalScore:            tscore,
		NVDTemporalSeverity:      tseverity,
		EnvironmentalScore:       escore,
		NVDEnvironmentalSeverity: eseverity,
	}

	return &cvss, nil
}

func rating(score float64) (string, error) {
	if score < 0.0 || score > 10.0 {
		return "", errors.New("out of bounds score")
	}
	if score >= 7.0 {
		return "HIGH", nil
	}
	if score >= 4.0 {
		return "MEDIUM", nil
	}
	return "LOW", nil
}

func Compare(x, y CVSSv2) int {
	return cmp.Or(
		cmp.Compare(x.BaseScore, y.BaseScore),
		cmp.Compare(x.TemporalScore, y.TemporalScore),
		cmp.Compare(x.EnvironmentalScore, y.EnvironmentalScore),
		cmp.Compare(x.Vector, y.Vector),
	)
}
