// Package fortinet holds helpers shared by the Fortinet CSAF and CVRF
// extractors that are not about product/version resolution.
package fortinet

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

// YearDir derives the output year directory from a Fortinet advisory ID
// (FG-IR-<yy>-<number>). A 2-digit yy maps to 20yy; the legacy zero-padded
// 3-digit form (FG-IR-012-003) maps to 2yyy. Any other shape is an error.
func YearDir(id string) (string, error) {
	const format = "FG-IR-<yy>-<number>"

	ss, err := util.Split(id, "-", "-", "-")
	if err != nil {
		return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", format, id)
	}
	if ss[0] != "FG" || ss[1] != "IR" {
		return "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", format, id)
	}

	isDigits := func(s string) bool {
		for _, r := range s {
			if r < '0' || r > '9' {
				return false
			}
		}
		return s != ""
	}
	switch yy := ss[2]; {
	case len(yy) == 2 && isDigits(yy):
		return fmt.Sprintf("20%s", yy), nil
	case len(yy) == 3 && strings.HasPrefix(yy, "0") && isDigits(yy):
		return fmt.Sprintf("2%s", yy), nil
	default:
		return "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", format, id)
	}
}
