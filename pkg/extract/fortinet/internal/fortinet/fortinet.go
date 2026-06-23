// Package fortinet holds helpers shared by the Fortinet CSAF and CVRF
// extractors that are not about product/version resolution.
package fortinet

import (
	"strconv"
	"strings"
	"time"

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

	// The <number> segment is used verbatim in the output filename, so require
	// it to be numeric — otherwise it could carry path separators (e.g.
	// "FG-IR-24-0/../x") and escape the output directory.
	if _, err := strconv.Atoi(ss[3]); err != nil {
		return "", errors.Errorf("unexpected ID format. expected: %q, actual: %q", format, id)
	}

	// yy is a 2-digit year (24 -> 2024); the legacy zero-padded 3-digit form
	// (012 -> 2012) is normalised to its 2-digit year first. Let time.Parse do
	// the digit validation and year resolution.
	yy := ss[2]
	if len(yy) == 3 && strings.HasPrefix(yy, "0") {
		yy = yy[1:]
	}
	t, err := time.Parse("06", yy)
	if err != nil {
		return "", errors.Wrapf(err, "unexpected ID format. expected: %q, actual: %q", format, id)
	}
	return strconv.Itoa(t.Year()), nil
}
