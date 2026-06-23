// Package product resolves Fortinet product names (shared between the CSAF and
// CVRF extractors) to CPEs and classifies their version tokens.
package product

import (
	"strconv"
	"strings"

	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// ToCPE returns the CPE 2.3 formatted string (wildcard version) for a Fortinet
// product name, or ("", false) when the name is not in the table. Callers
// should log and record unknown names rather than fabricate a CPE.
func ToCPE(name string) (string, bool) {
	cpe, ok := nameToCPE[strings.TrimSpace(name)]
	return cpe, ok
}

// BakeVersion returns cpe with its version attribute set to the concrete
// version string (dots/hyphens escaped per CPE WFN rules), e.g.
// ("cpe:2.3:o:fortinet:fortios:*:...", "7.4.3") -> the same CPE pinned to
// 7.4.3. Mirrors go-cve-dictionary's fetcher/fortinet version handling.
func BakeVersion(cpe, version string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	if err := wfn.Set("version", strings.NewReplacer(".", `\.`, "-", `\-`).Replace(version)); err != nil {
		return "", errors.Wrapf(err, "set version %q", version)
	}
	return naming.BindToFS(wfn), nil
}

// IsConcrete reports whether v is a concrete release (3 or more dotted
// components, e.g. 7.4.3) as opposed to a release train (7 or 7.4).
func IsConcrete(v string) bool {
	return strings.Count(v, ".") >= 2
}

// TrainRange builds a "fortinet"-typed range spanning an entire release train:
// ge train, lt <next train>, where <next> increments the train's last numeric
// component (7.0 -> 7.1, 7 -> 8, 24 -> 25). The train may be single-segment
// ("24", as FortiSandbox Cloud uses) or dotted ("7.2"); it errors when the last
// component is not numeric. (util.Split is deliberately not used here: it
// requires the "." delimiter to be present and would reject single-segment
// trains.)
func TrainRange(train string) (ccRangeTypes.Range, error) {
	// LastIndex returns -1 when there is no ".", so prefix is "" and last is
	// the whole token — exactly the single-segment behaviour we want.
	i := strings.LastIndex(train, ".")
	prefix, lastComponent := train[:i+1], train[i+1:]
	last, err := strconv.Atoi(lastComponent)
	if err != nil {
		return ccRangeTypes.Range{}, errors.Wrapf(err, "non-numeric train %q", train)
	}
	return ccRangeTypes.Range{
		Type:         ccRangeTypes.RangeTypeFortinet,
		GreaterEqual: train,
		LessThan:     prefix + strconv.Itoa(last+1),
	}, nil
}
