// Package product resolves Fortinet product names (shared between the CSAF and
// CVRF extractors) to CPEs.
package product

import (
	"strconv"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// nonNumericVersionedCPEProducts holds the CPE product slugs of the Fortinet
// products whose versions are NOT purely numeric (digits and dots) — they can
// carry an alphabetic component. That non-numeric component is the whole point:
// a version like "25.2.a" cannot be ordered against a multi-component numeric
// bound (the comparator's undefined "numeric vs alphabetic at the same position"
// case), so these products' advisory ranges must stay train-granular (the CSAF
// extractor asserts this).
//
// Today the only such product is FortiSASE, which uses a YY.N.<letter> scheme
// (e.g. "25.2.a") — verified as the sole non-numeric-versioned product across
// the CSAF and CVRF corpora. FortiSandbox is deliberately absent: its Cloud
// variant is also non-numeric-versioned but shares the "fortisandbox" slug with
// the numeric appliance, so the slug cannot single it out.
var nonNumericVersionedCPEProducts = map[string]struct{}{
	"fortisase": {},
}

// IsNonNumericVersioned reports whether the product encoded in a CPE 2.3
// formatted string has versions that are not purely numeric (see
// nonNumericVersionedCPEProducts). It errors when cpe is not a parseable CPE.
func IsNonNumericVersioned(cpe string) (bool, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return false, errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	_, ok := nonNumericVersionedCPEProducts[wfn.GetString(common.AttributeProduct)]
	return ok, nil
}

// ToCPE returns the CPE 2.3 formatted string (wildcard version) for a Fortinet
// product name, or ("", false) when the name is not in the table. Callers
// decide how to handle a miss rather than fabricate a CPE; the CVRF extractor,
// for one, treats an unknown affected product as a hard error.
func ToCPE(name string) (string, bool) {
	cpe, ok := nameToCPE[strings.TrimSpace(name)]
	return cpe, ok
}

// versionEscaper escapes the CPE WFN special characters (dots and hyphens) in a
// concrete version string. It is stateless and safe for concurrent use, so it
// is shared rather than rebuilt on every BakeVersion call.
var versionEscaper = strings.NewReplacer(".", `\.`, "-", `\-`)

// BakeVersion returns cpe with its version attribute set to the concrete
// version string (dots/hyphens escaped per CPE WFN rules), e.g.
// ("cpe:2.3:o:fortinet:fortios:*:...", "7.4.3") -> the same CPE pinned to
// 7.4.3. Mirrors go-cve-dictionary's fetcher/fortinet version handling.
func BakeVersion(cpe, version string) (string, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return "", errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	if err := wfn.Set(common.AttributeVersion, versionEscaper.Replace(version)); err != nil {
		return "", errors.Wrapf(err, "set version %q", version)
	}
	return naming.BindToFS(wfn), nil
}

// IsConcrete reports whether v is a concrete release (3 or more
// dot-separated components, i.e. at least two dots, e.g. 7.4.3) as opposed
// to a release train (7 or 7.4).
func IsConcrete(v string) bool {
	return strings.Count(v, ".") >= 2
}

// TrainRange builds a "fortinet"-typed range spanning an entire release train:
// ge train, lt <next train>, where <next> increments the train's last numeric
// component (7.0 -> 7.1, 7 -> 8). It errors when that component is not numeric.
func TrainRange(train string) (ccRangeTypes.Range, error) {
	ss := strings.Split(train, ".")
	last, err := strconv.Atoi(ss[len(ss)-1])
	if err != nil {
		return ccRangeTypes.Range{}, errors.Wrapf(err, "non-numeric train %q", train)
	}
	ss[len(ss)-1] = strconv.Itoa(last + 1)
	return ccRangeTypes.Range{
		Type:         ccRangeTypes.RangeTypeFortinet,
		GreaterEqual: train,
		LessThan:     strings.Join(ss, "."),
	}, nil
}
