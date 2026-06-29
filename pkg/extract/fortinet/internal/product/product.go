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

// RangeType returns the per-product cpecriterion range type for the product
// encoded in a CPE 2.3 formatted string (e.g. fortios -> RangeTypeFortinetFortios).
// Fortinet uses one range type per product so a product whose versioning scheme
// later diverges gets its own comparator without affecting any other product.
// It errors when cpe is not parseable or the product slug has no range type, so
// a new Fortinet product is noticed and added rather than silently mis-compared.
func RangeType(cpe string) (ccRangeTypes.RangeType, error) {
	wfn, err := naming.UnbindFS(cpe)
	if err != nil {
		return 0, errors.Wrapf(err, "unbind %q to WFN", cpe)
	}
	// GetString returns the WFN value with CPE special characters (e.g. "-")
	// backslash-escaped; strip the escapes to recover the bare product slug.
	slug := strings.ReplaceAll(wfn.GetString(common.AttributeProduct), `\`, "")
	rt, ok := ccRangeTypes.FortinetRangeTypeBySlug(slug)
	if !ok {
		return 0, errors.Errorf("no range type for fortinet product slug %q (cpe %q); add it to cpecriterion/range", slug, cpe)
	}
	return rt, nil
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

// TrainRange builds a range spanning an entire release train: ge train,
// lt <next train>, where <next> increments the train's last numeric component
// (7.0 -> 7.1, 7 -> 8). It errors when that component is not numeric. The Range
// Type is left unset; the caller sets the per-product range type (it has the
// product, this helper does not).
func TrainRange(train string) (ccRangeTypes.Range, error) {
	ss := strings.Split(train, ".")
	last, err := strconv.Atoi(ss[len(ss)-1])
	if err != nil {
		return ccRangeTypes.Range{}, errors.Wrapf(err, "non-numeric train %q", train)
	}
	ss[len(ss)-1] = strconv.Itoa(last + 1)
	return ccRangeTypes.Range{
		GreaterEqual: train,
		LessThan:     strings.Join(ss, "."),
	}, nil
}
