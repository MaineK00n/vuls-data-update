// Package product resolves Fortinet product names (shared between the CSAF and
// CVRF extractors) to CPEs and their per-product range types.
package product

import (
	"strconv"
	"strings"

	"github.com/knqyf263/go-cpe/common"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"

	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// Resolve returns the CPE 2.3 formatted string (wildcard version) and the
// per-product cpecriterion range type for a Fortinet product name, or ok=false
// when the name is not in the table. Fortinet uses one range type per product,
// so a product whose versioning scheme later diverges gets its own comparator
// without affecting any other product.
func Resolve(name string) (cpe string, rangeType ccRangeTypes.RangeType, ok bool) {
	p, ok := nameToProduct[strings.TrimSpace(name)]
	return p.cpe, p.rangeType, ok
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

// isConcrete reports whether v has 3 or more dot-separated components (i.e.
// at least two dots, e.g. 7.4.3). It is a purely format-level check with no
// product context, kept internal so that all classification goes through the
// product-aware IsExactVersion; TrainRange also uses it to reject inputs that
// cannot be a train under any product's versioning scheme.
func isConcrete(v string) bool {
	return strings.Count(v, ".") >= 2
}

// IsExactVersion reports whether ver is a concrete, enumerable release of the
// named product rather than a coarse release train. Most Fortinet products cut
// releases with three or more dot-separated components (e.g. FortiOS "7.4.3",
// FortiSASE "25.2.a"), so a one- or two-component token ("7", "7.4") is a
// train. A few products version their releases with two components (e.g.
// FortiAuthenticator OutlookAgent "2.1", IPS Engine "7.166", FortiSandbox
// Cloud "23.4"); those are marked twoComponentVersions in the table, and for
// them a two-component token is a concrete release — only a bare major ("24")
// is a train. The distinction cannot be made from the version string alone:
// the same "X.Y" shape is exact for FortiSandbox Cloud/PaaS but a train for
// FortiSandbox proper, even within a single advisory (e.g. FG-IR-26-136). An
// unknown product name falls back to the three-component rule.
func IsExactVersion(name, ver string) bool {
	if nameToProduct[strings.TrimSpace(name)].twoComponentVersions {
		return strings.Count(ver, ".") >= 1
	}
	return isConcrete(ver)
}

// TrainRange builds a range spanning an entire release train: ge train,
// lt <next train>, where <next> increments the train's last numeric component
// (7.0 -> 7.1, 7 -> 8). It errors when the input is a concrete version rather
// than a train, or when the last component is not numeric. The Range Type is left
// unset; the caller sets the per-product range type (it has the product, this
// helper does not).
func TrainRange(train string) (ccRangeTypes.Range, error) {
	// A train is 1-2 components ("7", "7.0"); a concrete version ("7.0.0") is not a
	// train. Incrementing its last component would silently narrow the range to a
	// single patch ("7.0.0" -> [7.0.0, 7.0.1)) instead of spanning a train, a
	// detection false negative, so reject it as unexpected input.
	if isConcrete(train) {
		return ccRangeTypes.Range{}, errors.Errorf("expected a release train (1-2 components), got concrete version %q", train)
	}
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
