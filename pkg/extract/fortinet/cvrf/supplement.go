package cvrf

import (
	"cmp"

	"github.com/pkg/errors"
	numericVersion "github.com/vulsio/go-fortinet-version/numeric"

	productpkg "github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/product"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	fixstatusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/fixstatus"
)

// supplementTable (supplement_data.go) carries the affected-product data for
// the CVRF advisories whose product_statuses/product_tree are empty upstream,
// so the CVRF document itself yields no detection. Fortinet did not switch
// over on a date, so the two shapes overlap: filled documents go as far back
// as FG-IR-16-035, but through 2021 they are the exception (21 filled against
// 123 empty), 2022 is where it flips (155 filled against 13 empty), and from
// FG-IR-23-* on every document carries product_statuses. That leaves the 427
// advisories numbered FG-IR-012-* through FG-IR-22-* in this table, a set
// that only shrinks if Fortinet backfills an old document. The rows are not
// frozen either: they state what the advisory says, and an advisory whose
// note is read differently later is re-read.
//
// A row's authority is the advisory's own Affected Products note, with the
// affected-version data Fortinet publishes as a CNA in its cvelistV5 records
// as the second source: a row covers what the note claims, plus what the CNA
// record adds for that product. Of the 721 rows, 549 have a version in their
// note, 34 rest on the CNA record alone, and 138 have neither — the note
// names the product without a version, or gives no version at all — and keep
// the ranges the table was seeded with. That seed was the curated ranges of
// the legacy vuls-data-raw-fortinet (handmade) dataset, which is no longer a
// source: it expressed "<v> and below" as an open-ended bound and stopped
// "<train> all versions" at whatever release existed when it was curated,
// neither of which is what the advisories say.
//
// How the notes' wording maps onto rows:
//
//   - "<v> and below/earlier" bounds the train it names — ge <train>.0,
//     le <v>. Fortinet's own CNA records read it that way: across the
//     records for these advisories, 58 entries bound their lowest affected
//     train explicitly against 4 that leave it open.
//   - "<train> all versions" / "<train>.x" is the whole train, in the shape
//     product.TrainRange emits for the CSAF source (ge "6.0", lt "6.1"), so
//     a later release of an EOL train cannot fall out of range.
//   - "all versions below <v>" is open-ended below, and "<a> through <b>"
//     is exactly that.
//
// A handful of notes cannot be expressed in versions at all — an impact
// scoped to hardware models (FG-IR-19-224 to the FortiSwitch 424E/426E/448E,
// FG-IR-20-036 to the FortiAnalyzer models that manage a FortiRecorder) or
// to a configuration (FG-IR-16-090 to the default TCP timestamp setting).
// Those rows carry the version bound the note gives and say so in a comment.
//
// Scope: rows are advisory-granular; per-CVE attribution is deliberately
// not modeled. A few multi-CVE advisories scope products per CVE in their
// notes (FG-IR-15-008, -16-026, -17-104, -17-127, -17-196, -19-007,
// -19-238 — e.g. FG-IR-16-026 says "FortiAP is not affected" by
// CVE-2016-2108 while the advisory's other CVEs do affect it), so a hit
// there correctly reports the advisory but lists all of its CVEs. The
// advisory's remediation is the same either way, and the product_statuses
// path — whose upstream data is advisory-level — sets this source's
// granularity; per-CVE tags are the CSAF source's job for the advisories
// that have them.

// supplementRange mirrors cpecriterion/range bounds; the range type is not in
// the data — it is the per-product type from the product table.
type supplementRange struct {
	GreaterEqual string
	GreaterThan  string
	LessEqual    string
	LessThan     string
}

// supplementProduct is one affected product of a supplemented advisory:
// enumerated exact versions and/or version ranges. A row with neither means
// the whole product is affected — such rows match every version and were
// each audited against the advisory text and CVE/NVD records (the verdict is
// on the row in supplement_data.go; the generator refuses to emit an
// unaudited one).
type supplementProduct struct {
	Product  string
	Versions []string
	Ranges   []supplementRange
}

// advisoryProduct keys the whole-product allowlist below. The fields are
// exported only so the external test package can read the allowlist through
// its export_test.go alias (the type itself stays package-private, like
// supplementProduct's fields).
type advisoryProduct struct {
	Advisory string
	Product  string
}

// wholeProductAudited is the closed set of supplement rows allowed to emit a
// whole-product criterion (no version constraint — it matches every version
// of the product, the largest false-positive surface in the table). Each pair
// was audited individually against the advisory text and CVE/NVD records; the
// verdict is on the row in supplement_data.go. A row with no versions and no
// ranges outside this list fails the extract, so a hand edit that drops a
// row's constraints by accident cannot silently widen detection to the whole
// product — extend this list only with a fresh audit.
var wholeProductAudited = map[advisoryProduct]struct{}{
	{"FG-IR-14-010", "FortiBalancer"}:      {},
	{"FG-IR-14-031", "FortiADC"}:           {},
	{"FG-IR-14-031", "FortiClientWindows"}: {},
	{"FG-IR-14-031", "FortiDB"}:            {},
	{"FG-IR-14-031", "FortiMail"}:          {},
	{"FG-IR-14-031", "FortiOS"}:            {},
	{"FG-IR-14-031", "FortiRecorder"}:      {},
	{"FG-IR-14-031", "FortiSwitch"}:        {},
	{"FG-IR-14-031", "FortiVoice"}:         {},
	{"FG-IR-15-007", "FortiMail"}:          {},
	{"FG-IR-16-041", "FortiClientSSLVPN"}:  {},
	{"FG-IR-16-069", "FortiClientSSLVPN"}:  {},
	{"FG-IR-16-090", "FortiOS"}:            {},
}

// supplementCriterions builds the detection criterions for an advisory from
// the given supplement table (supplementTable in production; tests inject
// synthetic tables), or nil when the advisory has no entry.
// Exact versions become CPEMatches on a wildcard-version product CPE (the
// same shape knownAffectedCriterions emits) and ranges become one range
// criterion each with the product's per-product range type (the same shape
// the CSAF extractor emits). The whitelist + hard-error policy applies: a
// table row whose product is missing from internal/product or whose version
// fails the numeric scheme fails the extract rather than silently dropping
// an affected product.
func supplementCriterions(table map[string][]supplementProduct, id string) ([]criterionTypes.Criterion, error) {
	rows, ok := table[id]
	if !ok {
		return nil, nil
	}

	criterions := make([]criterionTypes.Criterion, 0, len(rows))
	for _, row := range rows {
		cpe, rt, ok := productpkg.Resolve(row.Product)
		if !ok {
			return nil, errors.Errorf("unknown fortinet product %q in supplement entry %q (add it to internal/product)", row.Product, id)
		}

		if len(row.Versions) > 0 {
			baked := make([]ccTypes.CPE, 0, len(row.Versions))
			for _, v := range row.Versions {
				// Every supplement version is numeric (validated at generation
				// time); re-assert here so a bad table edit fails the extract
				// instead of baking a version no scanner reports.
				if _, err := numericVersion.NewVersion(v); err != nil {
					return nil, errors.Wrapf(err, "unexpected version %q for %q in supplement entry %q", v, row.Product, id)
				}
				b, err := productpkg.BakeVersion(cpe, v)
				if err != nil {
					return nil, errors.Wrapf(err, "bake version %q for %q in supplement entry %q", v, row.Product, id)
				}
				baked = append(baked, ccTypes.CPE(b))
			}
			criterions = append(criterions, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE(cpe),
					CPEMatches: baked,
				},
			})
		}

		for _, sr := range row.Ranges {
			r := ccRangeTypes.Range{
				Type:         rt,
				GreaterEqual: sr.GreaterEqual,
				GreaterThan:  sr.GreaterThan,
				LessEqual:    sr.LessEqual,
				LessThan:     sr.LessThan,
			}
			// A range with no bounds at all never matches anything (the
			// evaluator treats a bound-less range as empty, not as
			// match-all) — the same silent-false-negative class as an
			// inverted range, and the likeliest shape of a hand edit that
			// blanks a row's constraints without deleting the range.
			if cmp.Or(r.GreaterEqual, r.GreaterThan, r.LessEqual, r.LessThan) == "" {
				return nil, errors.Errorf("empty range for %q in supplement entry %q: no bounds set", row.Product, id)
			}
			for _, b := range []string{r.GreaterEqual, r.GreaterThan, r.LessEqual, r.LessThan} {
				if b == "" {
					continue
				}
				if _, err := numericVersion.NewVersion(b); err != nil {
					return nil, errors.Wrapf(err, "unexpected range bound %q for %q in supplement entry %q", b, row.Product, id)
				}
			}
			// A lower bound above the upper bound makes the criterion
			// unsatisfiable — a silent detection false negative. The source
			// data really carried such rows (the legacy dataset had
			// "ge 4.4.0, le 4.3.1"); the generator rejects them at
			// table-generation time, so this check guards the other editing
			// path: supplement_data.go is maintained as ordinary source, and
			// TestSupplementTableInvariants walks the whole table through
			// here, turning a bad hand edit into a test failure instead of a
			// criterion that never matches.
			if lo, hi := cmp.Or(r.GreaterEqual, r.GreaterThan), cmp.Or(r.LessEqual, r.LessThan); lo != "" && hi != "" {
				vlo, err := numericVersion.NewVersion(lo)
				if err != nil {
					return nil, errors.Wrapf(err, "parse lower bound %q for %q in supplement entry %q", lo, row.Product, id)
				}
				vhi, err := numericVersion.NewVersion(hi)
				if err != nil {
					return nil, errors.Wrapf(err, "parse upper bound %q for %q in supplement entry %q", hi, row.Product, id)
				}
				c, err := vlo.Compare(vhi)
				if err != nil {
					return nil, errors.Wrapf(err, "compare bounds %q, %q for %q in supplement entry %q", lo, hi, row.Product, id)
				}
				if c > 0 {
					return nil, errors.Errorf("inverted range for %q in supplement entry %q: lower bound %q > upper bound %q", row.Product, id, lo, hi)
				}
			}
			criterions = append(criterions, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE(cpe),
					Range:      &r,
				},
			})
		}

		if len(row.Versions) == 0 && len(row.Ranges) == 0 {
			// Whole product: the wildcard-version CPE with no narrowing —
			// only the audited pairs may take this branch (see
			// wholeProductAudited).
			if _, ok := wholeProductAudited[advisoryProduct{Advisory: id, Product: row.Product}]; !ok {
				return nil, errors.Errorf("unaudited whole-product row for %q in supplement entry %q (add versions or ranges, or audit it into wholeProductAudited)", row.Product, id)
			}
			criterions = append(criterions, criterionTypes.Criterion{
				Type: criterionTypes.CriterionTypeCPE,
				CPE: &ccTypes.Criterion{
					Vulnerable: true,
					FixStatus:  &fixstatusTypes.FixStatus{Class: fixstatusTypes.ClassUnknown},
					CPE:        ccTypes.CPE(cpe),
				},
			})
		}
	}
	return criterions, nil
}
