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
// the historical CVRF advisories (2012 through 2022) whose
// product_statuses/product_tree are empty upstream, so the CVRF document
// itself yields no detection. The rows were generated once from two
// Fortinet-authored sources and then frozen: the curated version ranges of
// the legacy vuls-data-raw-fortinet (handmade) dataset, and the
// affected-version data Fortinet publishes as a CNA in its cvelistV5 records.
// Where both sources cover an advisory, handmade rows win per product
// (curated ranges) and CNA rows fill the products handmade misses;
// disagreements were reviewed by hand. The gap is historical — from 2022 on
// Fortinet populates product_statuses (and publishes CSAF) — so the table is
// a frozen asset, not a maintained feed (mirroring how microsoft/bulletin
// compiles its frozen archive amendments in).

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

// supplementCriterions builds the detection criterions for an advisory from
// the supplement table, or nil when the advisory has no entry.
// Exact versions become CPEMatches on a wildcard-version product CPE (the
// same shape knownAffectedCriterions emits) and ranges become one range
// criterion each with the product's per-product range type (the same shape
// the CSAF extractor emits). The whitelist + hard-error policy applies: a
// table row whose product is missing from internal/product or whose version
// fails the numeric scheme fails the extract rather than silently dropping
// an affected product.
func supplementCriterions(id string) ([]criterionTypes.Criterion, error) {
	rows, ok := supplementTable[id]
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
			for _, b := range []string{r.GreaterEqual, r.GreaterThan, r.LessEqual, r.LessThan} {
				if b == "" {
					continue
				}
				if _, err := numericVersion.NewVersion(b); err != nil {
					return nil, errors.Wrapf(err, "unexpected range bound %q for %q in supplement entry %q", b, row.Product, id)
				}
			}
			// A lower bound above the upper bound (a transcription slip like
			// the legacy dataset's "ge 4.4.0, le 4.3.1") makes the criterion
			// unsatisfiable — a silent detection false negative — so reject
			// the row instead of emitting it.
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
			// Whole product: the wildcard-version CPE with no narrowing.
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
