// Command print-enums prints every enum value of the extracted-data schema
// known to this build, one per line as
// "<module-relative package path>.<type>\t<value>"
// (e.g. "pkg/extract/types/data/severity.SeverityType\tvendor").
//
// Consumers (vuls2, vuls0) run this command twice — once without a version so
// it resolves through their own go.mod, and once at vuls-data-update HEAD
// (e.g. @main / @nightly) — and diff the outputs in CI to detect enum
// additions that require a dependency bump:
//
//	diff \
//	  <(go run github.com/MaineK00n/vuls-data-update/tools/print-enums) \
//	  <(go run github.com/MaineK00n/vuls-data-update/tools/print-enums@main)
//
// Values are sorted per enum so the output is diff-stable across builds.
package main

import (
	"fmt"
	"slices"

	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
	cpecriterionrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	necTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	vcPackageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
)

func main() {
	printEnum("pkg/extract/types/data/detection/condition/criteria", "CriteriaOperatorType", criteriaTypes.CriteriaOperatorTypes())
	printEnum("pkg/extract/types/data/detection/condition/criteria/criterion", "CriterionType", criterionTypes.CriterionTypes())
	printEnum("pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range", "RangeType", cpecriterionrangeTypes.RangeTypes())
	printEnum("pkg/extract/types/data/detection/condition/criteria/criterion/noneexistcriterion", "PackageType", necTypes.PackageTypes())
	printEnum("pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range", "RangeType", affectedrangeTypes.RangeTypes())
	printEnum("pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package", "PackageType", vcPackageTypes.PackageTypes())
	printEnum("pkg/extract/types/data/severity", "SeverityType", severityTypes.SeverityTypes())
}

func printEnum[T ~string](pkg, name string, values []T) {
	vs := make([]string, 0, len(values))
	for _, v := range values {
		vs = append(vs, string(v))
	}
	slices.Sort(vs)
	for _, v := range vs {
		fmt.Printf("%s.%s\t%s\n", pkg, name, v)
	}
}
