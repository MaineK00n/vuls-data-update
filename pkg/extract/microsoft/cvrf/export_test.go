package cvrf

import (
	microsoftutil "github.com/MaineK00n/vuls-data-update/pkg/extract/microsoft/util"
	criterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion"
)

var (
	BuildFixedBuildCriterion = buildFixedBuildCriterion
	BuildKBCriterion         = buildKBCriterion
	CVRFOverrides            = cvrfOverrides
	IsHotpatchSubType        = isHotpatchSubType
	IsKBCriteria             = isKBCriteria
	KBCumulativeTwins        = kbCumulativeTwins
)

func (o cvrfOverride) Validate() error {
	return o.validate()
}

// FixedBuildOverride returns the fixed build that an overrideFixedBuild (or ""
// for an overrideNoFixedBuild) gives the FixedBuild from of product, a name
// after microsoftutil.NormalizeProductName, in cve.
func FixedBuildOverride(cve, product, from string) (string, bool) {
	for _, o := range cvrfOverrides {
		if o.cve == cve && microsoftutil.NormalizeProductName(o.product) == product && o.from == from && (o.kind == overrideFixedBuild || o.kind == overrideNoFixedBuild) {
			return o.fixedBuild, true
		}
	}
	return "", false
}

// BuildOverriddenFixedBuildCriterion is buildFixedBuildCriterion of the
// FixedBuild that applyOverrides gives the Vendor Fix.
func BuildOverriddenFixedBuildCriterion(cve, product, rawFixedBuild string) (*criterionTypes.Criterion, error) {
	if fb, ok := FixedBuildOverride(cve, product, cleanFixedBuild(rawFixedBuild)); ok {
		return buildFixedBuildCriterion(cve, product, fb)
	}
	return buildFixedBuildCriterion(cve, product, rawFixedBuild)
}
