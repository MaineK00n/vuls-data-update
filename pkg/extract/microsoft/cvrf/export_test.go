package cvrf

var (
	BuildFixedBuildCriterion = buildFixedBuildCriterion
	BuildKBCriterion         = buildKBCriterion
	FixedBuildOverrides      = fixedBuildOverrides
	IsHotpatchSubType        = isHotpatchSubType
	IsKBCriteria             = isKBCriteria
	KBCumulativeTwins        = kbCumulativeTwins
	VendorFixOverrides       = vendorFixOverrides
)

func VendorFixOverrideBaseline(k [3]string) string {
	return vendorFixOverrides[k].baseline
}
