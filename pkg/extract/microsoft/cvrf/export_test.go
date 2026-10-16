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

func (o vendorFixOverride) Baseline() string {
	return o.baseline
}

func (o vendorFixOverride) Tag() string {
	return o.tag
}
