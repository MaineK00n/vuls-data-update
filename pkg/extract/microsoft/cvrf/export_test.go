package cvrf

var (
	BuildFixedBuildCriterion = buildFixedBuildCriterion
	BuildKBCriterion         = buildKBCriterion
	FixedBuildOverrides      = fixedBuildOverrides
	IsHotpatchSubType        = isHotpatchSubType
	IsKBCriteria             = isKBCriteria
	NormalizeProductName     = normalizeProductName
	ProductNameOverrides     = productNameOverrides
	KBCumulativeTwins        = kbCumulativeTwins
	VendorFixAdditions       = vendorFixAdditions
	VendorFixExclusions      = vendorFixExclusions
)

func (a vendorFixAddition) KBID() string {
	return a.kbID
}

func (a vendorFixAddition) FixedBuild() string {
	return a.fixedBuild
}
