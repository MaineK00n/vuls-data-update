package version

import (
	gem "github.com/aquasecurity/go-gem-version"
	npm "github.com/aquasecurity/go-npm-version/pkg"
	pep440 "github.com/aquasecurity/go-pep440-version"
	"github.com/hashicorp/go-version"
	apk "github.com/knqyf263/go-apk-version"
	deb "github.com/knqyf263/go-deb-version"
	rpm "github.com/knqyf263/go-rpm-version"
	mvn "github.com/masahiro331/go-mvn-version"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/detection"
)

func Contains(a detection.Affected, v string) bool {
	for _, r := range a.Range {
		if r.Equal != "" {
			if r.Equal != v {
				continue
			}
		}
		if r.GreaterEqual != "" {
			switch a.Type {
			case detection.RangeTypeVersion:
				v1, _ := version.NewVersion(r.GreaterEqual)
				v2, _ := version.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeSEMVER:
				v1, _ := version.NewSemver(r.GreaterEqual)
				v2, _ := version.NewSemver(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeAPK:
				v1, _ := apk.NewVersion(r.GreaterEqual)
				v2, _ := apk.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeRPM:
				if rpm.NewVersion(r.GreaterEqual).Compare(rpm.NewVersion(v)) > 0 {
					continue
				}
			case detection.RangeTypeDPKG:
				v1, _ := deb.NewVersion(r.GreaterEqual)
				v2, _ := deb.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeNPM:
				v1, _ := npm.NewVersion(r.GreaterEqual)
				v2, _ := npm.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeRubyGems:
				v1, _ := gem.NewVersion(r.GreaterEqual)
				v2, _ := gem.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypePyPI:
				v1, _ := pep440.Parse(r.GreaterEqual)
				v2, _ := pep440.Parse(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			case detection.RangeTypeMaven:
				v1, _ := mvn.NewVersion(r.GreaterEqual)
				v2, _ := mvn.NewVersion(v)
				if v1.Compare(v2) > 0 {
					continue
				}
			}
		}
		if r.GreaterThan != "" {
			switch a.Type {
			case detection.RangeTypeVersion:
				v1, _ := version.NewVersion(r.GreaterThan)
				v2, _ := version.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeSEMVER:
				v1, _ := version.NewSemver(r.GreaterThan)
				v2, _ := version.NewSemver(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeAPK:
				v1, _ := apk.NewVersion(r.GreaterThan)
				v2, _ := apk.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeRPM:
				if rpm.NewVersion(r.GreaterThan).Compare(rpm.NewVersion(v)) >= 0 {
					continue
				}
			case detection.RangeTypeDPKG:
				v1, _ := deb.NewVersion(r.GreaterThan)
				v2, _ := deb.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeNPM:
				v1, _ := npm.NewVersion(r.GreaterThan)
				v2, _ := npm.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeRubyGems:
				v1, _ := gem.NewVersion(r.GreaterThan)
				v2, _ := gem.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypePyPI:
				v1, _ := pep440.Parse(r.GreaterThan)
				v2, _ := pep440.Parse(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			case detection.RangeTypeMaven:
				v1, _ := mvn.NewVersion(r.GreaterThan)
				v2, _ := mvn.NewVersion(v)
				if v1.Compare(v2) >= 0 {
					continue
				}
			}
		}
		if r.LessEqual != "" {
			switch a.Type {
			case detection.RangeTypeVersion:
				v1, _ := version.NewVersion(r.LessEqual)
				v2, _ := version.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeSEMVER:
				v1, _ := version.NewSemver(r.LessEqual)
				v2, _ := version.NewSemver(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeAPK:
				v1, _ := apk.NewVersion(r.LessEqual)
				v2, _ := apk.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeRPM:
				if rpm.NewVersion(r.LessEqual).Compare(rpm.NewVersion(v)) < 0 {
					continue
				}
			case detection.RangeTypeDPKG:
				v1, _ := deb.NewVersion(r.LessEqual)
				v2, _ := deb.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeNPM:
				v1, _ := npm.NewVersion(r.LessEqual)
				v2, _ := npm.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeRubyGems:
				v1, _ := gem.NewVersion(r.LessEqual)
				v2, _ := gem.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypePyPI:
				v1, _ := pep440.Parse(r.LessEqual)
				v2, _ := pep440.Parse(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			case detection.RangeTypeMaven:
				v1, _ := mvn.NewVersion(r.LessEqual)
				v2, _ := mvn.NewVersion(v)
				if v1.Compare(v2) < 0 {
					continue
				}
			}
		}
		if r.LessThan != "" {
			switch a.Type {
			case detection.RangeTypeVersion:
				v1, _ := version.NewVersion(r.LessThan)
				v2, _ := version.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeSEMVER:
				v1, _ := version.NewSemver(r.LessThan)
				v2, _ := version.NewSemver(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeAPK:
				v1, _ := apk.NewVersion(r.LessThan)
				v2, _ := apk.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeRPM:
				if rpm.NewVersion(r.LessThan).Compare(rpm.NewVersion(v)) <= 0 {
					continue
				}
			case detection.RangeTypeDPKG:
				v1, _ := deb.NewVersion(r.LessThan)
				v2, _ := deb.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeNPM:
				v1, _ := npm.NewVersion(r.LessThan)
				v2, _ := npm.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeRubyGems:
				v1, _ := gem.NewVersion(r.LessThan)
				v2, _ := gem.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypePyPI:
				v1, _ := pep440.Parse(r.LessThan)
				v2, _ := pep440.Parse(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			case detection.RangeTypeMaven:
				v1, _ := mvn.NewVersion(r.LessThan)
				v2, _ := mvn.NewVersion(v)
				if v1.Compare(v2) <= 0 {
					continue
				}
			}
		}
		return true
	}
	return false
}
