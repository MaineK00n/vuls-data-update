package detection

import (
	"cmp"

	criteriaTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria"
)

type Detection struct {
	Ecosystem Ecosystem              `json:"ecosystem,omitempty"`
	Criteria  criteriaTypes.Criteria `json:"criteria,omitempty"`
}

type Ecosystem string

const (
	EcosystemTypeAlma        = "alma"
	EcosystemTypeAlpine      = "alpine"
	EcosystemTypeAmazon      = "amazon"
	EcosystemTypeArch        = "arch"
	EcosystemTypeDebian      = "debian"
	EcosystemTypeEPEL        = "epel"
	EcosystemTypeFedora      = "fedora"
	EcosystemTypeFreeBSD     = "freebsd"
	EcosystemTypeGentoo      = "gentoo"
	EcosystemTypeNetBSD      = "netbsd"
	EcosystemTypeOracle      = "oracle"
	EcosystemTypeRedHat      = "redhat"
	EcosystemTypeRocky       = "rocky"
	EcosystemTypeOpenSUSE    = "opensuse"
	EcosystemTypeSUSEServer  = "sles"
	EcosystemTypeSUSEDesktop = "sled"
	EcosystemTypeUbuntu      = "ubuntu"
	EcosystemTypeWindows     = "windows"

	EcosystemTypeCPE = "cpe"

	EcosystemTypeFortinet = "fortinet"

	EcosystemTypeCargo    = "cargo"
	EcosystemTypeComposer = "composer"
	EcosystemTypeConan    = "conan"
	EcosystemTypeErlang   = "erlang"
	EcosystemTypeGolang   = "golang"
	EcosystemTypeHaskell  = "haskell"
	EcosystemTypeMaven    = "maven"
	EcosystemTypeNpm      = "npm"
	EcosystemTypeNuget    = "nuget"
	EcosystemTypePerl     = "perl"
	EcosystemTypePip      = "pip"
	EcosystemTypePub      = "pub"
	EcosystemTypeR        = "r"
	EcosystemTypeRubygems = "rubygems"
	EcosystemTypeSwift    = "swift"
)

func (d *Detection) Sort() {
	(&d.Criteria).Sort()
}

func Compare(x, y Detection) int {
	return cmp.Or(
		cmp.Compare(x.Ecosystem, y.Ecosystem),
		criteriaTypes.Compare(x.Criteria, y.Criteria),
	)
}
