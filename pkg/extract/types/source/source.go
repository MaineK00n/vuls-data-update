package source

import (
	"encoding/json"
	"fmt"
)

type SourceID int

const (
	_ SourceID = iota
	AlmaErrata
	AlmaOSV
	AlpineOSV
	AlpineSecDB
	Amazon
	Arch
	CargoDB
	CargoGHSA
	CargoOSV
	ComposerDB
	ComposerGHSA
	ComposerGLSA
	ComposerOSV
	ConanGLSA
	CWECapecAttack
	DebianOSV
	DebianOVAL
	DebianSecurityTracker
	EPSS
	ErlangGHSA
	ErlangOSV
	ExploitExploitDB
	ExploitGitHub
	ExploitInTheWild
	ExploitTrickest
	Fedora
	Fortinet
	FreeBSD
	Gentoo
	GolangDB
	GolangGHSA
	GolangGLSA
	GolangOSV
	GolangVulnDB
	HaskellDB
	HaskellOSV
	JVNFeedDetail
	JVNFeedProduct
	JVNFeedRSS
	KEV
	MavenGHSA
	MavenGLSA
	MavenOSV
	MitreCVRF
	MitreV4
	MitreV5
	Metasploit
	NetBSD
	NpmDB
	NpmGHSA
	NpmGLSA
	NpmOSV
	NugetGHSA
	NugetGLSA
	NugetOSV
	NVDAPICPE
	NVDAPICPEMatch
	NVDAPICVE
	NVDFeedCPE
	NVDFeedCPEMatch
	NVDFeedCVE
	Oracle
	PerlDB
	PipDB
	PipGHSA
	PipGLSA
	PipOSV
	PubGHSA
	PubOSV
	RDB
	ROSV
	RedHatCSAF
	RedHatCVE
	RedHatCVRF
	RedHatOVALv1
	RedHatOVALv2
	RedHatVEX
	RockyErrata
	RockyOSV
	RubygemsDB
	RubygemsGHSA
	RubygemsGLSA
	RubygemsOSV
	Snort
	SUSECSAF
	SUSECSAFVEX
	SUSECVRF
	SUSECVRFCVE
	SUSEOVAL
	SwiftGHSA
	SwiftOSV
	UbuntuOVAL
	UbuntuCVETracker
	WindowsBulletin
	WindowsCVRF
	WindowsMSUC
	WindowsWSUSSCN2
)

func (id SourceID) String() string {
	switch id {
	case AlmaErrata:
		return "alma-errata"
	case AlmaOSV:
		return "alma-osv"
	case AlpineOSV:
		return "alpine-osv"
	case AlpineSecDB:
		return "alpine-secdb"
	case Amazon:
		return "amazon"
	case Arch:
		return "arch"
	case CargoDB:
		return "cargo-db"
	case CargoGHSA:
		return "cargo-ghsa"
	case CargoOSV:
		return "cargo-osv"
	case ComposerDB:
		return "composer-db"
	case ComposerGHSA:
		return "composer-ghsa"
	case ComposerGLSA:
		return "composer-glsa"
	case ComposerOSV:
		return "composer-osv"
	case ConanGLSA:
		return "conan-glsa"
	case CWECapecAttack:
		return "cwe-capec-attack"
	case DebianOSV:
		return "debian-osv"
	case DebianOVAL:
		return "debian-oval"
	case DebianSecurityTracker:
		return "debian-security-tracker"
	case EPSS:
		return "epss"
	case ErlangGHSA:
		return "erlang-ghsa"
	case ErlangOSV:
		return "erlang-osv"
	case ExploitExploitDB:
		return "exploit-exploitdb"
	case ExploitGitHub:
		return "exploit-github"
	case ExploitInTheWild:
		return "exploit-inthewild"
	case ExploitTrickest:
		return "exploit-trickest"
	case Fedora:
		return "fedora"
	case Fortinet:
		return "fortinet"
	case FreeBSD:
		return "freebsd"
	case Gentoo:
		return "gentoo"
	case GolangDB:
		return "golang-db"
	case GolangGHSA:
		return "golang-ghsa"
	case GolangGLSA:
		return "golang-glsa"
	case GolangOSV:
		return "golang-osv"
	case GolangVulnDB:
		return "golang-vulndb"
	case HaskellDB:
		return "haskell-db"
	case HaskellOSV:
		return "haskell-osv"
	case JVNFeedDetail:
		return "jvn-feed-detail"
	case JVNFeedProduct:
		return "jvn-feed-product"
	case JVNFeedRSS:
		return "jvn-feed-rss"
	case KEV:
		return "kev"
	case MavenGHSA:
		return "maven-ghsa"
	case MavenGLSA:
		return "maven-glsa"
	case MavenOSV:
		return "maven-osv"
	case MitreCVRF:
		return "mitre-cvrf"
	case MitreV4:
		return "mitre-v4"
	case MitreV5:
		return "mitre-v5"
	case Metasploit:
		return "metasploit"
	case NetBSD:
		return "netbsd"
	case NpmDB:
		return "npm-db"
	case NpmGHSA:
		return "npm-ghsa"
	case NpmGLSA:
		return "npm-glsa"
	case NpmOSV:
		return "npm-osv"
	case NugetGHSA:
		return "nuget-ghsa"
	case NugetGLSA:
		return "nuget-glsa"
	case NugetOSV:
		return "nuget-osv"
	case NVDAPICPE:
		return "nvd-api-cpe"
	case NVDAPICPEMatch:
		return "nvd-api-cpematch"
	case NVDAPICVE:
		return "nvd-api-cve"
	case NVDFeedCPE:
		return "nvd-feed-cpe"
	case NVDFeedCPEMatch:
		return "nvd-feed-cpematch"
	case NVDFeedCVE:
		return "nvd-feed-cve"
	case Oracle:
		return "oracle"
	case PerlDB:
		return "perl-db"
	case PipDB:
		return "pip-db"
	case PipGHSA:
		return "pip-ghsa"
	case PipGLSA:
		return "pip-glsa"
	case PipOSV:
		return "pip-osv"
	case PubGHSA:
		return "pub-ghsa"
	case PubOSV:
		return "pub-osv"
	case RDB:
		return "r-db"
	case ROSV:
		return "r-osv"
	case RedHatCSAF:
		return "redhat-csaf"
	case RedHatCVE:
		return "redhat-cve"
	case RedHatCVRF:
		return "redhat-cvrf"
	case RedHatOVALv1:
		return "redhat-ovalv1"
	case RedHatOVALv2:
		return "redhat-ovalv2"
	case RedHatVEX:
		return "redhat-vex"
	case RockyErrata:
		return "rocky-errata"
	case RockyOSV:
		return "rocky-osv"
	case RubygemsDB:
		return "rubygems-db"
	case RubygemsGHSA:
		return "rubygems-ghsa"
	case RubygemsGLSA:
		return "rubygems-glsa"
	case RubygemsOSV:
		return "rubygems-osv"
	case Snort:
		return "snort"
	case SUSECSAF:
		return "suse-csaf"
	case SUSECSAFVEX:
		return "suse-csaf-vex"
	case SUSECVRF:
		return "suse-cvrf"
	case SUSECVRFCVE:
		return "suse-cvrf-cve"
	case SUSEOVAL:
		return "suse-oval"
	case SwiftGHSA:
		return "swift-ghsa"
	case SwiftOSV:
		return "swift-osv"
	case UbuntuOVAL:
		return "ubuntu-oval"
	case UbuntuCVETracker:
		return "ubuntu-cve-tracker"
	case WindowsBulletin:
		return "windows-bulletin"
	case WindowsCVRF:
		return "windows-cvrf"
	case WindowsMSUC:
		return "windows-msuc"
	case WindowsWSUSSCN2:
		return "windows-wsusscn2"
	default:
		return ""
	}
}

func (id SourceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

func (id *SourceID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var sid SourceID
	switch s {
	case "alma-errata":
		sid = AlmaErrata
	case "alma-osv":
		sid = AlmaOSV
	case "alpine-osv":
		sid = AlpineOSV
	case "alpine-secdb":
		sid = AlpineSecDB
	case "amazon":
		sid = Amazon
	case "arch":
		sid = Arch
	case "cargo-db":
		sid = CargoDB
	case "cargo-ghsa":
		sid = CargoGHSA
	case "cargo-osv":
		sid = CargoOSV
	case "composer-db":
		sid = ComposerDB
	case "composer-ghsa":
		sid = ComposerGHSA
	case "composer-glsa":
		sid = ComposerGLSA
	case "composer-osv":
		sid = ComposerOSV
	case "conan-glsa":
		sid = ConanGLSA
	case "cwe-capec-attack":
		sid = CWECapecAttack
	case "debian-osv":
		sid = DebianOSV
	case "debian-oval":
		sid = DebianOVAL
	case "debian-security-tracker":
		sid = DebianSecurityTracker
	case "epss":
		sid = EPSS
	case "erlang-ghsa":
		sid = ErlangGHSA
	case "erlang-osv":
		sid = ErlangOSV
	case "exploit-exploitdb":
		sid = ExploitExploitDB
	case "exploit-github":
		sid = ExploitGitHub
	case "exploit-inthewild":
		sid = ExploitInTheWild
	case "exploit-trickest":
		sid = ExploitTrickest
	case "fedora":
		sid = Fedora
	case "fortinet":
		sid = Fortinet
	case "freebsd":
		sid = FreeBSD
	case "gentoo":
		sid = Gentoo
	case "golang-db":
		sid = GolangDB
	case "golang-ghsa":
		sid = GolangGHSA
	case "golang-glsa":
		sid = GolangGLSA
	case "golang-osv":
		sid = GolangOSV
	case "golang-vulndb":
		sid = GolangVulnDB
	case "haskell-db":
		sid = HaskellDB
	case "haskell-osv":
		sid = HaskellOSV
	case "jvn-feed-detail":
		sid = JVNFeedDetail
	case "jvn-feed-product":
		sid = JVNFeedProduct
	case "jvn-feed-rss":
		sid = JVNFeedRSS
	case "kev":
		sid = KEV
	case "maven-ghsa":
		sid = MavenGHSA
	case "maven-glsa":
		sid = MavenGLSA
	case "maven-osv":
		sid = MavenOSV
	case "mitre-cvrf":
		sid = MitreCVRF
	case "mitre-v4":
		sid = MitreV4
	case "mitre-v5":
		sid = MitreV5
	case "metasploit":
		sid = Metasploit
	case "netbsd":
		sid = NetBSD
	case "npm-db":
		sid = NpmDB
	case "npm-ghsa":
		sid = NpmGHSA
	case "npm-glsa":
		sid = NpmGLSA
	case "npm-osv":
		sid = NpmOSV
	case "nuget-ghsa":
		sid = NugetGHSA
	case "nuget-glsa":
		sid = NugetGLSA
	case "nuget-osv":
		sid = NugetOSV
	case "nvd-api-cpe":
		sid = NVDAPICPE
	case "nvd-api-cpematch":
		sid = NVDAPICPEMatch
	case "nvd-api-cve":
		sid = NVDAPICVE
	case "nvd-feed-cpe":
		sid = NVDFeedCPE
	case "nvd-feed-cpematch":
		sid = NVDFeedCPEMatch
	case "nvd-feed-cve":
		sid = NVDFeedCVE
	case "oracle":
		sid = Oracle
	case "perl-db":
		sid = PerlDB
	case "pip-db":
		sid = PipDB
	case "pip-ghsa":
		sid = PipGHSA
	case "pip-glsa":
		sid = PipGLSA
	case "pip-osv":
		sid = PipOSV
	case "pub-ghsa":
		sid = PubGHSA
	case "pub-osv":
		sid = PubOSV
	case "r-db":
		sid = RDB
	case "r-osv":
		sid = ROSV
	case "redhat-csaf":
		sid = RedHatCSAF
	case "redhat-cve":
		sid = RedHatCVE
	case "redhat-cvrf":
		sid = RedHatCVRF
	case "redhat-ovalv1":
		sid = RedHatOVALv1
	case "redhat-ovalv2":
		sid = RedHatOVALv2
	case "redhat-vex":
		sid = RedHatVEX
	case "rocky-errata":
		sid = RockyErrata
	case "rocky-osv":
		sid = RockyOSV
	case "rubygems-db":
		sid = RubygemsDB
	case "rubygems-ghsa":
		sid = RubygemsGHSA
	case "rubygems-glsa":
		sid = RubygemsGLSA
	case "rubygems-osv":
		sid = RubygemsOSV
	case "snort":
		sid = Snort
	case "suse-csaf":
		sid = SUSECSAF
	case "suse-csaf-vex":
		sid = SUSECSAFVEX
	case "suse-cvrf":
		sid = SUSECVRF
	case "suse-cvrf-cve":
		sid = SUSECVRFCVE
	case "suse-oval":
		sid = SUSEOVAL
	case "swift-ghsa":
		sid = SwiftGHSA
	case "swift-osv":
		sid = SwiftOSV
	case "ubuntu-oval":
		sid = UbuntuOVAL
	case "ubuntu-cve-tracker":
		sid = UbuntuCVETracker
	case "windows-bulletin":
		sid = WindowsBulletin
	case "windows-cvrf":
		sid = WindowsCVRF
	case "windows-msuc":
		sid = WindowsMSUC
	case "windows-wsusscn2":
		sid = WindowsWSUSSCN2
	default:
		return fmt.Errorf("invalid SourceID %s", s)
	}
	*id = sid
	return nil
}
