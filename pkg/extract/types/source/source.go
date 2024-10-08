package source

import (
	"cmp"
	"slices"
)

type SourceID string

type Source struct {
	ID   SourceID `json:"id,omitempty"`
	Raws []string `json:"raws,omitempty"`
}

const (
	AlmaErrata            SourceID = "alma-errata"
	AlmaOSV               SourceID = "alma-osv"
	AlmaOVAL              SourceID = "alma-oval"
	AlpineOSV             SourceID = "alpine-osv"
	AlpineSecDB           SourceID = "alpine-secdb"
	Amazon                SourceID = "amazon"
	Arch                  SourceID = "arch"
	Attack                SourceID = "attack"
	Capec                 SourceID = "capec"
	CargoDB               SourceID = "cargo-db"
	CargoGHSA             SourceID = "cargo-ghsa"
	CargoOSV              SourceID = "cargo-osv"
	ComposerDB            SourceID = "composer-db"
	ComposerGHSA          SourceID = "composer-ghsa"
	ComposerGLSA          SourceID = "composer-glsa"
	ComposerOSV           SourceID = "composer-osv"
	ConanGLSA             SourceID = "conan-glsa"
	CWE                   SourceID = "cwe"
	DebianOSV             SourceID = "debian-osv"
	DebianOVAL            SourceID = "debian-oval"
	DebianSecurityTracker SourceID = "debian-security-tracker"
	EOL                   SourceID = "eol"
	EPSS                  SourceID = "epss"
	ErlangGHSA            SourceID = "erlang-ghsa"
	ErlangOSV             SourceID = "erlang-osv"
	ExploitExploitDB      SourceID = "exploit-exploitdb"
	ExploitGitHub         SourceID = "exploit-github"
	ExploitInTheWild      SourceID = "exploit-inthewild"
	ExploitTrickest       SourceID = "exploit-trickest"
	Fedora                SourceID = "fedora"
	Fortinet              SourceID = "fortinet"
	FreeBSD               SourceID = "freebsd"
	Gentoo                SourceID = "gentoo"
	GolangDB              SourceID = "golang-db"
	GolangGHSA            SourceID = "golang-ghsa"
	GolangGLSA            SourceID = "golang-glsa"
	GolangOSV             SourceID = "golang-osv"
	GolangVulnDB          SourceID = "golang-vulndb"
	HaskellDB             SourceID = "haskell-db"
	HaskellOSV            SourceID = "haskell-osv"
	JVNFeedDetail         SourceID = "jvn-feed-detail"
	JVNFeedProduct        SourceID = "jvn-feed-product"
	JVNFeedRSS            SourceID = "jvn-feed-rss"
	KEV                   SourceID = "kev"
	MavenGHSA             SourceID = "maven-ghsa"
	MavenGLSA             SourceID = "maven-glsa"
	MavenOSV              SourceID = "maven-osv"
	MitreCVRF             SourceID = "mitre-cvrf"
	MitreV4               SourceID = "mitre-v4"
	MitreV5               SourceID = "mitre-v5"
	Metasploit            SourceID = "metasploit"
	NetBSD                SourceID = "netbsd"
	NpmDB                 SourceID = "npm-db"
	NpmGHSA               SourceID = "npm-ghsa"
	NpmGLSA               SourceID = "npm-glsa"
	NpmOSV                SourceID = "npm-osv"
	NugetGHSA             SourceID = "nuget-ghsa"
	NugetGLSA             SourceID = "nuget-glsa"
	NugetOSV              SourceID = "nuget-osv"
	NVDAPICPE             SourceID = "nvd-api-cpe"
	NVDAPICPEMatch        SourceID = "nvd-api-cpematch"
	NVDAPICVE             SourceID = "nvd-api-cve"
	NVDFeedCPE            SourceID = "nvd-feed-cpe"
	NVDFeedCPEMatch       SourceID = "nvd-feed-cpematch"
	NVDFeedCVE            SourceID = "nvd-feed-cve"
	Oracle                SourceID = "oracle"
	PerlDB                SourceID = "perl-db"
	PipDB                 SourceID = "pip-db"
	PipGHSA               SourceID = "pip-ghsa"
	PipGLSA               SourceID = "pip-glsa"
	PipOSV                SourceID = "pip-osv"
	PubGHSA               SourceID = "pub-ghsa"
	PubOSV                SourceID = "pub-osv"
	RDB                   SourceID = "r-db"
	ROSV                  SourceID = "r-osv"
	RedHatCSAF            SourceID = "redhat-csaf"
	RedHatCVE             SourceID = "redhat-cve"
	RedHatCVRF            SourceID = "redhat-cvrf"
	RedHatOVALv1          SourceID = "redhat-ovalv1"
	RedHatOVALv2          SourceID = "redhat-ovalv2"
	RedHatVEX             SourceID = "redhat-vex"
	RockyErrata           SourceID = "rocky-errata"
	RockyOSV              SourceID = "rocky-osv"
	RubygemsDB            SourceID = "rubygems-db"
	RubygemsGHSA          SourceID = "rubygems-ghsa"
	RubygemsGLSA          SourceID = "rubygems-glsa"
	RubygemsOSV           SourceID = "rubygems-osv"
	Snort                 SourceID = "snort"
	SUSECSAF              SourceID = "suse-csaf"
	SUSECSAFVEX           SourceID = "suse-csaf-vex"
	SUSECVRF              SourceID = "suse-cvrf"
	SUSECVRFCVE           SourceID = "suse-cvrf-cve"
	SUSEOVAL              SourceID = "suse-oval"
	SwiftGHSA             SourceID = "swift-ghsa"
	SwiftOSV              SourceID = "swift-osv"
	UbuntuOVAL            SourceID = "ubuntu-oval"
	UbuntuCVETracker      SourceID = "ubuntu-cve-tracker"
	WindowsBulletin       SourceID = "windows-bulletin"
	WindowsCVRF           SourceID = "windows-cvrf"
	WindowsMSUC           SourceID = "windows-msuc"
	WindowsWSUSSCN2       SourceID = "windows-wsusscn2"
)

func (d *Source) Sort() {
	slices.Sort(d.Raws)
}

func Compare(x, y Source) int {
	return cmp.Or(
		cmp.Compare(x.ID, y.ID),
		slices.Compare(x.Raws, y.Raws),
	)
}
