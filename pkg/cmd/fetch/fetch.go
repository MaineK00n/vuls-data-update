package fetch

import (
	"path/filepath"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	almaErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
	almaOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/osv"
	almaOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/oval"
	alpineOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/osv"
	alpineSecDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
	androidOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/android/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/arch"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/attack"
	azureOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/azure/oval"
	bitnamiOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/bitnami/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/capec"
	cargoGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/cargo/ghsa"
	cargoOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/cargo/osv"
	chainguardOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/chainguard/osv"
	chainguardSecDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/chainguard/secdb"
	ciscoCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/csaf"
	ciscoCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/cvrf"
	ciscoJSON "github.com/MaineK00n/vuls-data-update/pkg/fetch/cisco/json"
	composerGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/composer/ghsa"
	composerGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/composer/glsa"
	composerOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/composer/osv"
	conanGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/conan/glsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cwe"
	debianOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/osv"
	debianOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/oval"
	debianSecurityTrackerAPI "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/api"
	debianSecurityTrackerSalsa "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
	erlangGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/erlang/ghsa"
	erlangOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/erlang/osv"
	exploitExploitDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/exploitdb"
	exploitGitHub "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/github"
	exploitInTheWild "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/inthewild"
	exploitTrickest "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/trickest"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora"
	fortinetCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/fortinet/cvrf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/gentoo"
	ghactionsOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/ghactions/osv"
	gitOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/git/osv"
	golangGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/golang/ghsa"
	golangGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/golang/glsa"
	golangOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/golang/osv"
	haskellOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/haskell/osv"
	jvnFeedDetail "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/detail"
	jvnFeedProduct "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/product"
	jvnFeedRSS "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/rss"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/kev"
	linuxOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/linux/osv"
	mageiaOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/mageia/osv"
	mavenGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/maven/ghsa"
	mavenGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/maven/glsa"
	mavenOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/maven/osv"
	mitreCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cvrf"
	mitreV4 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v4"
	mitreV5 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v5"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/netbsd"
	npmGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/npm/ghsa"
	npmGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/npm/glsa"
	npmOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/npm/osv"
	nugetGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/nuget/ghsa"
	nugetGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/nuget/glsa"
	nugetOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/nuget/osv"
	nvdAPICPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cpe"
	nvdAPICPEMatch "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cpematch"
	nvdAPICVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
	nvdFeedCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpe"
	nvdFeedCPEMatch "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch"
	nvdFeedCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve"
	openeulerCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/csaf"
	openeulerCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/cvrf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle"
	ossFuzzOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/oss-fuzz/osv"
	paloaltoCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/csaf"
	paloaltoJSON "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/json"
	paloaltoList "github.com/MaineK00n/vuls-data-update/pkg/fetch/paloalto/list"
	photonCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/photon/cve"
	photonOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/photon/oval"
	pipGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/pip/ghsa"
	pipGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/pip/glsa"
	pipOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/pip/osv"
	pubGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/pub/ghsa"
	pubOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/pub/osv"
	rOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/r/osv"
	redhatCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/csaf"
	redhatCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/cve"
	redhatCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/cvrf"
	redhatOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/osv"
	redhatOVALv1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v1"
	redhatOVALv2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v2"
	redhatRepositoryToCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/repository2cpe"
	redhatVEX "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/vex"
	rockyErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/errata"
	rockyOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/osv"
	rubygemsGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/rubygems/ghsa"
	rubygemsGLSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/rubygems/glsa"
	rubygemsOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/rubygems/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/snort"
	suseCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf"
	suseCSAFVEX "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf_vex"
	suseCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf"
	suseCVRFCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf_cve"
	suseOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/osv"
	suseOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval"
	swiftGHSA "github.com/MaineK00n/vuls-data-update/pkg/fetch/swift/ghsa"
	swiftOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/swift/osv"
	ubuntuOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/osv"
	ubuntuOVAL "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/oval"
	ubuntuCVETracker "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/tracker"
	ubuntuUSNDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/usndb"
	ubuntuVEX "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/vex"
	vulncheckKEV "github.com/MaineK00n/vuls-data-update/pkg/fetch/vulncheck/kev"
	windowsAdvisory "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/advisory"
	windowsBulletin "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/bulletin"
	windowsCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/csaf"
	windowsCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/cvrf"
	windowsMSUC "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/msuc"
	windowsProduct "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/product"
	windowsVulnerability "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/vulnerability"
	windowsWSUSSCN2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/wsusscn2"
	wolfiOSV "github.com/MaineK00n/vuls-data-update/pkg/fetch/wolfi/osv"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type base struct {
	dir   string
	retry int
}

func NewCmdFetch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <data source>",
		Short: "Fetch data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker-salsa
			$ vuls-data-update fetch cargo-db
			$ vuls-data-update fetch nvd-feed-cve
		`),
	}

	cmd.AddCommand(
		newCmdAlmaErrata(), newCmdAlmaOSV(), newCmdAlmaOVAL(),
		newCmdAlpineSecDB(), newCmdAlpineOSV(),
		newCmdAmazon(),
		newCmdAndroidOSV(),
		newCmdArch(),
		newCmdAttack(),
		newCmdAzureOVAL(),
		newCmdBitnamiOSV(),
		newCmdCapec(),
		newCmdCargoGHSA(), newCmdCargoOSV(), newCmdCargoDB(),
		newCmdChainguardSecDB(), newCmdChainguardOSV(),
		newCmdCiscoJSON(), newCmdCiscoCVRF(), newCmdCiscoCSAF(),
		newCmdComposerGHSA(), newCmdComposerGLSA(), newCmdComposerOSV(), newCmdComposerDB(),
		newCmdConanGLSA(),
		newCmdCWE(),
		newCmdDebianOVAL(), newCmdDebianSecurityTrackerAPI(), newCmdDebianSecurityTrackerSalsa(), newCmdDebianOSV(),
		newCmdEPSS(),
		newCmdErlangGHSA(), newCmdErlangOSV(),
		newCmdExploitExploitDB(), newCmdExploitGitHub(), newCmdExploitInTheWild(), newCmdExploitExploitTrickest(),
		newCmdFedora(),
		newCmdFortinetCVRF(),
		newCmdFreeBSD(),
		newCmdGentoo(),
		newCmdGHActionsOSV(),
		newCmdGitOSV(),
		newCmdGolangGHSA(), newCmdGolangGLSA(), newCmdGolangOSV(), newCmdGolangDB(), newCmdGolangVulnDB(),
		newCmdHaskellOSV(),
		newCmdJVNFeedDetail(), newCmdJVNFeedProduct(), newCmdJVNFeedRSS(),
		newCmdKEV(),
		newCmdLinuxOSV(),
		newCmdMageiaOSV(),
		newCmdMavenGHSA(), newCmdMavenGLSA(), newCmdMavenOSV(),
		newCmdMitreCVRF(), newCmdMitreV4(), newCmdMitreV5(),
		newCmdMSF(),
		newCmdNetBSD(),
		newCmdNpmGHSA(), newCmdNpmGLSA(), newCmdNpmOSV(), newCmdNpmDB(),
		newCmdNugetGHSA(), newCmdNugetGLSA(), newCmdNugetOSV(),
		newCmdNVDAPICVE(), newCmdNVDAPICPE(), newCmdNVDAPICPEMatch(), newCmdNVDFeedCVE(), newCmdNVDFeedCPE(), newCmdNVDFeedCPEMatch(),
		newCmdOpenEulerCVRF(), newCmdOpenEulerCSAF(),
		newCmdOracle(),
		newCmdOSSFuzzOSV(),
		newCmdPaloAltoList(), newCmdPaloAltoJSON(), newCmdPaloAltoCSAF(),
		newCmdPerlDB(),
		newCmdPhotonCVE(), newCmdPhotonOVAL(),
		newCmdPipGHSA(), newCmdPipGLSA(), newCmdPipOSV(), newCmdPipDB(),
		newCmdPubGHSA(), newCmdPubOSV(),
		newCmdROSV(),
		newCmdRedHatOVALRepositoryToCPE(), newCmdRedHatOVALV1(), newCmdRedHatOVALV2(), newCmdRedHatCVE(), newCmdRedHatCVRF(), newCmdRedHatCSAF(), newCmdRedHatVEX(), newCmdRedHatOSV(),
		newCmdRockyErrata(), newCmdRockyOSV(),
		newCmdRubygemsGHSA(), newCmdRubygemsGLSA(), newCmdRubygemsOSV(), newCmdRubygemsDB(),
		newCmdSnort(),
		newCmdSUSEOVAL(), newCmdSUSECVRF(), newCmdSUSECVRFCVE(), newCmdSUSECSAF(), newCmdSUSECSAFVEX(), newCmdSUSEOSV(),
		newCmdSwiftGHSA(), newCmdSwiftOSV(),
		newCmdUbuntuOVAL(), newCmdUbuntuCVETracker(), newCmdUbuntuUSNDB(), newCmdUbuntuOSV(), newCmdUbuntuVEX(),
		newCmdVulnCheckKEV(),
		newCmdWindowsBulletin(), newCmdWindowsCVRF(), newCmdWindowsCSAF(), newCmdWindowsMSUC(), newCmdWindowsAdvisory(), newCmdWindowsVulnerability(), newCmdWindowsProduct(), newCmdWindowsWSUSSCN2(),
		newCmdWolfiOSV(),
	)

	return cmd
}

func newCmdAlmaErrata() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alma", "errata"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alma-errata",
		Short: "Fetch AlmaLinux Errata data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alma-errata
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := almaErrata.Fetch(almaErrata.WithDir(options.dir), almaErrata.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch almalinux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "alma", "errata"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAlmaOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alma", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alma-osv",
		Short: "Fetch AlmaLinux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alma-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := almaOSV.Fetch(almaOSV.WithDir(options.dir), almaOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch almalinux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "alma", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAlmaOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alma", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alma-oval",
		Short: "Fetch AlmaLinux OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alma-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := almaOVAL.Fetch(almaOVAL.WithDir(options.dir), almaOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch almalinux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "alma", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAlpineSecDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alpine", "secdb"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alpine-secdb",
		Short: "Fetch Alpine Linux SecDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alpine-secdb
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := alpineSecDB.Fetch(alpineSecDB.WithDir(options.dir), alpineSecDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch alpine linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "alpine", "secdb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAlpineOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "alpine", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "alpine-osv",
		Short: "Fetch Alpine Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch alpine-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := alpineOSV.Fetch(alpineOSV.WithDir(options.dir), alpineOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch alpine linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "alpine", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAmazon() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "amazon"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "amazon",
		Short: "Fetch Amazon Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch amzon
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := amazon.Fetch(amazon.WithDir(options.dir), amazon.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch amazon linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "amazon"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAndroidOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "android", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "android-osv",
		Short: "Fetch Android OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch android-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := androidOSV.Fetch(androidOSV.WithDir(options.dir), androidOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch android")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "android", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdArch() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "arch"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "arch",
		Short: "Fetch Arch Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch arch
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := arch.Fetch(arch.WithDir(options.dir), arch.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch arch linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "arch"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAttack() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "attack"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "attack",
		Short: "Fetch MITRE ATT&CK data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch attack
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := attack.Fetch(attack.WithDir(options.dir), attack.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch attack")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "attack"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdAzureOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "azure", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "azure-oval",
		Short: "Fetch Azure Linux OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch azure-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := azureOVAL.Fetch(azureOVAL.WithDir(options.dir), azureOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch azure oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdBitnamiOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "bitnami", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "bitnami-osv",
		Short: "Fetch Bitnami OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch bitnami-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := bitnamiOSV.Fetch(bitnamiOSV.WithDir(options.dir), bitnamiOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch bitnami")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "bitnami", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCapec() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "capec"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "capec",
		Short: "Fetch CAPEC data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch capec
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := capec.Fetch(capec.WithDir(options.dir), capec.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch capec")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "capec"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCargoDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "cargo", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "cargo-db",
		Short: "Fetch Cargo DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cargo-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := cargoDB.Fetch(cargoDB.WithDir(options.dir), cargoDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "cargo", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCargoGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "cargo", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "cargo-ghsa",
		Short: "Fetch Cargo GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cargo-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := cargoGHSA.Fetch(cargoGHSA.WithDir(options.dir), cargoGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch cargo ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "cargo", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCargoOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "cargo", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "cargo-osv",
		Short: "Fetch Cargo Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cargo-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := cargoOSV.Fetch(cargoOSV.WithDir(options.dir), cargoOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch cargo osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "cargo", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdChainguardSecDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "chainguard", "secdb"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "chainguard-secdb",
		Short: "Fetch Chainguard SecDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch chainguard-secdb
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := chainguardSecDB.Fetch(chainguardSecDB.WithDir(options.dir), chainguardSecDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch chainguard secdb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdChainguardOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "chainguard", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "chainguard-osv",
		Short: "Fetch Chainguard Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch chainguard-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := chainguardOSV.Fetch(chainguardOSV.WithDir(options.dir), chainguardOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch chainguard osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "chainguard", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCiscoJSON() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "cisco", "json"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "cisco-json <Cisco Client Key> <Cisco Client Secret>",
		Short: "Fetch Cisco JSON data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cisco-json client_key client_secret
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ciscoJSON.Fetch(args[0], args[1], ciscoJSON.WithDir(options.dir), ciscoJSON.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch cisco json")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdCiscoCVRF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "cisco", "cvrf"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "cisco-cvrf [<Cisco Security Advisory ID>]",
		Short: "Fetch Cisco CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cisco-cvrf cisco-sa-xwork-xss-KCcg7WwU cisco-sa-tms-xss-vuln-WbTcYwxG
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ciscoCVRF.Fetch(args, ciscoCVRF.WithDir(options.dir), ciscoCVRF.WithRetry(options.retry), ciscoCVRF.WithConcurrency(options.concurrency), ciscoCVRF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch cisco cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdCiscoCSAF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "cisco", "csaf"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "cisco-csaf [<Cisco Security Advisory ID>]",
		Short: "Fetch Cisco CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cisco-csaf cisco-sa-xwork-xss-KCcg7WwU cisco-sa-tms-xss-vuln-WbTcYwxG
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ciscoCSAF.Fetch(args, ciscoCSAF.WithDir(options.dir), ciscoCSAF.WithRetry(options.retry), ciscoCSAF.WithConcurrency(options.concurrency), ciscoCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch cisco csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdComposerDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "composer", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "composer-db",
		Short: "Fetch Composer DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch composer-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := composerDB.Fetch(composerDB.WithDir(options.dir), composerDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "composer", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdComposerGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "composer", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "composer-ghsa",
		Short: "Fetch Composer GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch composer-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := composerGHSA.Fetch(composerGHSA.WithDir(options.dir), composerGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch composer ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "composer", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdComposerGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "composer", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "composer-glsa",
		Short: "Fetch Composer GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch composer-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := composerGLSA.Fetch(composerGLSA.WithDir(options.dir), composerGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch composer glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "composer", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdComposerOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "composer", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "composer-osv",
		Short: "Fetch Composer OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch composer-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := composerOSV.Fetch(composerOSV.WithDir(options.dir), composerOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch composer osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "composer", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdConanGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "conan", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "conan-glsa",
		Short: "Fetch Conan GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch conan-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := conanGLSA.Fetch(conanGLSA.WithDir(options.dir), conanGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch conan glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "conan", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdCWE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "cwe"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "cwe",
		Short: "Fetch CWE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch cwe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := cwe.Fetch(cwe.WithDir(options.dir), cwe.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch cwe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "cwe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdDebianOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "debian", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "debian-oval",
		Short: "Fetch Debian OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := debianOVAL.Fetch(debianOVAL.WithDir(options.dir), debianOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "debian", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdDebianSecurityTrackerAPI() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "debian", "security-tracker", "api"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "debian-security-tracker-api",
		Short: "Fetch Debian Security Tracker API data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker-api
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := debianSecurityTrackerAPI.Fetch(debianSecurityTrackerAPI.WithDir(options.dir), debianSecurityTrackerAPI.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian security tracker api")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "debian", "security-tracker", "api"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdDebianSecurityTrackerSalsa() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "debian", "security-tracker", "salsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "debian-security-tracker-salsa",
		Short: "Fetch Debian Security Tracker Salsa repository data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker-salsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := debianSecurityTrackerSalsa.Fetch(debianSecurityTrackerSalsa.WithDir(options.dir), debianSecurityTrackerSalsa.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian security tracker salsa repository")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "debian", "security-tracker", "salsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdDebianOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "debian", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "debian-osv",
		Short: "Fetch Debian OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := debianOSV.Fetch(debianOSV.WithDir(options.dir), debianOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "debian", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdEPSS() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "epss"),
			retry: 3,
		},
		concurrency: 4,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "epss",
		Short: "Fetch EPSS data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch epss
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := epss.Fetch(args, epss.WithDir(options.dir), epss.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch epss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "epss"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 4, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdErlangGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "erlang", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "erlang-ghsa",
		Short: "Fetch Erlang GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch erlang-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := erlangGHSA.Fetch(erlangGHSA.WithDir(options.dir), erlangGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch erlang-ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "erlang", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdErlangOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "erlang", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "erlang-osv",
		Short: "Fetch Erlang Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch erlang-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := erlangOSV.Fetch(erlangOSV.WithDir(options.dir), erlangOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch erlang osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "erlang", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdExploitExploitDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "exploit", "exploitdb"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "exploit-exploitdb",
		Short: "Fetch Exploit ExploitDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch exploit-exploitdb
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := exploitExploitDB.Fetch(exploitExploitDB.WithDir(options.dir), exploitExploitDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit exploitdb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "exploit", "exploitdb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdExploitGitHub() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "exploit", "github"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "exploit-github",
		Short: "Fetch Exploit GitHub data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch exploit-github
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := exploitGitHub.Fetch(exploitGitHub.WithDir(options.dir), exploitGitHub.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit github")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "exploit", "github"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdExploitInTheWild() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "exploit", "inthewild"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "exploit-inthewild",
		Short: "Fetch Exploit InTheWild data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch exploit-inthewild
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := exploitInTheWild.Fetch(exploitInTheWild.WithDir(options.dir), exploitInTheWild.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit inthewild")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "exploit", "inthewild"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdExploitExploitTrickest() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "exploit", "trickest"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "exploit-trickest",
		Short: "Fetch Exploit Trickest data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch exploit-trickest
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := exploitTrickest.Fetch(exploitTrickest.WithDir(options.dir), exploitTrickest.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit trickest")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "exploit", "trickest"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFedora() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "fedora"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "fedora",
		Short: "Fetch Fedora data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch fedora F39
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fedora.Fetch(args, fedora.WithDir(options.dir), fedora.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch fedora")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "fedora"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 5, "number of concurrency process")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFortinetCVRF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "fortinet", "cvrf"),
			retry: 3,
		},
		concurrency: 4,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "fortinet-cvrf [Fortinet Advisory ID]",
		Short: "Fetch Fortinet CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch fortinet-cvrf FG-IR-24-371
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fortinetCVRF.Fetch(args, fortinetCVRF.WithDir(options.dir), fortinetCVRF.WithRetry(options.retry), fortinetCVRF.WithConcurrency(options.concurrency), fortinetCVRF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch fortinet")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "fortinet", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 4, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFreeBSD() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "freebsd"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "freebsd",
		Short: "Fetch FreeBSD data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch freebsd
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := freebsd.Fetch(freebsd.WithDir(options.dir), freebsd.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch freebsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "freebsd"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGentoo() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "fetch", "gentoo"),
	}

	cmd := &cobra.Command{
		Use:   "gentoo",
		Short: "Fetch Gentoo Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch gentoo
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := gentoo.Fetch(gentoo.WithDir(options.dir), gentoo.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch gentoo")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "gentoo"), "output fetch results to specified directory")

	return cmd
}

func newCmdGHActionsOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ghactions", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ghactions-osv",
		Short: "Fetch GitHub Actions OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ghactions-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ghactionsOSV.Fetch(ghactionsOSV.WithDir(options.dir), ghactionsOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ghactions osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "ghactions", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGitOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "git", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "git-osv",
		Short: "Fetch Git OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch git-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := gitOSV.Fetch(gitOSV.WithDir(options.dir), gitOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch git osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "git", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGolangDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "golang", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "golang-db",
		Short: "Fetch Golang DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch golang-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := golangDB.Fetch(golangDB.WithDir(options.dir), golangDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "golang", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGolangGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "golang", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "golang-ghsa",
		Short: "Fetch Golang GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch golang-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := golangGHSA.Fetch(golangGHSA.WithDir(options.dir), golangGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch golang ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "golang", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGolangGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "golang", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "golang-glsa",
		Short: "Fetch Golang GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch golang-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := golangGLSA.Fetch(golangGLSA.WithDir(options.dir), golangGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch golang glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "golang", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGolangOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "golang", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "golang-osv",
		Short: "Fetch Golang OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch golang-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := golangOSV.Fetch(golangOSV.WithDir(options.dir), golangOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch golang osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "golang", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdGolangVulnDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "golang", "vulndb"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "golang-vulndb",
		Short: "Fetch Golang VulnDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch golang-vulndb
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := golangVulnDB.Fetch(golangVulnDB.WithDir(options.dir), golangVulnDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang vulndb")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "golang", "vulndb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdHaskellOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "haskell", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "haskell-osv",
		Short: "Fetch Haskell OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch haskell-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := haskellOSV.Fetch(haskellOSV.WithDir(options.dir), haskellOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch haskell osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "haskell", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdJVNFeedDetail() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "detail"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-detail",
		Short: "Fetch jvn feed detail data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch jvn-feed-detail
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := jvnFeedDetail.Fetch(jvnFeedDetail.WithDir(options.dir), jvnFeedDetail.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed detail")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "detail"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdJVNFeedProduct() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "product"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-product",
		Short: "Fetch jvn feed product data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch jvn-feed-product
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := jvnFeedProduct.Fetch(jvnFeedProduct.WithDir(options.dir), jvnFeedProduct.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed product")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "product"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdJVNFeedRSS() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "rss"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-rss",
		Short: "Fetch jvn feed rss data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch jvn-feed-rss
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := jvnFeedRSS.Fetch(jvnFeedRSS.WithDir(options.dir), jvnFeedRSS.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed rss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "jvn", "feed", "rss"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdKEV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "kev"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "kev",
		Short: "Fetch KEV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch kev
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := kev.Fetch(kev.WithDir(options.dir), kev.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch kev")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "kev"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdLinuxOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "linux", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "linux-osv",
		Short: "Fetch Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch linux-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := linuxOSV.Fetch(linuxOSV.WithDir(options.dir), linuxOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch linux osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "linux", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMageiaOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "mageia", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "mageia-osv",
		Short: "Fetch Mageia Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch mageia-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mageiaOSV.Fetch(mageiaOSV.WithDir(options.dir), mageiaOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mageia osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdMavenGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "maven", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "maven-ghsa",
		Short: "Fetch Maven GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch maven-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mavenGHSA.Fetch(mavenGHSA.WithDir(options.dir), mavenGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch maven ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "maven", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMavenGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "maven", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "maven-glsa",
		Short: "Fetch GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch maven-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mavenGLSA.Fetch(mavenGLSA.WithDir(options.dir), mavenGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch maven glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "maven", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMavenOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "maven", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "maven-osv",
		Short: "Fetch Maven OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch maven-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mavenOSV.Fetch(mavenOSV.WithDir(options.dir), mavenOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch maven osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "maven", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMitreCVRF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "mitre", "cvrf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "mitre-cvrf",
		Short: "Fetch MITRE CVE CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch mitre-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mitreCVRF.Fetch(mitreCVRF.WithDir(options.dir), mitreCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "mitre", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMitreV4() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "mitre", "v4"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "mitre-v4",
		Short: "Fetch MITRE CVE V4 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch mitre-v4
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mitreV4.Fetch(mitreV4.WithDir(options.dir), mitreV4.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre v4")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "mitre", "v4"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMitreV5() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "mitre", "v5"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "mitre-v5",
		Short: "Fetch MITRE CVE V5 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch mitre-v5
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := mitreV5.Fetch(mitreV5.WithDir(options.dir), mitreV5.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre v5")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "mitre", "v5"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdMSF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "msf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "msf",
		Short: "Fetch Metasploit Framework data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch msf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := msf.Fetch(msf.WithDir(options.dir), msf.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch msf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "msf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNetBSD() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "netbsd"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "netbsd",
		Short: "Fetch NetBSD data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch netbsd
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := netbsd.Fetch(netbsd.WithDir(options.dir), netbsd.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch netbsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "netbsd"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNpmDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "npm", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "npm-db",
		Short: "Fetch NPM DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch npm-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := npmDB.Fetch(npmDB.WithDir(options.dir), npmDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "npm", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNpmGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "npm", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "npm-ghsa",
		Short: "Fetch NPM GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch npm-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := npmGHSA.Fetch(npmGHSA.WithDir(options.dir), npmGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch npm ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "npm", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNpmGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "npm", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "npm-glsa",
		Short: "Fetch NPM GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch npm-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := npmGLSA.Fetch(npmGLSA.WithDir(options.dir), npmGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch npm glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "npm", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNpmOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "npm", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "npm-osv",
		Short: "Fetch NPM OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch npm-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := npmOSV.Fetch(npmOSV.WithDir(options.dir), npmOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch npm osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "npm", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNugetGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nuget", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nuget-ghsa",
		Short: "Fetch Nuget GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nuget-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nugetGHSA.Fetch(nugetGHSA.WithDir(options.dir), nugetGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nuget ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nuget", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNugetGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nuget", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nuget-glsa",
		Short: "Fetch Nuget GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nuget-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nugetGLSA.Fetch(nugetGLSA.WithDir(options.dir), nugetGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nuget glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nuget", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNugetOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nuget", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nuget-osv",
		Short: "Fetch Nuget OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nuget-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nugetOSV.Fetch(nugetOSV.WithDir(options.dir), nugetOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nuget osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nuget", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNVDAPICVE() *cobra.Command {
	options := &struct {
		base
		retryWaitMin     int
		retryWaitMax     int
		concurrency      int
		wait             int
		lastModStartDate string
		lastModEndDate   string
		apiKey           string
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cve"),
			retry: 20,
		},
		retryWaitMin: 6,
		retryWaitMax: 30,
		concurrency:  1,
		wait:         6,
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cve",
		Short: "Fetch NVD API CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-api-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var lastModStartDate, lastModEndDate *time.Time
			if options.lastModStartDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModStartDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				}
				lastModStartDate = &t
			}
			if options.lastModEndDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModEndDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				}
				lastModEndDate = &t
			}

			if err := nvdAPICVE.Fetch(
				nvdAPICVE.WithDir(options.dir),
				nvdAPICVE.WithRetry(options.retry), nvdAPICVE.WithRetryWaitMin(options.retryWaitMin), nvdAPICVE.WithRetryWaitMax(options.retryWaitMax),
				nvdAPICVE.WithConcurrency(options.concurrency), nvdAPICVE.WithWait(options.wait),
				nvdAPICVE.WithLastModStartDate(lastModStartDate), nvdAPICVE.WithLastModEndDate(lastModEndDate),
				nvdAPICVE.WithAPIKey(options.apiKey),
			); err != nil {
				return errors.Wrap(err, "failed to fetch nvd api cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 20, "number of retry http request")
	cmd.Flags().IntVarP(&options.retryWaitMin, "retry-wait-min", "", 6, "number of minimum time to retry wait")
	cmd.Flags().IntVarP(&options.retryWaitMax, "retry-wait-max", "", 30, "number of maximum time to retry wait")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 1, "number of concurrent API requests")
	// Rate limet without API key: 5 requests in a rolling 30 second window, and
	// with API key: 50 requests in a rolling 30 second window.
	cmd.Flags().IntVarP(&options.wait, "wait", "", 6, "sleep duration in seconds between consecutive requests")
	cmd.Flags().StringVarP(&options.lastModStartDate, "last-mod-start-date", "", "", "lastModStartDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVarP(&options.lastModEndDate, "last-mod-end-date", "", "", "lastModEndDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVar(&options.apiKey, "api-key", "", "API Key to increase rate limit")

	return cmd
}

func newCmdNVDAPICPE() *cobra.Command {
	options := &struct {
		base
		retryWaitMin     int
		retryWaitMax     int
		concurrency      int
		wait             int
		lastModStartDate string
		lastModEndDate   string
		apiKey           string
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cpe"),
			retry: 20,
		},
		retryWaitMin: 6,
		retryWaitMax: 30,
		concurrency:  1,
		wait:         6,
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cpe",
		Short: "Fetch NVD API CPE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-api-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var lastModStartDate, lastModEndDate *time.Time
			if options.lastModStartDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModStartDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				}
				lastModStartDate = &t
			}
			if options.lastModEndDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModEndDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				}
				lastModEndDate = &t
			}

			if err := nvdAPICPE.Fetch(
				nvdAPICPE.WithDir(options.dir),
				nvdAPICPE.WithRetry(options.retry), nvdAPICPE.WithRetryWaitMin(options.retryWaitMin), nvdAPICPE.WithRetryWaitMax(options.retryWaitMax),
				nvdAPICPE.WithConcurrency(options.concurrency), nvdAPICPE.WithWait(options.wait),
				nvdAPICPE.WithLastModStartDate(lastModStartDate), nvdAPICPE.WithLastModEndDate(lastModEndDate),
				nvdAPICPE.WithAPIKey(options.apiKey),
			); err != nil {
				return errors.Wrap(err, "failed to fetch nvd api cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cpe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 20, "number of retry http request")
	cmd.Flags().IntVarP(&options.retryWaitMin, "retry-wait-min", "", 6, "number of minimum time to retry wait")
	cmd.Flags().IntVarP(&options.retryWaitMax, "retry-wait-max", "", 30, "number of maximum time to retry wait")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 1, "number of concurrent API requests")
	// Rate limet without API key: 5 requests in a rolling 30 second window, and
	// with API key: 50 requests in a rolling 30 second window.
	cmd.Flags().IntVarP(&options.wait, "wait", "", 6, "sleep duration in seconds between consecutive requests")
	cmd.Flags().StringVarP(&options.lastModStartDate, "last-mod-start-date", "", "", "lastModStartDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVarP(&options.lastModEndDate, "last-mod-end-date", "", "", "lastModEndDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVar(&options.apiKey, "api-key", "", "API Key to increase rate limit")

	return cmd
}

func newCmdNVDAPICPEMatch() *cobra.Command {
	options := &struct {
		base
		retryWaitMin     int
		retryWaitMax     int
		concurrency      int
		wait             int
		lastModStartDate string
		lastModEndDate   string
		apiKey           string
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cpematch"),
			retry: 20,
		},
		retryWaitMin: 6,
		retryWaitMax: 30,
		concurrency:  1,
		wait:         6,
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cpematch",
		Short: "Fetch NVD API CPE Match data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-api-cpematch
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var lastModStartDate, lastModEndDate *time.Time
			if options.lastModStartDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModStartDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModStartDate)
				}
				lastModStartDate = &t
			}
			if options.lastModEndDate != "" {
				t, err := time.Parse("2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				if err != nil {
					return errors.Wrapf(err, "failed to parse lastModEndDate option. expected: %q, actual: %q", "2006-01-02T15:04:05.000-07:00", options.lastModEndDate)
				}
				lastModEndDate = &t
			}

			if err := nvdAPICPEMatch.Fetch(
				nvdAPICPEMatch.WithDir(options.dir),
				nvdAPICPEMatch.WithRetry(options.retry), nvdAPICPEMatch.WithRetryWaitMin(options.retryWaitMin), nvdAPICPEMatch.WithRetryWaitMax(options.retryWaitMax),
				nvdAPICPEMatch.WithConcurrency(options.concurrency), nvdAPICPEMatch.WithWait(options.wait),
				nvdAPICPEMatch.WithLastModStartDate(lastModStartDate), nvdAPICPEMatch.WithLastModEndDate(lastModEndDate),
				nvdAPICPEMatch.WithAPIKey(options.apiKey),
			); err != nil {
				return errors.Wrap(err, "failed to fetch nvd api cpematch")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "api", "cpematch"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 20, "number of retry http request")
	cmd.Flags().IntVarP(&options.retryWaitMin, "retry-wait-min", "", 6, "number of minimum time to retry wait")
	cmd.Flags().IntVarP(&options.retryWaitMax, "retry-wait-max", "", 30, "number of maximum time to retry wait")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 1, "number of concurrent API requests")
	// Rate limet without API key: 5 requests in a rolling 30 second window, and
	// with API key: 50 requests in a rolling 30 second window.
	cmd.Flags().IntVarP(&options.wait, "wait", "", 6, "sleep duration in seconds between consecutive requests")
	cmd.Flags().StringVarP(&options.lastModStartDate, "last-mod-start-date", "", "", "lastModStartDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVarP(&options.lastModEndDate, "last-mod-end-date", "", "", "lastModEndDate. use extended ISO-8601 date/time format: 2021-08-04T13:00:00.000%2B01:00")
	cmd.Flags().StringVar(&options.apiKey, "api-key", "", "API Key to increase rate limit")

	return cmd
}

func newCmdNVDFeedCVE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cve"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cve",
		Short: "Fetch NVD CVE Feed data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-feed-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nvdFeedCVE.Fetch(nvdFeedCVE.WithDir(options.dir), nvdFeedCVE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNVDFeedCPE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpe"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpe",
		Short: "Fetch NVD CPE Dictionary Feed data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-feed-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nvdFeedCPE.Fetch(nvdFeedCPE.WithDir(options.dir), nvdFeedCPE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdNVDFeedCPEMatch() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpematch"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpematch",
		Short: "Fetch NVD CPE Match Feed data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-feed-cpematch
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nvdFeedCPEMatch.Fetch(nvdFeedCPEMatch.WithDir(options.dir), nvdFeedCPEMatch.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "nvd", "feed", "cpematch"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdOpenEulerCVRF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "openeuler", "cvrf"),
			retry: 5,
		},
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "openeuler-cvrf",
		Short: "Fetch openEuler CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch openeuler-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := openeulerCVRF.Fetch(openeulerCVRF.WithDir(options.dir), openeulerCVRF.WithRetry(options.retry), openeulerCVRF.WithConcurrency(options.concurrency), openeulerCVRF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch openeuler cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdOpenEulerCSAF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "openeuler", "csaf"),
			retry: 5,
		},
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "openeuler-csaf",
		Short: "Fetch openEuler CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch openeuler-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := openeulerCSAF.Fetch(openeulerCSAF.WithDir(options.dir), openeulerCSAF.WithRetry(options.retry), openeulerCSAF.WithConcurrency(options.concurrency), openeulerCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch openeuler csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdOracle() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "oracle"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "oracle",
		Short: "Fetch Oracle Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch oracle
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := oracle.Fetch(oracle.WithDir(options.dir), oracle.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch oracle linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "oracle"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdOSSFuzzOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "oss-fuzz", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "oss-fuzz-osv",
		Short: "Fetch OSS-Fuzz OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch oss-fuzz-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ossFuzzOSV.Fetch(ossFuzzOSV.WithDir(options.dir), ossFuzzOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch oss-fuzz osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "oss-fuzz", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPaloAltoList() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "paloalto", "list"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "paloalto-list",
		Short: "Fetch Palo Alto List data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch paloalto-list
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := paloaltoList.Fetch(paloaltoList.WithDir(options.dir), paloaltoList.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch paloalto list")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdPaloAltoJSON() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "paloalto", "json"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "paloalto-json [<Palo Alto Networks Security Advisory ID>]",
		Short: "Fetch Palo Alto JSON data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch paloalto-json CVE-2025-0114 PAN-SA-2025-0007
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := paloaltoJSON.Fetch(args, paloaltoJSON.WithDir(options.dir), paloaltoJSON.WithRetry(options.retry), paloaltoJSON.WithConcurrency(options.concurrency), paloaltoJSON.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch paloalto json")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdPaloAltoCSAF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "paloalto", "csaf"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "paloalto-csaf [<Palo Alto Networks Security Advisory ID>]",
		Short: "Fetch Palo Alto CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch paloalto-csaf CVE-2025-0114 PAN-SA-2025-0007
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := paloaltoCSAF.Fetch(args, paloaltoCSAF.WithDir(options.dir), paloaltoCSAF.WithRetry(options.retry), paloaltoCSAF.WithConcurrency(options.concurrency), paloaltoCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch paloalto csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdPerlDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "perl", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "perl-db",
		Short: "Fetch Perl DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch perl-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// if err := perlDB.Fetch(perlDB.WithDir(options.dir), perlDB.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch perl db")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "perl", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPhotonCVE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "photon", "cve"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "photon-cve",
		Short: "Fetch Photon CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch photon-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := photonCVE.Fetch(photonCVE.WithDir(options.dir), photonCVE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch photon cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdPhotonOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "photon", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "photon-oval",
		Short: "Fetch Photon OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch photon-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := photonOVAL.Fetch(photonOVAL.WithDir(options.dir), photonOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch photon oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdPipDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pip", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pip-db",
		Short: "Fetch Pip DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pip-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := pipDB.Fetch(pipDB.WithDir(options.dir), pipDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pip", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPipGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pip", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pip-ghsa",
		Short: "Fetch Pip GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pip-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := pipGHSA.Fetch(pipGHSA.WithDir(options.dir), pipGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch pip ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pip", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPipGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pip", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pip-glsa",
		Short: "Fetch Pip GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pip-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := pipGLSA.Fetch(pipGLSA.WithDir(options.dir), pipGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch pip glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pip", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPipOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pip", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pip-osv",
		Short: "Fetch Pip OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pip-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := pipOSV.Fetch(pipOSV.WithDir(options.dir), pipOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch pip osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pip", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPubGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pub", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pub-ghsa",
		Short: "Fetch Pub GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pub-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := pubGHSA.Fetch(pubGHSA.WithDir(options.dir), pubGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch pub ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pub", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdPubOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "pub", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "pub-osv",
		Short: "Fetch Pub Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch pub-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := pubOSV.Fetch(pubOSV.WithDir(options.dir), pubOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch pub osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "pub", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdROSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "r", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "r-osv",
		Short: "Fetch R OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch r-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rOSV.Fetch(rOSV.WithDir(options.dir), rOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch r osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "r", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRedHatCVE() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "cve"),
			retry: 20,
		},
		concurrency: 15,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "redhat-cve",
		Short: "Fetch RedHat Enterprise Linux CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatCVE.Fetch(redhatCVE.WithDir(options.dir), redhatCVE.WithRetry(options.retry), redhatCVE.WithConcurrency(options.concurrency), redhatCVE.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 20, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 15, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdRedHatCSAF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "csaf"),
			retry: 3,
		},
		concurrency: 10,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "redhat-csaf",
		Short: "Fetch RedHat Enterprise Linux CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatCSAF.Fetch(redhatCSAF.WithDir(options.dir), redhatCSAF.WithRetry(options.retry), redhatCSAF.WithConcurrency(options.concurrency), redhatCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "csaf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 10, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdRedHatCVRF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "cvrf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-cvrf",
		Short: "Fetch RedHat Enterprise Linux CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatCVRF.Fetch(redhatCVRF.WithDir(options.dir), redhatCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRedHatOVALRepositoryToCPE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "repository-to-cpe"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-repository-to-cpe",
		Short: "Fetch RedHat Enterprise Linux Repository-to-CPE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-repository-to-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatRepositoryToCPE.Fetch(redhatRepositoryToCPE.WithDir(options.dir), redhatRepositoryToCPE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat oval repository-to-cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "repository-to-cpe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRedHatOVALV1() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "oval", "v1"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-ovalv1",
		Short: "Fetch RedHat Enterprise Linux OVALv1 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-ovalv1
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatOVALv1.Fetch(redhatOVALv1.WithDir(options.dir), redhatOVALv1.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "oval", "v1"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRedHatOVALV2() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "oval", "v2"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-ovalv2",
		Short: "Fetch RedHat Enterprise Linux OVALv2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-ovalv2
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatOVALv2.Fetch(redhatOVALv2.WithDir(options.dir), redhatOVALv2.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "oval", "v2"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRedHatVEX() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "vex"),
			retry: 3,
		},
		concurrency: 10,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "redhat-vex",
		Short: "Fetch RedHat Enterprise Linux CSAF VEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-vex
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatVEX.Fetch(redhatVEX.WithDir(options.dir), redhatVEX.WithRetry(options.retry), redhatVEX.WithConcurrency(options.concurrency), redhatVEX.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "vex"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 10, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdRedHatOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "redhat", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-osv",
		Short: "Fetch RedHat Enterprise Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatOSV.Fetch(redhatOSV.WithDir(options.dir), redhatOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "redhat", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRockyErrata() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rocky", "errata"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rocky-errata",
		Short: "Fetch Rocky Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rocky-errata
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rockyErrata.Fetch(rockyErrata.WithDir(options.dir), rockyErrata.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rocky")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rocky", "errata"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRockyOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rocky", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rocky-osv",
		Short: "Fetch Rocky Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rocky-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rockyOSV.Fetch(rockyOSV.WithDir(options.dir), rockyOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rocky")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rocky", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRubygemsDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rubygems", "db"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rubygems-db",
		Short: "Fetch Rubygems DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rubygems-db
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := rubygemsDB.Fetch(rubygemsDB.WithDir(options.dir), rubygemsDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems db")
			// 	}
			return errors.New("not yet implemented")
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rubygems", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRubygemsGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rubygems", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rubygems-ghsa",
		Short: "Fetch Rubygems GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rubygems-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rubygemsGHSA.Fetch(rubygemsGHSA.WithDir(options.dir), rubygemsGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rubygems ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rubygems", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRubygemsGLSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rubygems", "glsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rubygems-glsa",
		Short: "Fetch Rubygems GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rubygems-glsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rubygemsGLSA.Fetch(rubygemsGLSA.WithDir(options.dir), rubygemsGLSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rubygems glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rubygems", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdRubygemsOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "rubygems", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "rubygems-osv",
		Short: "Fetch Rubygems OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch rubygems-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := rubygemsOSV.Fetch(rubygemsOSV.WithDir(options.dir), rubygemsOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rubygems osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "rubygems", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSnort() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "snort"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "snort",
		Short: "Fetch Snort Community Rule data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch snort
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := snort.Fetch(snort.WithDir(options.dir), snort.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch snort")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "snort"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSUSEOVAL() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "oval"),
			retry: 3,
		},
		concurrency: 3,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "suse-oval",
		Short: "Fetch SUSE OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseOVAL.Fetch(suseOVAL.WithDir(options.dir), suseOVAL.WithRetry(options.retry), suseOVAL.WithConcurrency(options.concurrency), suseOVAL.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 3, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdSUSECVRF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf",
		Short: "Fetch SUSE CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCVRF.Fetch(suseCVRF.WithDir(options.dir), suseCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSUSECVRFCVE() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf-cve"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf-cve",
		Short: "Fetch SUSE CVRF CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-cvrf-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCVRFCVE.Fetch(suseCVRFCVE.WithDir(options.dir), suseCVRFCVE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse cvrf cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "cvrf-cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSUSECSAF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "csaf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf",
		Short: "Fetch SUSE CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCSAF.Fetch(suseCSAF.WithDir(options.dir), suseCSAF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "csaf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSUSECSAFVEX() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "csaf-vex"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf-vex",
		Short: "Fetch SUSE CSAF VEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-csaf-vex
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCSAFVEX.Fetch(suseCSAFVEX.WithDir(options.dir), suseCSAFVEX.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse csaf vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "csaf-vex"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSUSEOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "suse", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-osv",
		Short: "Fetch SUSE OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseOSV.Fetch(suseOSV.WithDir(options.dir), suseOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "suse", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSwiftGHSA() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "swift", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "swift-ghsa",
		Short: "Fetch Swift GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch swift-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := swiftGHSA.Fetch(swiftGHSA.WithDir(options.dir), swiftGHSA.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch swift ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "swift", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdSwiftOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "swift", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "swift-osv",
		Short: "Fetch Swift OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch swift-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := swiftOSV.Fetch(swiftOSV.WithDir(options.dir), swiftOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch swift osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "swift", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdUbuntuOVAL() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ubuntu", "oval"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-oval",
		Short: "Fetch Ubuntu OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ubuntu-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ubuntuOVAL.Fetch(ubuntuOVAL.WithDir(options.dir), ubuntuOVAL.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "ubuntu", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdUbuntuCVETracker() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ubuntu", "ubuntu-cve-tracker"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-cve-tracker",
		Short: "Fetch Ubuntu CVE Tracker data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ubuntu-cve-tracker
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ubuntuCVETracker.Fetch(ubuntuCVETracker.WithDir(options.dir), ubuntuCVETracker.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu cve tracker")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "ubuntu", "ubuntu-cve-tracker"), "output fetch results to specified directory")

	return cmd
}

func newCmdUbuntuUSNDB() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ubuntu", "usndb"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-usndb",
		Short: "Fetch Ubuntu USN DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ubuntu-usndb
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ubuntuUSNDB.Fetch(ubuntuUSNDB.WithDir(options.dir), ubuntuUSNDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu usndb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdUbuntuOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ubuntu", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-osv",
		Short: "Fetch Ubuntu OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ubuntu-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ubuntuOSV.Fetch(ubuntuOSV.WithDir(options.dir), ubuntuOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "ubuntu", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdUbuntuVEX() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "ubuntu", "vex"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-vex",
		Short: "Fetch Ubuntu OpenVEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch ubuntu-vex
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := ubuntuVEX.Fetch(ubuntuVEX.WithDir(options.dir), ubuntuVEX.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdVulnCheckKEV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "vulncheck", "kev"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "vulncheck-kev <VulnCheck token>",
		Short: "Fetch VulnCheck KEV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch vulncheck-kev vulncheck_token
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := vulncheckKEV.Fetch(args[0], vulncheckKEV.WithDir(options.dir), vulncheckKEV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch vulncheck kev")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "vulncheck", "kev"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdWindowsBulletin() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "bulletin"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-bulletin",
		Short: "Fetch Windows Bulletin data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-bulletin
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsBulletin.Fetch(windowsBulletin.WithDir(options.dir), windowsBulletin.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows bulletin")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "windows", "bulletin"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdWindowsCVRF() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "cvrf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-cvrf",
		Short: "Fetch Windows CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsCVRF.Fetch(windowsCVRF.WithDir(options.dir), windowsCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "windows", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdWindowsCSAF() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "csaf"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "windows-csaf",
		Short: "Fetch Windows CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsCSAF.Fetch(windowsCSAF.WithDir(options.dir), windowsCSAF.WithRetry(options.retry), windowsCSAF.WithConcurrency(options.concurrency), windowsCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch windows csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", options.concurrency, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", options.wait, "wait seccond")

	return cmd
}

func newCmdWindowsMSUC() *cobra.Command {
	options := &struct {
		base
		concurrency int
		wait        int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "msuc"),
			retry: 3,
		},
		concurrency: 5,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "windows-msuc [KBID]",
		Short: "Fetch Windows Microsoft Software Update Catalog data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-msuc "KB5019311", "KB5017389", "KB5018427", "KB5019509", "KB5018496", "KB5019980", "KB5020044", "KB5021255", "KB5022303", "KB5022360", "KB5022845"
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsMSUC.Fetch(args, windowsMSUC.WithDir(options.dir), windowsMSUC.WithRetry(options.retry), windowsMSUC.WithConcurrency(options.concurrency), windowsMSUC.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch windows msuc")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "windows", "msuc"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 5, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdWindowsAdvisory() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "advisory"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-advisory",
		Short: "Fetch Microsoft Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-advisory
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsAdvisory.Fetch(windowsAdvisory.WithDir(options.dir), windowsAdvisory.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows advisory")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdWindowsVulnerability() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "vulnerability"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-vulnerability",
		Short: "Fetch Microsoft Vulnerability data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-vulnerability
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsVulnerability.Fetch(windowsVulnerability.WithDir(options.dir), windowsVulnerability.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows vulnerability")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdWindowsProduct() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "product"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-product",
		Short: "Fetch Microsoft Product data source",
		Example: heredoc.Doc(`
				$ vuls-data-update fetch windows-product
			`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsProduct.Fetch(windowsProduct.WithDir(options.dir), windowsProduct.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows product")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", options.retry, "number of retry http request")

	return cmd
}

func newCmdWindowsWSUSSCN2() *cobra.Command {
	options := &struct {
		base
		concurrency int
	}{
		base: base{
			dir:   filepath.Join(util.CacheDir(), "fetch", "windows", "wsusscn2"),
			retry: 3,
		},
		concurrency: 2,
	}

	cmd := &cobra.Command{
		Use:   "windows-wsusscn2",
		Short: "Fetch Windows WSUSSCN2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-wsusscn2
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := windowsWSUSSCN2.Fetch(windowsWSUSSCN2.WithDir(options.dir), windowsWSUSSCN2.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows wsusscn2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "windows", "wsusscn2"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 2, "number of concurrency cabextract")

	return cmd
}

func newCmdWolfiOSV() *cobra.Command {
	options := &base{
		dir:   filepath.Join(util.CacheDir(), "fetch", "wolfi", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "wolfi-osv",
		Short: "Fetch Wolfi OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch wolfi-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := wolfiOSV.Fetch(wolfiOSV.WithDir(options.dir), wolfiOSV.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch wolfi osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fetch", "wolfi", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
