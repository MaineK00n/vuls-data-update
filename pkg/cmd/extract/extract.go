package extract

import (
	"path/filepath"
	"runtime"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	almaErrata "github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
	almaOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/alma/osv"
	almaOVAL "github.com/MaineK00n/vuls-data-update/pkg/extract/alma/oval"
	alpineOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/alpine/osv"
	alpineSecDB "github.com/MaineK00n/vuls-data-update/pkg/extract/alpine/secdb"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/amazon"
	androidOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/android/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/arch"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/attack"
	bitnamiOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/bitnami/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/capec"
	cargoDB "github.com/MaineK00n/vuls-data-update/pkg/extract/cargo/db"
	cargoGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/cargo/ghsa"
	cargoOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/cargo/osv"
	chainguardOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/chainguard/osv"
	cisaKEV "github.com/MaineK00n/vuls-data-update/pkg/extract/cisa/kev"
	composerDB "github.com/MaineK00n/vuls-data-update/pkg/extract/composer/db"
	composerGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/composer/ghsa"
	composerGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/composer/glsa"
	composerOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/composer/osv"
	conanGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/conan/glsa"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/cwe"
	debianOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/debian/osv"
	debianOVAL "github.com/MaineK00n/vuls-data-update/pkg/extract/debian/oval"
	debianSecurityTrackerAPI "github.com/MaineK00n/vuls-data-update/pkg/extract/debian/tracker/api"
	debianSecurityTrackerSalsa "github.com/MaineK00n/vuls-data-update/pkg/extract/debian/tracker/salsa"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/eol"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/epss"
	erlangGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/erlang/ghsa"
	erlangOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/erlang/osv"
	exploitExploitDB "github.com/MaineK00n/vuls-data-update/pkg/extract/exploit/exploitdb"
	exploitGitHub "github.com/MaineK00n/vuls-data-update/pkg/extract/exploit/github"
	exploitInTheWild "github.com/MaineK00n/vuls-data-update/pkg/extract/exploit/inthewild"
	exploitTrickest "github.com/MaineK00n/vuls-data-update/pkg/extract/exploit/trickest"
	fedoraAPI "github.com/MaineK00n/vuls-data-update/pkg/extract/fedora/api"
	fortinetCVRF "github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/cvrf"
	fortinetHandmade "github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/handmade"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/gentoo"
	ghactionsOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/ghactions/osv"
	gitOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/git/osv"
	golangDB "github.com/MaineK00n/vuls-data-update/pkg/extract/golang/db"
	golangGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/golang/ghsa"
	golangGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/golang/glsa"
	golangOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/golang/osv"
	golangVulnDB "github.com/MaineK00n/vuls-data-update/pkg/extract/golang/vulndb"
	haskellOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/haskell/osv"
	jvnFeedDetail "github.com/MaineK00n/vuls-data-update/pkg/extract/jvn/feed/detail"
	jvnFeedProduct "github.com/MaineK00n/vuls-data-update/pkg/extract/jvn/feed/product"
	jvnFeedRSS "github.com/MaineK00n/vuls-data-update/pkg/extract/jvn/feed/rss"
	linuxOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/linux/osv"
	mavenGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/maven/ghsa"
	mavenGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/maven/glsa"
	mavenOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/maven/osv"
	mitreCVRF "github.com/MaineK00n/vuls-data-update/pkg/extract/mitre/cvrf"
	mitreV4 "github.com/MaineK00n/vuls-data-update/pkg/extract/mitre/v4"
	mitreV5 "github.com/MaineK00n/vuls-data-update/pkg/extract/mitre/v5"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/netbsd"
	npmDB "github.com/MaineK00n/vuls-data-update/pkg/extract/npm/db"
	npmGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/npm/ghsa"
	npmGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/npm/glsa"
	npmOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/npm/osv"
	nugetGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/nuget/ghsa"
	nugetGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/nuget/glsa"
	nugetOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/nuget/osv"
	nvdAPICPE "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/api/cpe"
	nvdAPICVE "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/api/cve"
	nvdFeedCPEv1 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cpe/v1"
	nvdFeedCPEv2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cpe/v2"
	nvdFeedCPEMATCHv1 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cpematch/v1"
	nvdFeedCPEMATCHv2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cpematch/v2"
	nvdFeedCVEv1 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cve/v1"
	nvdFeedCVEv2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cve/v2"
	oracleLinux "github.com/MaineK00n/vuls-data-update/pkg/extract/oracle/linux"
	ossFuzzOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/oss-fuzz/osv"
	perlDB "github.com/MaineK00n/vuls-data-update/pkg/extract/perl/db"
	pipDB "github.com/MaineK00n/vuls-data-update/pkg/extract/pip/db"
	pipGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/pip/ghsa"
	pipGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/pip/glsa"
	pipOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/pip/osv"
	pubGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/pub/ghsa"
	pubOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/pub/osv"
	rOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/r/osv"
	redhatCSAF "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/csaf"
	redhatCVE "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/cve"
	redhatCVRF "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/cvrf"
	redhatOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/osv"
	redhatOVALv1 "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/oval/v1"
	redhatOVALv2 "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/oval/v2"
	redhatVEX "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/vex"
	rockyErrata "github.com/MaineK00n/vuls-data-update/pkg/extract/rocky/errata"
	rockyOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/rocky/osv"
	rubygemsDB "github.com/MaineK00n/vuls-data-update/pkg/extract/rubygems/db"
	rubygemsGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/rubygems/ghsa"
	rubygemsGLSA "github.com/MaineK00n/vuls-data-update/pkg/extract/rubygems/glsa"
	rubygemsOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/rubygems/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/snort"
	suseCSAF "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/csaf"
	suseCSAFVEX "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/csaf_vex"
	suseCVRF "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/cvrf"
	suseCVRFCVE "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/cvrf_cve"
	suseOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/osv"
	suseOVAL "github.com/MaineK00n/vuls-data-update/pkg/extract/suse/oval"
	swiftGHSA "github.com/MaineK00n/vuls-data-update/pkg/extract/swift/ghsa"
	swiftOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/swift/osv"
	ubuntuOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/ubuntu/osv"
	ubuntuOVAL "github.com/MaineK00n/vuls-data-update/pkg/extract/ubuntu/oval"
	ubuntuCVETracker "github.com/MaineK00n/vuls-data-update/pkg/extract/ubuntu/tracker"
	vulncheckKEV "github.com/MaineK00n/vuls-data-update/pkg/extract/vulncheck/kev"
	windowsBulletin "github.com/MaineK00n/vuls-data-update/pkg/extract/windows/bulletin"
	windowsCVRF "github.com/MaineK00n/vuls-data-update/pkg/extract/windows/cvrf"
	windowsMSUC "github.com/MaineK00n/vuls-data-update/pkg/extract/windows/msuc"
	windowsWSUSSCN2 "github.com/MaineK00n/vuls-data-update/pkg/extract/windows/wsusscn2"
	wolfiOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/wolfi/osv"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

type base struct {
	dir string
}

func NewCmdExtract() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract <data source>",
		Short: "Extract data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract debian-security-tracker-salsa vuls-data-raw-debian-security-tracker-salsa
		`),
	}

	cmd.AddCommand(
		newCmdAlmaErrata(), newCmdAlmaOSV(), newCmdAlmaOVAL(),
		newCmdAlpineSecDB(), newCmdAlpineOSV(),
		newCmdAmazon(),
		newCmdAndroidOSV(),
		newCmdArch(),
		newCmdAttack(),
		newCmdBitnamiOSV(),
		newCmdCapec(),
		newCmdCargoGHSA(), newCmdCargoOSV(), newCmdCargoDB(),
		newCmdChainguardOSV(),
		newCmdCISAKEV(),
		newCmdComposerGHSA(), newCmdComposerGLSA(), newCmdComposerOSV(), newCmdComposerDB(),
		newCmdConanGLSA(),
		newCmdCWE(),
		newCmdDebianOVAL(), newCmdDebianSecurityTrackerAPI(), newCmdDebianSecurityTrackerSalsa(), newCmdDebianOSV(),
		newCmdEOL(),
		newCmdEPSS(),
		newCmdErlangGHSA(), newCmdErlangOSV(),
		newCmdExploitExploitDB(), newCmdExploitGitHub(), newCmdExploitInTheWild(), newCmdExploitTrickest(),
		newCmdFedoraAPI(),
		newCmdFortinetHandmade(), newCmdFortinetCVRF(),
		newCmdFreeBSD(),
		newCmdGentoo(),
		newCmdGHActionsOSV(),
		newCmdGitOSV(),
		newCmdGolangGHSA(), newCmdGolangGLSA(), newCmdGolangOSV(), newCmdGolangDB(), newCmdGolangVulnDB(),
		newCmdHaskellOSV(),
		newCmdJVNFeedDetail(), newCmdJVNFeedProduct(), newCmdJVNFeedRSS(),
		newCmdLinuxOSV(),
		newCmdMavenGHSA(), newCmdMavenGLSA(), newCmdMavenOSV(),
		newCmdMitreCVRF(), newCmdMitreV4(), newCmdMitreV5(),
		newCmdMSF(),
		newCmdNetBSD(),
		newCmdNpmGHSA(), newCmdNpmGLSA(), newCmdNpmOSV(), newCmdNpmDB(),
		newCmdNugetGHSA(), newCmdNugetGLSA(), newCmdNugetOSV(),
		newCmdNVDAPICVE(), newCmdNVDAPICPE(), newCmdNVDFeedCVEv1(), newCmdNVDFeedCPEv1(), newCmdNVDFeedCPEMATCHv1(), newCmdNVDFeedCVEv2(), newCmdNVDFeedCPEv2(), newCmdNVDFeedCPEMATCHv2(),
		newCmdOracleLinux(),
		newCmdOSSFuzzOSV(),
		newCmdPerlDB(),
		newCmdPipGHSA(), newCmdPipGLSA(), newCmdPipOSV(), newCmdPipDB(),
		newCmdPubGHSA(), newCmdPubOSV(),
		newCmdROSV(),
		newCmdRedHatOVALv1(), newCmdRedHatOVALv2(), newCmdRedHatCVE(), newCmdRedHatCVRF(), newCmdRedHatCSAF(), newCmdRedHatVEX(), newCmdRedHatOSV(),
		newCmdRockyErrata(), newCmdRockyOSV(),
		newCmdRubygemsGHSA(), newCmdRubygemsGLSA(), newCmdRubygemsOSV(), newCmdRubygemsDB(),
		newCmdSnort(),
		newCmdSUSEOVAL(), newCmdSUSECVRF(), newCmdSUSECVRFCVE(), newCmdSUSECSAF(), newCmdSUSECSAFVEX(), newCmdSUSEOSV(),
		newCmdSwiftGHSA(), newCmdSwiftOSV(),
		newCmdUbuntuOVAL(), newCmdUbuntuCVETracker(), newCmdUbuntuOSV(),
		newCmdVulnCheckKEV(),
		newCmdWindowsBulletin(), newCmdWindowsCVRF(), newCmdWindowsMSUC(), newCmdWindowsWSUSSCN2(),
		newCmdWolfiOSV(),
	)

	return cmd
}

func newCmdAlmaErrata() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "errata"),
	}

	cmd := &cobra.Command{
		Use:   "alma-errata <Raw AlmaLinux Errata Repository PATH>",
		Short: "Extract AlmaLinux Errata data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alma-errata vuls-data-raw-alma-errata
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := almaErrata.Extract(args[0], almaErrata.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract almalinux errata")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "alma", "errata"), "output extract results to specified directory")

	return cmd
}

func newCmdAlmaOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "alma-osv <Raw AlmaLinux OSV Repository PATH>",
		Short: "Extract AlmaLinux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alma-osv vuls-data-raw-alma-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := almaOSV.Extract(args[0], almaOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract almalinux osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "alma", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdAlmaOVAL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alma", "oval"),
	}

	cmd := &cobra.Command{
		Use:   "alma-oval <Raw AlmaLinux OVAL Repository PATH>",
		Short: "Extract AlmaLinux OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alma-oval vuls-data-raw-alma-oval
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := almaOVAL.Extract(args[0], almaOVAL.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract almalinux oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "alma", "oval"), "output extract results to specified directory")

	return cmd
}

func newCmdAlpineSecDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alpine", "secdb"),
	}

	cmd := &cobra.Command{
		Use:   "alpine-secdb <Raw Alpine Linux SecDB Repository PATH>",
		Short: "Extract Alpine Linux SecDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alpine-secdb vuls-data-raw-alpine-secdb
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := alpineSecDB.Extract(args[0], alpineSecDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract alpine linux secdb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "alpine", "secdb"), "output extract results to specified directory")

	return cmd
}

func newCmdAlpineOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "alpine", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "alpine-osv <Raw Alpine Linux OSV Repository PATH>",
		Short: "Extract Alpine Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract alpine-osv vuls-data-raw-alpine-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := alpineOSV.Extract(args[0], alpineOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract alpine linux osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "alpine", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdAmazon() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "amazon"),
	}

	cmd := &cobra.Command{
		Use:   "amazon <Raw Amazon Linux Repository PATH>",
		Short: "Extract Amazon Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract amazon vuls-data-raw-amazon
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := amazon.Extract(args[0], amazon.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract amazon")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "amazon"), "output extract results to specified directory")

	return cmd
}

func newCmdAndroidOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "android", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "android-osv <Raw Android OSV Repository PATH>",
		Short: "Extract Android OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract android-osv vuls-data-raw-android-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := androidOSV.Extract(args[0], androidOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract android osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "android", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdArch() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "arch"),
	}

	cmd := &cobra.Command{
		Use:   "arch <Raw Arch Linux Repository PATH>",
		Short: "Extract Arch Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract arch vuls-data-raw-arch
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := arch.Extract(args[0], arch.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract arch")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "arch"), "output extract results to specified directory")

	return cmd
}

func newCmdAttack() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cwe-capec-attack"),
	}

	cmd := &cobra.Command{
		Use:   "attack <Raw Attack Repository PATH>",
		Short: "Extract Attack data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract attack vuls-data-raw-attack
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := attack.Extract(args[0], attack.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract attack")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "attack"), "output extract results to specified directory")

	return cmd
}

func newCmdBitnamiOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "bitnami", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "bitnami-osv <Raw Bitnami OSV Repository PATH>",
		Short: "Extract Bitnami OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract bitnami-osv vuls-data-raw-bitnami-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := bitnamiOSV.Extract(args[0], bitnamiOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract bitnami osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "bitnami", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdCapec() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "capec"),
	}

	cmd := &cobra.Command{
		Use:   "capec <Raw Capec Repository PATH>",
		Short: "Extract Capec data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract capec vuls-data-raw-capec
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := capec.Extract(args[0], capec.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract capec")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "capec"), "output extract results to specified directory")

	return cmd
}

func newCmdCargoGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cargo", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "cargo-ghsa <Raw Cargo GHSA Repository PATH>",
		Short: "Extract Cargo GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract cargo-ghsa vuls-data-raw-cargo-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cargoGHSA.Extract(args[0], cargoGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract cargo ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "cargo", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdCargoOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cargo", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "cargo-osv <Raw Cargo OSV Repository PATH>",
		Short: "Extract Cargo OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract cargo-osv vuls-data-raw-cargo-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cargoOSV.Extract(args[0], cargoOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract cargo osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "cargo", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdCargoDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cargo", "db"),
	}

	cmd := &cobra.Command{
		Use:   "cargo-db <Raw Cargo DB Repository PATH>",
		Short: "Extract Cargo DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract cargo-db vuls-data-raw-cargo-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cargoDB.Extract(args[0], cargoDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract cargo db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "cargo", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdChainguardOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "chainguard", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "chainguard-osv <Raw Chainguard OSV Repository PATH>",
		Short: "Extract Chainguard OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract chainguard-osv vuls-data-raw-chainguard-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := chainguardOSV.Extract(args[0], chainguardOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract chainguard osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "chainguard", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdCISAKEV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cisa", "kev"),
	}

	cmd := &cobra.Command{
		Use:   "cisa-kev <Raw CISA KEV Repository PATH>",
		Short: "Extract CISA KEV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract cisa-kev vuls-data-raw-cisa-kev
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cisaKEV.Extract(args[0], cisaKEV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract cisa kev")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdComposerGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "composer", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "composer-ghsa <Raw Composer GHSA Repository PATH>",
		Short: "Extract Composer GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract composer-ghsa vuls-data-raw-composer-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := composerGHSA.Extract(args[0], composerGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract composer ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "composer", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdComposerGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "composer", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "composer-glsa <Raw Composer GLSA Repository PATH>",
		Short: "Extract Composer GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract composer-glsa vuls-data-raw-composer-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := composerGLSA.Extract(args[0], composerGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract composer glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "composer", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdComposerOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "composer", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "composer-osv <Raw Composer OSV Repository PATH>",
		Short: "Extract Composer OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract composer-osv vuls-data-raw-composer-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := composerOSV.Extract(args[0], composerOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract composer osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "composer", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdComposerDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "composer", "db"),
	}

	cmd := &cobra.Command{
		Use:   "composer-db <Raw Composer DB Repository PATH>",
		Short: "Extract Composer DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract composer-db vuls-data-raw-composer-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := composerDB.Extract(args[0], composerDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract composer db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "composer", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdConanGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "conan", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "conan-glsa <Raw Conan GLSA Repository PATH>",
		Short: "Extract Conan GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract conan-glsa vuls-data-raw-conan-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := conanGLSA.Extract(args[0], conanGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract conan glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "conan", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdCWE() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "cwe"),
	}

	cmd := &cobra.Command{
		Use:   "cwe-capec-attack <Raw CWE Repository PATH>",
		Short: "Extract CWE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract cwe vuls-data-raw-cwe
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := cwe.Extract(args[0], cwe.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract cwe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "cwe"), "output extract results to specified directory")

	return cmd
}

func newCmdDebianOVAL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "debian", "oval"),
	}

	cmd := &cobra.Command{
		Use:   "debian-oval <Raw Debian OVAL Repository PATH>",
		Short: "Extract Debian OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract debian-oval vuls-data-raw-debian-oval
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := debianOVAL.Extract(args[0], debianOVAL.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to fetch extract oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "debian", "oval"), "output extract results to specified directory")

	return cmd
}

func newCmdDebianSecurityTrackerAPI() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "debian", "security-tracker", "api"),
	}

	cmd := &cobra.Command{
		Use:   "debian-security-tracker-api <Raw Debian Security Tracker API Repository PATH>",
		Short: "Extract Debian Security Tracker API data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract debian-security-tracker-api vuls-data-raw-debian-security-tracker-api
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := debianSecurityTrackerAPI.Extract(args[0], debianSecurityTrackerAPI.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to fetch debian security tracker api")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "debian", "security-tracker", "api"), "output fetch results to specified directory")

	return cmd
}

func newCmdDebianSecurityTrackerSalsa() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "debian", "security-tracker", "salsa"),
	}

	cmd := &cobra.Command{
		Use:   "debian-security-tracker-salsa <Raw Debian Security Tracker Salsa Repository PATH>",
		Short: "Extract Debian Security Tracker Salsa repository data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract debian-security-tracker-salsa vuls-data-raw-debian-security-tracker-salsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := debianSecurityTrackerSalsa.Extract(args[0], debianSecurityTrackerSalsa.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to fetch debian security tracker salsa repository")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "debian", "security-tracker", "salsa"), "output fetch results to specified directory")

	return cmd
}

func newCmdDebianOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "debian", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "debian-osv <Raw Debian OSV Repository PATH>",
		Short: "Extract Debian OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract debian-osv vuls-data-raw-debian-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, args []string) error {
			if err := debianOSV.Extract(args[0], debianOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to fetch debian osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "debian", "osv"), "output fetch results to specified directory")

	return cmd
}

func newCmdEOL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "eol"),
	}

	cmd := &cobra.Command{
		Use:   "eol",
		Short: "Extract EOL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract eol
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := eol.Extract(eol.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract eol")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "eol"), "output extract results to specified directory")

	return cmd
}

func newCmdEPSS() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "epss"),
	}

	cmd := &cobra.Command{
		Use:   "epss <Raw EPSS Repository PATH>",
		Short: "Extract EPSS data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract epss vuls-data-raw-epss
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := epss.Extract(args[0], epss.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract epss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "epss"), "output extract results to specified directory")

	return cmd
}

func newCmdErlangGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "erlang", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "erlang-ghsa <Raw Erlang GHSA Repository PATH>",
		Short: "Extract Erlang GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract erlang-ghsa vuls-data-raw-erlang-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := erlangGHSA.Extract(args[0], erlangGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract erlang ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "erlang", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdErlangOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "erlang", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "erlang-osv <Raw Erlang OSV Repository PATH>",
		Short: "Extract Erlang OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract erlang-osv vuls-data-raw-erlang-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := erlangOSV.Extract(args[0], erlangOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract erlang osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "erlang", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdExploitExploitDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "exploit", "exploitdb"),
	}

	cmd := &cobra.Command{
		Use:   "exploit-exploitdb <Raw Exploit ExploitDB Repository PATH>",
		Short: "Extract Exploit ExploitDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract exploit-exploitdb vuls-data-raw-exploit-exploitdb
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exploitExploitDB.Extract(args[0], exploitExploitDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract exploit exploitdb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "exploit", "exploitdb"), "output extract results to specified directory")

	return cmd
}

func newCmdExploitGitHub() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "exploit", "github"),
	}

	cmd := &cobra.Command{
		Use:   "exploit-github <Raw Exploit GitHub Repository PATH>",
		Short: "Extract Exploit GitHub data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract exploit-github vuls-data-raw-exploit-github
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exploitGitHub.Extract(args[0], exploitGitHub.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract exploit github")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "exploit", "github"), "output extract results to specified directory")

	return cmd
}

func newCmdExploitInTheWild() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "exploit", "inthewild"),
	}

	cmd := &cobra.Command{
		Use:   "exploit-inthewild <Raw Exploit InTheWild Repository PATH>",
		Short: "Extract Exploit InTheWild data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract exploit-inthewild vuls-data-raw-exploit-inthewild
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exploitInTheWild.Extract(args[0], exploitInTheWild.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract exploit inthewild")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "exploit", "inthewild"), "output extract results to specified directory")

	return cmd
}

func newCmdExploitTrickest() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "exploit", "trickest"),
	}

	cmd := &cobra.Command{
		Use:   "exploit-trickest <Raw Exploit Trickest Repository PATH>",
		Short: "Extract Exploit Trickest data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract exploit-trickest vuls-data-raw-exploit-trickest
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := exploitTrickest.Extract(args[0], exploitTrickest.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract exploit trickest")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "exploit", "trickest"), "output extract results to specified directory")

	return cmd
}

func newCmdFedoraAPI() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "fedora", "api"),
	}

	cmd := &cobra.Command{
		Use:   "fedora-api <Raw Fedora Repository PATH>",
		Short: "Extract Fedora API data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract fedora-api vuls-data-raw-fedora-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fedoraAPI.Extract(args[0], fedoraAPI.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract fedora api")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdFortinetHandmade() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "fortinet", "handmade"),
	}

	cmd := &cobra.Command{
		Use:   "fortinet-handmade <Raw Fortinet Handmade Repository PATH>",
		Short: "Extract Fortinet Handmade data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract fortinet-handmade vuls-data-raw-fortinet-handmade
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fortinetHandmade.Extract(args[0], fortinetHandmade.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract fortinet handmade")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "fortinet", "handmade"), "output extract results to specified directory")

	return cmd
}

func newCmdFortinetCVRF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "fortinet", "cvrf"),
	}

	cmd := &cobra.Command{
		Use:   "fortinet-cvrf <Raw Fortinet CVRF Repository PATH>",
		Short: "Extract Fortinet CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract fortinet-cvrf vuls-data-raw-fortinet-cvrf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := fortinetCVRF.Extract(args[0], fortinetCVRF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract fortinet cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "fortinet", "cvrf"), "output extract results to specified directory")

	return cmd
}

func newCmdFreeBSD() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "freebsd"),
	}

	cmd := &cobra.Command{
		Use:   "freebsd <Raw FreeBSD Repository PATH>",
		Short: "Extract FreeBSD data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract freebsd vuls-data-raw-freebsd
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := freebsd.Extract(args[0], freebsd.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract freebsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "freebsd"), "output extract results to specified directory")

	return cmd
}

func newCmdGentoo() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "gentoo"),
	}

	cmd := &cobra.Command{
		Use:   "gentoo <Raw Gentoo Linux Repository PATH>",
		Short: "Extract Gentoo Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract gentoo vuls-data-raw-gentoo
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := gentoo.Extract(args[0], gentoo.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract gentoo")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "gentoo"), "output extract results to specified directory")

	return cmd
}

func newCmdGHActionsOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "ghactions", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "ghactions-osv <Raw GitHub Actions OSV Repository PATH>",
		Short: "Extract GitHub Actions OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract ghactions-osv vuls-data-raw-ghactions-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ghactionsOSV.Extract(args[0], ghactionsOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract ghactions osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "ghactions", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdGitOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "git", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "git-osv <Raw Git OSV Repository PATH>",
		Short: "Extract Git OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract git-osv vuls-data-raw-git-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := gitOSV.Extract(args[0], gitOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract git osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "git", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdGolangGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "golang", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "golang-ghsa <Raw Golang GHSA Repository PATH>",
		Short: "Extract Golang GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract golang-ghsa vuls-data-raw-golang-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := golangGHSA.Extract(args[0], golangGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract golang ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "golang", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdGolangGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "golang", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "golang-glsa <Raw Golang GLSA Repository PATH>",
		Short: "Extract Golang GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract golang-glsa vuls-data-raw-golang-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := golangGLSA.Extract(args[0], golangGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract golang glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "golang", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdGolangOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "golang", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "golang-osv <Raw Golang OSV Repository PATH>",
		Short: "Extract Golang OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract golang-osv vuls-data-raw-golang-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := golangOSV.Extract(args[0], golangOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract golang osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "golang", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdGolangDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "golang", "db"),
	}

	cmd := &cobra.Command{
		Use:   "golang-db <Raw Golang DB Repository PATH>",
		Short: "Extract Golang DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract golang-db vuls-data-raw-golang-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := golangDB.Extract(args[0], golangDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract golang db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "golang", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdGolangVulnDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "golang", "vulndb"),
	}

	cmd := &cobra.Command{
		Use:   "golang-vulndb <Raw Golang VulnDB Repository PATH>",
		Short: "Extract Golang VulnDB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract golang-vulndb vuls-data-raw-golang-vulndb
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := golangVulnDB.Extract(args[0], golangVulnDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract golang vulndb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "golang", "vulndb"), "output extract results to specified directory")

	return cmd
}

func newCmdHaskellOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "haskell", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "haskell-osv <Raw Haskell OSV Repository PATH>",
		Short: "Extract Haskell OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract haskell-osv vuls-data-raw-haskell-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := haskellOSV.Extract(args[0], haskellOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract haskell osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "haskell", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdJVNFeedDetail() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "detail"),
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-detail <Raw JVN Feed Detail Repository PATH>",
		Short: "Extract JVN Feed Detail data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract jvn-feed-detail vuls-data-raw-jvn-feed-detail
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := jvnFeedDetail.Extract(args[0], jvnFeedDetail.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract jvn feed detail")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "detail"), "output extract results to specified directory")

	return cmd
}

func newCmdJVNFeedProduct() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "product"),
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-product <Raw JVN Feed Product Repository PATH>",
		Short: "Extract JVN Feed Product data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract jvn-feed-product vuls-data-raw-jvn-feed-product
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := jvnFeedProduct.Extract(args[0], jvnFeedProduct.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract jvn feed product")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "product"), "output extract results to specified directory")

	return cmd
}

func newCmdJVNFeedRSS() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "rss"),
	}

	cmd := &cobra.Command{
		Use:   "jvn-feed-rss <Raw JVN Feed RSS Repository PATH>",
		Short: "Extract JVN Feed RSS data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract jvn-feed-rss vuls-data-raw-jvn-feed-rss
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := jvnFeedRSS.Extract(args[0], jvnFeedRSS.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract jvn feed rss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "jvn", "feed", "rss"), "output extract results to specified directory")

	return cmd
}

func newCmdLinuxOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "linux", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "linux-osv <Raw Linux OSV Repository PATH>",
		Short: "Extract Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract linux-osv vuls-data-raw-linux-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := linuxOSV.Extract(args[0], linuxOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract linux osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "linux", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdMavenGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "maven", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "maven-ghsa <Raw Maven GHSA Repository PATH>",
		Short: "Extract Maven GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract maven-ghsa vuls-data-raw-maven-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mavenGHSA.Extract(args[0], mavenGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract maven ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "maven", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdMavenGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "maven", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "maven-glsa <Raw Maven GLSA Repository PATH>",
		Short: "Extract Maven GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract maven-glsa vuls-data-raw-maven-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mavenGLSA.Extract(args[0], mavenGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract maven glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "maven", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdMavenOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "maven", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "maven-osv <Raw Maven OSV Repository PATH>",
		Short: "Extract Maven OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract maven-osv vuls-data-raw-maven-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mavenOSV.Extract(args[0], mavenOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract maven osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "maven", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdMitreCVRF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "cvrf"),
	}

	cmd := &cobra.Command{
		Use:   "mitre-cvrf <Raw Mitre CVRF Repository PATH>",
		Short: "Extract Mitre CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract mitre-cvrf vuls-data-raw-mitre-cvrf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mitreCVRF.Extract(args[0], mitreCVRF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract mitre cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "mitre", "cvrf"), "output extract results to specified directory")

	return cmd
}

func newCmdMitreV4() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "v4"),
	}

	cmd := &cobra.Command{
		Use:   "mitre-v4 <Raw Mitre V4 Repository PATH>",
		Short: "Extract Mitre V4 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract mitre-v4 vuls-data-raw-mitre-v4
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mitreV4.Extract(args[0], mitreV4.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract mitre v4")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "mitre", "v4"), "output extract results to specified directory")

	return cmd
}

func newCmdMitreV5() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "mitre", "v5"),
	}

	cmd := &cobra.Command{
		Use:   "mitre-v5 <Raw Mitre V5 Repository PATH>",
		Short: "Extract Mitre V5 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract mitre-v5 vuls-data-raw-mitre-v5
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := mitreV5.Extract(args[0], mitreV5.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract mitre v5")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "mitre", "v5"), "output extract results to specified directory")

	return cmd
}

func newCmdMSF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "msf"),
	}

	cmd := &cobra.Command{
		Use:   "msf <Raw MSF Repository PATH>",
		Short: "Extract MSF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract msf vuls-data-raw-msf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := msf.Extract(args[0], msf.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract msf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "msf"), "output extract results to specified directory")

	return cmd
}

func newCmdNetBSD() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "netbsd"),
	}

	cmd := &cobra.Command{
		Use:   "netbsd <Raw NetBSD Repository PATH>",
		Short: "Extract NetBSD data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract netbsd vuls-data-raw-netbsd
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := netbsd.Extract(args[0], netbsd.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract netbsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "netbsd"), "output extract results to specified directory")

	return cmd
}

func newCmdNpmGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "npm", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "npm-ghsa <Raw Npm GHSA Repository PATH>",
		Short: "Extract Npm GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract npm-ghsa vuls-data-raw-npm-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := npmGHSA.Extract(args[0], npmGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract npm ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "npm", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdNpmGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "npm", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "npm-glsa <Raw Npm GLSA Repository PATH>",
		Short: "Extract Npm GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract npm-glsa vuls-data-raw-npm-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := npmGLSA.Extract(args[0], npmGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract npm glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "npm", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdNpmOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "npm", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "npm-osv <Raw Npm OSV Repository PATH>",
		Short: "Extract Npm OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract npm-osv vuls-data-raw-npm-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := npmOSV.Extract(args[0], npmOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract npm osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "npm", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdNpmDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "npm", "db"),
	}

	cmd := &cobra.Command{
		Use:   "npm-db <Raw Npm DB Repository PATH>",
		Short: "Extract Npm DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract npm-db vuls-data-raw-npm-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := npmDB.Extract(args[0], npmDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract npm db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "npm", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdNugetGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nuget", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "nuget-ghsa <Raw Nuget GHSA Repository PATH>",
		Short: "Extract Nuget GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nuget-ghsa vuls-data-raw-nuget-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nugetGHSA.Extract(args[0], nugetGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nuget ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "nuget", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdNugetGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nuget", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "nuget-glsa <Raw Nuget GLSA Repository PATH>",
		Short: "Extract Nuget GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nuget-glsa vuls-data-raw-nuget-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nugetGLSA.Extract(args[0], nugetGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nuget glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "nuget", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdNugetOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nuget", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "nuget-osv <Raw Nuget OSV Repository PATH>",
		Short: "Extract Nuget OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nuget-osv vuls-data-raw-nuget-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nugetOSV.Extract(args[0], nugetOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nuget osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "nuget", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdNVDAPICVE() *cobra.Command {
	options := &struct {
		base
		concurrency int
	}{
		base: base{
			dir: filepath.Join(util.CacheDir(), "extract", "nvd", "api", "cve"),
		},
		concurrency: runtime.NumCPU(),
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cve <Raw NVD API CVE Repository PATH> <Raw NVD API CPEMATCH Repository PATH>",
		Short: "Extract NVD API CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-api-cve vuls-data-raw-nvd-api-cve vuls-data-raw-nvd-api-cpematch
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdAPICVE.Extract(args[0], args[1], nvdAPICVE.WithDir(options.dir), nvdAPICVE.WithConcurrency(options.concurrency)); err != nil {
				return errors.Wrap(err, "failed to extract nvd api cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "nvd", "api", "cve"), "output extract results to specified directory")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", runtime.NumCPU(), "number of concurrency process")

	return cmd
}

func newCmdNVDAPICPE() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "api", "cpe"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cpe <Raw NVD API CPE Repository PATH>",
		Short: "Extract NVD API CPE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-api-cpe vuls-data-raw-nvd-api-cpe
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdAPICPE.Extract(args[0], nvdAPICPE.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd api cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "nvd", "api", "cpe"), "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCVEv1() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cve", "v1"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cve-v1 <Raw NVD CVE Feed v1 Repository PATH>",
		Short: "Extract NVD CVE Feed v1 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cve-v1 vuls-data-raw-nvd-feed-cve-v1
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCVEv1.Extract(args[0], nvdFeedCVEv1.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cve feed v1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCPEv1() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cpe", "v1"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpe-v1 <Raw NVD CPE Feed v1 Repository PATH>",
		Short: "Extract NVD CPE Feed v1 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cpe-v1 vuls-data-raw-nvd-feed-cpe-v1
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCPEv1.Extract(args[0], nvdFeedCPEv1.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cpe feed v1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCPEMATCHv1() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cpematch", "v1"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpematch-v1 <Raw NVD CPEMatch Feed v1 Repository PATH>",
		Short: "Extract NVD CPEMatch Feed v1 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cpematch-v1 vuls-data-raw-nvd-feed-cpematch-v1
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCPEMATCHv1.Extract(args[0], nvdFeedCPEMATCHv1.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cpematch feed v1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCVEv2() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cve", "v2"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cve-v2 <Raw NVD CVE Feed v2 Repository PATH>",
		Short: "Extract NVD CVE Feed v2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cve-v2 vuls-data-raw-nvd-feed-cve-v2
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCVEv2.Extract(args[0], nvdFeedCVEv2.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cve feed v2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCPEv2() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cpe", "v2"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpe-v2 <Raw NVD CPE Feed v2 Repository PATH>",
		Short: "Extract NVD CPE Feed v2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cpe-v2 vuls-data-raw-nvd-feed-cpe-v2
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCPEv2.Extract(args[0], nvdFeedCPEv2.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cpe feed v2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdNVDFeedCPEMATCHv2() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "nvd", "feed", "cpematch", "v2"),
	}

	cmd := &cobra.Command{
		Use:   "nvd-feed-cpematch-v2 <Raw NVD CPEMatch Feed v2 Repository PATH>",
		Short: "Extract NVD CPEMatch Feed v2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract nvd-feed-cpematch-v2 vuls-data-raw-nvd-feed-cpematch-v2
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := nvdFeedCPEMATCHv2.Extract(args[0], nvdFeedCPEMATCHv2.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract nvd cpematch feed v2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdOracleLinux() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "oracle", "linux"),
	}

	cmd := &cobra.Command{
		Use:   "oracle-linux <Raw Oracle Linux Repository PATH>",
		Short: "Extract Oracle Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract oracle-linux vuls-data-raw-oracle
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := oracleLinux.Extract(args[0], oracleLinux.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract oracle linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdOSSFuzzOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "oss-fuzz", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "oss-fuzz-osv <Raw OSS-Fuzz OSV Repository PATH>",
		Short: "Extract OSS-Fuzz OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract oss-fuzz-osv vuls-data-raw-oss-fuzz-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ossFuzzOSV.Extract(args[0], ossFuzzOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract oss-fuzz osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "oss-fuzz", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdPerlDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "perl", "db"),
	}

	cmd := &cobra.Command{
		Use:   "perl-db <Raw Perl DB Repository PATH>",
		Short: "Extract Perl DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract perl-db vuls-data-raw-perl-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := perlDB.Extract(args[0], perlDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract perl db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "perl", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdPipGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pip", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "pip-ghsa <Raw Pip GHSA Repository PATH>",
		Short: "Extract Pip GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pip-ghsa vuls-data-raw-pip-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pipGHSA.Extract(args[0], pipGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pip ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pip", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdPipGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pip", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "pip-glsa <Raw Pip GLSA Repository PATH>",
		Short: "Extract Pip GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pip-glsa vuls-data-raw-pip-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pipGLSA.Extract(args[0], pipGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pip glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pip", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdPipOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pip", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "pip-osv <Raw Pip OSV Repository PATH>",
		Short: "Extract Pip OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pip-osv vuls-data-raw-pip-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pipOSV.Extract(args[0], pipOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pip osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pip", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdPipDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pip", "db"),
	}

	cmd := &cobra.Command{
		Use:   "pip-db <Raw Pip DB Repository PATH>",
		Short: "Extract Pip DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pip-db vuls-data-raw-pip-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pipDB.Extract(args[0], pipDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pip db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pip", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdPubGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pub", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "pub-ghsa <Raw Pub GHSA Repository PATH>",
		Short: "Extract Pub GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pub-ghsa vuls-data-raw-pub-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pubGHSA.Extract(args[0], pubGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pub ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pub", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdPubOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "pub", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "pub-osv <Raw Pub OSV Repository PATH>",
		Short: "Extract Pub OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract pub-osv vuls-data-raw-pub-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := pubOSV.Extract(args[0], pubOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract pub osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "pub", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdROSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "r", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "r-osv <Raw R OSV Repository PATH>",
		Short: "Extract R OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract r-osv vuls-data-raw-r-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rOSV.Extract(args[0], rOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract r osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "r", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatOVALv1() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "oval", "v1"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-ovalv1 <Raw RedHat OVALv1 Repository PATH> <Raw RedHat Repositoy to CPE Repository PATH>",
		Short: "Extract RedHat OVALv1 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-ovalv1 vuls-data-raw-redhat-ovalv1 vuls-data-raw-redhat-repository-to-cpe
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatOVALv1.Extract(args[0], args[1], redhatOVALv1.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat ovalv1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "oval", "v1"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatOVALv2() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "oval", "v2"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-ovalv2 <Raw RedHat OVALv2 Repository PATH> <Raw RedHat Repositoy to CPE Repository PATH>",
		Short: "Extract RedHat OVALv2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-ovalv2 vuls-data-raw-redhat-ovalv2 vuls-data-raw-redhat-repository-to-cpe
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatOVALv2.Extract(args[0], args[1], redhatOVALv2.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat ovalv2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "oval", "v2"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatCVE() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "cve"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-cve <Raw RedHat CVE Repository PATH>",
		Short: "Extract RedHat CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-cve vuls-data-raw-redhat-cve
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatCVE.Extract(args[0], redhatCVE.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "cve"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatCVRF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "cvrf"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-cvrf <Raw RedHat CVRF Repository PATH>",
		Short: "Extract RedHat CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-cvrf vuls-data-raw-redhat-cvrf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatCVRF.Extract(args[0], redhatCVRF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "cvrf"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatCSAF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "csaf"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-csaf <Raw RedHat CSAF Repository PATH> <Raw RedHat Repositoy to CPE Repository PATH>",
		Short: "Extract RedHat CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-csaf vuls-data-raw-redhat-csaf vuls-data-raw-redhat-repository-to-cpe
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatCSAF.Extract(args[0], args[1], redhatCSAF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "csaf"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatVEX() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "vex"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-vex <Raw RedHat VEX Repository PATH> <Raw RedHat Repositoy to CPE Repository PATH>",
		Short: "Extract RedHat VEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-vex vuls-data-raw-redhat-vex vuls-data-raw-redhat-repository-to-cpe
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatVEX.Extract(args[0], args[1], redhatVEX.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "vex"), "output extract results to specified directory")

	return cmd
}

func newCmdRedHatOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "redhat", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "redhat-osv <Raw RedHat OSV Repository PATH>",
		Short: "Extract RedHat OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract redhat-osv vuls-data-raw-redhat-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := redhatOSV.Extract(args[0], redhatOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract redhat osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "redhat", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdRockyErrata() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rocky", "errata"),
	}

	cmd := &cobra.Command{
		Use:   "rocky-errata <Raw Rocky Linux Errata Repository PATH>",
		Short: "Extract Rocky Linux Errata data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rocky-errata vuls-data-raw-rocky-errata
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rockyErrata.Extract(args[0], rockyErrata.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rocky errata")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rocky", "errata"), "output extract results to specified directory")

	return cmd
}

func newCmdRockyOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rocky", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "rocky-osv <Raw Rocky Linux OSV Repository PATH>",
		Short: "Extract Rocky Linux OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rocky-osv vuls-data-raw-rocky-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rockyOSV.Extract(args[0], rockyOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rocky osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rocky", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdRubygemsGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rubygems", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "rubygems-ghsa <Raw Rubygems GHSA Repository PATH>",
		Short: "Extract Rubygems GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rubygems-ghsa vuls-data-raw-rubygems-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rubygemsGHSA.Extract(args[0], rubygemsGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rubygems ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rubygems", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdRubygemsGLSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rubygems", "glsa"),
	}

	cmd := &cobra.Command{
		Use:   "rubygems-glsa <Raw Rubygems GLSA Repository PATH>",
		Short: "Extract Rubygems GLSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rubygems-glsa vuls-data-raw-rubygems-glsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rubygemsGLSA.Extract(args[0], rubygemsGLSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rubygems glsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rubygems", "glsa"), "output extract results to specified directory")

	return cmd
}

func newCmdRubygemsOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rubygems", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "rubygems-osv <Raw Rubygems OSV Repository PATH>",
		Short: "Extract Rubygems OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rubygems-osv vuls-data-raw-rubygems-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rubygemsOSV.Extract(args[0], rubygemsOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rubygems osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rubygems", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdRubygemsDB() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "rubygems", "db"),
	}

	cmd := &cobra.Command{
		Use:   "rubygems-db <Raw Rubygems DB Repository PATH>",
		Short: "Extract Rubygems DB data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract rubygems-db vuls-data-raw-rubygems-db
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := rubygemsDB.Extract(args[0], rubygemsDB.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract rubygems db")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "rubygems", "db"), "output extract results to specified directory")

	return cmd
}

func newCmdSnort() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "snort"),
	}

	cmd := &cobra.Command{
		Use:   "snort <Raw Snort Repository PATH>",
		Short: "Extract Snort data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract snort vuls-data-raw-snort
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := snort.Extract(args[0], snort.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract snort")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "snort"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSEOVAL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "oval"),
	}

	cmd := &cobra.Command{
		Use:   "suse-oval <Raw SUSE OVAL Repository PATH>",
		Short: "Extract SUSE OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-oval vuls-data-raw-suse-oval
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseOVAL.Extract(args[0], suseOVAL.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "oval"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSECVRF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "cvrf"),
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf <Raw SUSE CVRF Repository PATH>",
		Short: "Extract SUSE CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-cvrf vuls-data-raw-suse-cvrf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCVRF.Extract(args[0], suseCVRF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "cvrf"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSECVRFCVE() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "cvrf-cve"),
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf-cve <Raw SUSE CVRF CVE Repository PATH>",
		Short: "Extract SUSE CVRF CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-cvrf-cve vuls-data-raw-suse-cvrf-cve
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCVRFCVE.Extract(args[0], suseCVRFCVE.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse cvrf-cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "cvrf-cve"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSECSAF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "csaf"),
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf <Raw SUSE CSAF Repository PATH>",
		Short: "Extract SUSE CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-csaf vuls-data-raw-suse-csaf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCSAF.Extract(args[0], suseCSAF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "csaf"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSECSAFVEX() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "csaf-vex"),
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf-vex <Raw SUSE CSAF VEX Repository PATH>",
		Short: "Extract SUSE CSAF VEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-csaf-vex vuls-data-raw-suse-csaf-vex
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCSAFVEX.Extract(args[0], suseCSAFVEX.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse csaf-vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "csaf-vex"), "output extract results to specified directory")

	return cmd
}

func newCmdSUSEOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "suse", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "suse-osv <Raw SUSE OSV Repository PATH>",
		Short: "Extract SUSE OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract suse-osv vuls-data-raw-suse-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseOSV.Extract(args[0], suseOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract suse osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "suse", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdSwiftGHSA() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "swift", "ghsa"),
	}

	cmd := &cobra.Command{
		Use:   "swift-ghsa <Raw Swift GHSA Repository PATH>",
		Short: "Extract Swift GHSA data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract swift-ghsa vuls-data-raw-swift-ghsa
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := swiftGHSA.Extract(args[0], swiftGHSA.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract swift ghsa")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "swift", "ghsa"), "output extract results to specified directory")

	return cmd
}

func newCmdSwiftOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "swift", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "swift-osv <Raw Swift OSV Repository PATH>",
		Short: "Extract Swift OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract swift-osv vuls-data-raw-swift-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := swiftOSV.Extract(args[0], swiftOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract swift osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "swift", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdUbuntuOVAL() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "ubuntu", "oval"),
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-oval <Raw Ubuntu OVAL Repository PATH>",
		Short: "Extract Ubuntu OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract ubuntu-oval vuls-data-raw-ubuntu-oval
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ubuntuOVAL.Extract(args[0], ubuntuOVAL.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract ubuntu oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "ubuntu", "oval"), "output extract results to specified directory")

	return cmd
}

func newCmdUbuntuCVETracker() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "ubuntu", "ubuntu-cve-tracker"),
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-cve-tracker <Raw Ubuntu CVE Tracker Repository PATH>",
		Short: "Extract Ubuntu CVE Tracker data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract ubuntu-cve-tracker vuls-data-raw-ubuntu-cve-tracker
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ubuntuCVETracker.Extract(args[0], ubuntuCVETracker.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract ubuntu cve tracker")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "output extract results to specified directory")

	return cmd
}

func newCmdUbuntuOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "ubuntu", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "ubuntu-osv <Raw Ubuntu OSV Repository PATH>",
		Short: "Extract Ubuntu OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract ubuntu-osv vuls-data-raw-ubuntu-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := ubuntuOSV.Extract(args[0], ubuntuOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract ubuntu osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "ubuntu", "osv"), "output extract results to specified directory")

	return cmd
}

func newCmdVulnCheckKEV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "vulncheck", "kev"),
	}

	cmd := &cobra.Command{
		Use:   "vulncheck-kev <Raw VulnCheck KEV Repository PATH>",
		Short: "Extract VulnCheck KEV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract vulncheck-kev vuls-data-raw-vulncheck-kev
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := vulncheckKEV.Extract(args[0], vulncheckKEV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract vulncheck kev")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "vulncheck", "kev"), "output extract results to specified directory")

	return cmd
}

func newCmdWindowsBulletin() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "windows", "bulletin"),
	}

	cmd := &cobra.Command{
		Use:   "windows-bulletin <Raw Windows Bulletin Repository PATH>",
		Short: "Extract Windows Bulletin data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract windows-bulletin vuls-data-raw-windows-bulletin
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsBulletin.Extract(args[0], windowsBulletin.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract windows bulletin")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "windows", "bulletin"), "output extract results to specified directory")

	return cmd
}

func newCmdWindowsCVRF() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "windows", "cvrf"),
	}

	cmd := &cobra.Command{
		Use:   "windows-cvrf <Raw Windows CVRF Repository PATH>",
		Short: "Extract Windows CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract windows-cvrf vuls-data-raw-windows-cvrf
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsCVRF.Extract(args[0], windowsCVRF.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract windows cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "windows", "cvrf"), "output extract results to specified directory")

	return cmd
}

func newCmdWindowsMSUC() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "windows", "msuc"),
	}

	cmd := &cobra.Command{
		Use:   "windows-msuc <Raw Windows MSUC Repository PATH>",
		Short: "Extract Windows MSUC data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract windows-msuc vuls-data-raw-windows-msuc
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsMSUC.Extract(args[0], windowsMSUC.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract windows msuc")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "windows", "msuc"), "output extract results to specified directory")

	return cmd
}

func newCmdWindowsWSUSSCN2() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "windows", "wsusscn2"),
	}

	cmd := &cobra.Command{
		Use:   "windows-wsusscn2 <Raw Windows WSUSSCN2 Repository PATH>",
		Short: "Extract Windows WSUSSCN2 data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract windows-wsusscn2 vuls-data-raw-windows-wsusscn2
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsWSUSSCN2.Extract(args[0], windowsWSUSSCN2.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract windows wsusscn2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "windows", "wsusscn2"), "output extract results to specified directory")

	return cmd
}

func newCmdWolfiOSV() *cobra.Command {
	options := &base{
		dir: filepath.Join(util.CacheDir(), "extract", "wolfi", "osv"),
	}

	cmd := &cobra.Command{
		Use:   "wolfi-osv <Raw Wolfi OSV Repository PATH>",
		Short: "Extract Wolfi OSV data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract wolfi-osv vuls-data-raw-wolfi-osv
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := wolfiOSV.Extract(args[0], wolfiOSV.WithDir(options.dir)); err != nil {
				return errors.Wrap(err, "failed to extract wolfi osv")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "wolfi", "osv"), "output extract results to specified directory")

	return cmd
}
