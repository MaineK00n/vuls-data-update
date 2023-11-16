package fetch

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	almaErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
	alpineSecDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/arch"
	debianOval "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/oval"
	debianSecurityTrackerAPI "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/api"
	debianSecurityTrackerSalsa "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/tracker/salsa"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/gentoo"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/netbsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle"
	redhatOvalRepositoryToCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/repository2cpe"
	redhatOvalV1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v1"
	redhatOvalV2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v2"
	rockyErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/errata"
	suseCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf"
	suseCSAFVEX "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf_vex"
	suseCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf"
	suseCVRFCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf_cve"
	suseOval "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/oval"
	ubuntuOval "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/oval"
	ubuntuCveTracker "github.com/MaineK00n/vuls-data-update/pkg/fetch/ubuntu/tracker"
	windowsBulletin "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/bulletin"
	windowsCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/cvrf"
	windowsMSUC "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/msuc"
	windowsWSUSSCN2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/windows/wsusscn2"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/attack"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/capec"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/cwe"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/epss"
	exploitExploitDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/exploitdb"
	exploitGitHub "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/github"
	exploitInTheWild "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/inthewild"
	exploitTrickest "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/trickest"
	jvnFeedDetail "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/detail"
	jvnFeedProduct "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/product"
	jvnFeedRSS "github.com/MaineK00n/vuls-data-update/pkg/fetch/jvn/feed/rss"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/kev"
	mitreCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/cvrf"
	mitreV4 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v4"
	mitreV5 "github.com/MaineK00n/vuls-data-update/pkg/fetch/mitre/v5"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/msf"

	nvdAPICVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/api/cve"
	nvdFeedCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpe"
	nvdFeedCPEMatch "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch"
	nvdFeedCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/snort"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	dir   string
	retry int

	concurrency int // SUSE CVRF/CVRF CVE/CSAF/CSAF VEX, NVD API CVE/CPE/CPEMatch, Windows WSUSSCN2
	wait        int // SUSE CVRF/CVRF CVE/CSAF/CSAF VEX, NVD API CVE/CPE/CPEMatch

	apiKey string // NVD API CVE/CPE/CPEMatch
}

func NewCmdFetch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <data source>",
		Short: "Fetch data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker
			$ vuls-data-update fetch cargo-db
			$ vuls-data-update fetch nvd-feed-cve
		`),
	}

	cmd.AddCommand(
		newCmdFetchAlmaErrata(), newCmdFetchAlmaOSV(),
		newCmdFetchAlpineSecDB(), newCmdFetchAlpineOSV(),
		newCmdFetchAmazon(),
		newCmdFetchArch(),
		newCmdFetchDebianOval(), newCmdFetchDebianSecurityTrackerAPI(), newCmdFetchDebianSecurityTrackerSalsa(), newCmdFetchDebianOSV(),
		newCmdFetchEPEL(),
		newCmdFetchFedora(),
		newCmdFetchFreeBSD(),
		newCmdFetchGentoo(),
		newCmdFetchNetBSD(),
		newCmdFetchOracle(),
		newCmdFetchRedhatOvalRepositoryToCPE(), newCmdFetchRedhatOvalV1(), newCmdFetchRedhatOvalV2(), newCmdFetchRedhatSecurityAPI(), newCmdFetchRedhatCSAF(),
		newCmdFetchRockyErrata(), newCmdFetchRockyOSV(),
		newCmdFetchSUSEOval(), newCmdFetchSUSECVRF(), newCmdFetchSUSECVRFCVE(), newCmdFetchSUSECSAF(), newCmdFetchSUSECSAFVEX(),
		newCmdFetchUbuntuOVAL(), newCmdFetchUbuntuCVETracker(),
		newCmdFetchWindowsBulletin(), newCmdFetchWindowsCVRF(), newCmdFetchWindowsMSUC(), newCmdFetchWindowsWSUSSCN2(),

		newCmdFetchCargoDB(), newCmdFetchCargoGHSA(), newCmdFetchCargoOSV(),
		newCmdFetchComposerDB(), newCmdFetchComposerGHSA(), newCmdFetchComposerGLSA(),
		newCmdFetchConanGLSA(),
		newCmdFetchDartGHSA(), newCmdFetchDartOSV(),
		newCmdFetchErlangGHSA(), newCmdFetchErlangOSV(),
		newCmdFetchGolangDB(), newCmdFetchGolangGHSA(), newCmdFetchGolangGLSA(), newCmdFetchGolangVulnDB(), newCmdFetchGolangOSV(),
		newCmdFetchMavenGHSA(), newCmdFetchMavenGLSA(),
		newCmdFetchNpmDB(), newCmdFetchNpmGHSA(), newCmdFetchNpmGLSA(), newCmdFetchNpmOSV(),
		newCmdFetchNugetGHSA(), newCmdFetchNugetGLSA(), newCmdFetchNugetOSV(),
		newCmdFetchPipDB(), newCmdFetchPipGHSA(), newCmdFetchPipGLSA(), newCmdFetchPipOSV(),
		newCmdFetchRubygemsDB(), newCmdFetchRubygemsGHSA(), newCmdFetchRubygemsGLSA(), newCmdFetchRubygemsOSV(),

		newCmdFetchAttack(),
		newCmdFetchCapec(),
		newCmdFetchCWE(),
		newCmdFetchEPSS(),
		newCmdFetchExploitExploitDB(), newCmdFetchExploitGitHub(), newCmdFetchExploitInthewild(), newCmdFetchExploitExploitTrickest(),
		newCmdFetchJVNFeedDetail(), newCmdFetchJVNFeedProduct(), newCmdFetchJVNFeedRSS(),
		newCmdFetchKEV(),
		newCmdFetchMitreCVRF(), newCmdFetchMitreV4(), newCmdFetchMitreV5(),
		newCmdFetchMSF(),
		newCmdFetchNVDAPICVE(), newCmdFetchNVDFeedCVE(), newCmdFetchNVDFeedCPE(), newCmdFetchNVDFeedCPEMatch(),
		newCmdFetchSnort(),
	)

	return cmd
}

func newCmdFetchAlmaErrata() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "alma", "errata"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "alma", "errata"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlmaOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "alma", "osv"),
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
			// if err := almaOSV.Fetch(almaOSV.WithDir(options.dir), almaOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch almalinux")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "alma", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlpineSecDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "alpine", "secdb"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "alpine", "secdb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlpineOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "alpine", "osv"),
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
			// if err := alpineOSV.Fetch(alpineOSV.WithDir(options.dir), alpineOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch alpine linux")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "alpine", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAmazon() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "amazon"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "amazon"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchArch() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "arch"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "arch"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianOval() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "debian", "oval"),
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
			if err := debianOval.Fetch(debianOval.WithDir(options.dir), debianOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "debian", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianSecurityTrackerAPI() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "debian", "security-tracker", "api"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "debian", "security-tracker", "api"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianSecurityTrackerSalsa() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "debian", "security-tracker", "salsa"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "debian", "security-tracker", "salsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "debian", "osv"),
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
			// if err := debianOSV.Fetch(debianOSV.WithDir(options.dir), debianOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch debian osv")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "debian", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchEPEL() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "epel"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "epel",
		Short: "Fetch EPEL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch epel
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := epel.Fetch(epel.WithDir(options.dir), epel.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch epel")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "epel"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchFedora() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "fedora"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "fedora",
		Short: "Fetch Fedora data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch fedora
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := fedora.Fetch(fedora.WithDir(options.dir), fedora.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch fedora")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "fedora"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchFreeBSD() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "freebsd"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "freebsd"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGentoo() *cobra.Command {
	options := &options{
		dir: filepath.Join(util.CacheDir(), "gentoo"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "gentoo"), "output fetch results to specified directory")

	return cmd
}

func newCmdFetchNetBSD() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "netbsd"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "netbsd"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchOracle() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "oracle"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "oracle"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalRepositoryToCPE() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "redhat", "oval", "repository-to-cpe"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-oval-repository-to-cpe",
		Short: "Fetch RedHat Enterprise Linux Repository-to-CPE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-oval-repository-to-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatOvalRepositoryToCPE.Fetch(redhatOvalRepositoryToCPE.WithDir(options.dir), redhatOvalRepositoryToCPE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat oval repository-to-cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "redhat", "oval", "repository-to-cpe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalV1() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "redhat", "oval", "v1"),
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
			if err := redhatOvalV1.Fetch(redhatOvalV1.WithDir(options.dir), redhatOvalV1.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "redhat", "oval", "v1"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalV2() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "redhat", "oval", "v2"),
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
			if err := redhatOvalV2.Fetch(redhatOvalV2.WithDir(options.dir), redhatOvalV2.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "redhat", "oval", "v2"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatSecurityAPI() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "redhat", "api"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-security-api",
		Short: "Fetch RedHat Security API data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-security-api
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// if err := redhatSecurityAPI.Fetch(redhatSecurityAPI.WithDir(options.dir), redhatSecurityAPI.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch redhat security api")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "redhat", "api"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatCSAF() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "redhat", "csaf"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-csaf",
		Short: "Fetch RedHat CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// if err := redhatCSAF.Fetch(redhatCSAF.WithDir(options.dir), redhatCSAF.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch redhat csaf")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "redhat", "csaf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRockyErrata() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rocky", "errata"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rocky", "errata"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRockyOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rocky", "osv"),
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
			// if err := rockyOSV.Fetch(rockyOSV.WithDir(options.dir), rockyOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch rocky")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rocky", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchSUSEOval() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "suse", "oval"),
		retry:       3,
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
			if err := suseOval.Fetch(suseOval.WithDir(options.dir), suseOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "suse", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 3, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchSUSECVRF() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "suse", "cvrf"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf",
		Short: "Fetch SUSE CVRF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-cvrf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCVRF.Fetch(suseCVRF.WithDir(options.dir), suseCVRF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "suse", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchSUSECVRFCVE() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "suse", "cvrf-cve"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "suse-cvrf-cve",
		Short: "Fetch SUSE CVRF CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-cvrf-cve
		`),
		ValidArgs: func() []string {
			var ys []string
			for y := 1999; y <= time.Now().Year(); y++ {
				ys = append(ys, fmt.Sprintf("%d", y))
			}
			return ys
		}(),
		Args: cobra.MatchAll(cobra.MinimumNArgs(1), cobra.OnlyValidArgs),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCVRFCVE.Fetch(args, suseCVRFCVE.WithDir(options.dir), suseCVRFCVE.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse cvrf cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "suse", "cvrf-cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchSUSECSAF() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "suse", "csaf"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf",
		Short: "Fetch SUSE CSAF data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-csaf
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseCSAF.Fetch(suseCSAF.WithDir(options.dir), suseCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "suse", "csaf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchSUSECSAFVEX() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "suse", "csaf-vex"),
		retry:       3,
		concurrency: 20,
		wait:        1,
	}

	cmd := &cobra.Command{
		Use:   "suse-csaf-vex",
		Short: "Fetch SUSE CSAF VEX data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-csaf-vex
		`),
		ValidArgs: func() []string {
			var ys []string
			for y := 1999; y <= time.Now().Year(); y++ {
				ys = append(ys, fmt.Sprintf("%d", y))
			}
			return ys
		}(),
		Args: cobra.MatchAll(cobra.MinimumNArgs(1), cobra.OnlyValidArgs),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := suseCSAFVEX.Fetch(args, suseCSAFVEX.WithDir(options.dir), suseCSAFVEX.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse csaf vex")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "suse", "csaf-vex"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchUbuntuOVAL() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "ubuntu", "oval"),
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
			if err := ubuntuOval.Fetch(ubuntuOval.WithDir(options.dir), ubuntuOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "ubuntu", "oval"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchUbuntuCVETracker() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "ubuntu", "ubuntu-cve-tracker"),
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
			if err := ubuntuCveTracker.Fetch(ubuntuCveTracker.WithDir(options.dir), ubuntuCveTracker.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu cve tracker")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "ubuntu", "ubuntu-cve-tracker"), "output fetch results to specified directory")

	return cmd
}

func newCmdFetchWindowsBulletin() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "windows", "bulletin"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "windows", "bulletin"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsCVRF() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "windows", "cvrf"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "windows", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsMSUC() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "windows", "msuc"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "windows-msuc [KBID]",
		Short: "Fetch Windows Microsoft Software Update Catalog data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch windows-msuc "KB5019311", "KB5017389", "KB5018427", "KB5019509", "KB5018496", "KB5019980", "KB5020044", "KB5021255", "KB5022303", "KB5022360", "KB5022845"
		`),
		Args: cobra.MinimumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := windowsMSUC.Fetch(args, windowsMSUC.WithDir(options.dir), windowsMSUC.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows msuc")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "windows", "msuc"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsWSUSSCN2() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "windows", "wsusscn2"),
		retry:       3,
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "windows", "wsusscn2"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 2, "number of concurrency cabextract")

	return cmd
}

func newCmdFetchCargoDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "cargo", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "cargo", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchCargoGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "cargo", "ghsa"),
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
			// 	if err := cargoGHSA.Fetch(cargoGHSA.WithDir(options.dir), cargoGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "cargo", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchCargoOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "cargo", "osv"),
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
			// 	if err := cargoOSV.Fetch(cargoOSV.WithDir(options.dir), cargoOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "cargo", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "composer", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "composer", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "composer", "ghsa"),
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
			// 	if err := composerGHSA.Fetch(composerGHSA.WithDir(options.dir), composerGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "composer", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "composer", "glsa"),
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
			// 	if err := composerGLSA.Fetch(composerGLSA.WithDir(options.dir), composerGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "composer", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchConanGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "conan", "glsa"),
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
			// 	if err := conanGLSA.Fetch(conanGLSA.WithDir(options.dir), conanGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch conan glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "conan", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDartGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "dart", "ghsa"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "dart-ghsa",
		Short: "Fetch Dart GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch dart-ghsa
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := dartGHSA.Fetch(dartGHSA.WithDir(options.dir), dartGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch dart ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "dart", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDartOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "dart", "osv"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "dart-osv",
		Short: "Fetch Dart Open Source Vulnerabilities Database data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch dart-osv
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := dartOSV.Fetch(dartOSV.WithDir(options.dir), dartOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch dart osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "dart", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchErlangGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "erlang", "ghsa"),
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
			// 	if err := erlangGHSA.Fetch(erlangGHSA.WithDir(options.dir), erlangGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch erlang-ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "erlang", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchErlangOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "erlang", "osv"),
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
			// 	if err := erlangOSV.Fetch(erlangOSV.WithDir(options.dir), erlangOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch erlang osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "erlang", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "golang", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "golang", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "golang", "ghsa"),
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
			// 	if err := golangGHSA.Fetch(golangGHSA.WithDir(options.dir), golangGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "golang", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "golang", "glsa"),
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
			// 	if err := golangGLSA.Fetch(golangGLSA.WithDir(options.dir), golangGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "golang", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "golang", "osv"),
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
			// 	if err := golangOSV.Fetch(golangOSV.WithDir(options.dir), golangOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "golang", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangVulnDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "golang", "vulndb"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "golang", "vulndb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMavenGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "maven", "ghsa"),
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
			// 	if err := mavenGHSA.Fetch(mavenGHSA.WithDir(options.dir), mavenGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch maven ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "maven", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchMavenGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "maven", "glsa"),
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
			// 	if err := mavenGLSA.Fetch(mavenGLSA.WithDir(options.dir), mavenGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch maven glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "maven", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "npm", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "npm", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "npm", "ghsa"),
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
			// 	if err := npmGHSA.Fetch(npmGHSA.WithDir(options.dir), npmGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "npm", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "npm", "glsa"),
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
			// 	if err := npmGLSA.Fetch(npmGLSA.WithDir(options.dir),npmGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "npm", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "npm", "osv"),
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
			// 	if err := npmOSV.Fetch(npmOSV.WithDir(options.dir), npmOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "npm", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNugetGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nuget", "ghsa"),
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
			// 	if err := nugetGHSA.Fetch(nugetGHSA.WithDir(options.dir), nugetGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nuget", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNugetGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nuget", "glsa"),
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
			// 	if err := nugetGLSA.Fetch(nugetGLSA.WithDir(options.dir), nugetGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nuget", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNugetOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nuget", "osv"),
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
			// 	if err := nugetOSV.Fetch(nugetOSV.WithDir(options.dir), nugetOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nuget", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchPipDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "pip", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "pip", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "pip", "ghsa"),
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
			// 	if err := pipGHSA.Fetch(pipGHSA.WithDir(options.dir), pipGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "pip", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "pip", "glsa"),
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
			// 	if err := pipGLSA.Fetch(pipGLSA.WithDir(options.dir), pipGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "pip", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "pip", "osv"),
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
			// 	if err := pipOSV.Fetch(pipOSV.WithDir(options.dir), pipOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "pip", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRubygemsDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rubygems", "db"),
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
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rubygems", "db"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsGHSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rubygems", "ghsa"),
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
			// 	if err := rubygemsGHSA.Fetch(rubygemsGHSA.WithDir(options.dir), rubygemsGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rubygems", "ghsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsGLSA() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rubygems", "glsa"),
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
			// 	if err := rubygemsGLSA.Fetch(rubygemsGLSA.WithDir(options.dir), rubygemsGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rubygems", "glsa"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsOSV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "rubygems", "osv"),
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
			// 	if err := rubygemsOSV.Fetch(rubygemsOSV.WithDir(options.dir), rubygemsOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "rubygems", "osv"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchAttack() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "attack"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "attack"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchCapec() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "capec"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "capec"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchCWE() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "cwe"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "cwe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchEPSS() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "epss"),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "epss",
		Short: "Fetch EPSS data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch epss
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := epss.Fetch(epss.WithDir(options.dir), epss.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch epss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "epss"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitExploitDB() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "exploit", "exploitdb"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "exploit", "exploitdb"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitGitHub() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "exploit", "github"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "exploit", "github"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitInthewild() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "exploit", "inthewild"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "exploit", "inthewild"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitExploitTrickest() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "exploit", "trickest"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "exploit", "trickest"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedDetail() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "jvn", "feed", "detail"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "jvn", "feed", "detail"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedProduct() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "jvn", "feed", "product"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "jvn", "feed", "product"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedRSS() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "jvn", "feed", "rss"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "jvn", "feed", "rss"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchKEV() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "kev"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "kev"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreCVRF() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "mitre", "cvrf"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "mitre", "cvrf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreV4() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "mitre", "v4"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "mitre", "v4"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreV5() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "mitre", "v5"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "mitre", "v5"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMSF() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "msf"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "msf"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNVDAPICVE() *cobra.Command {
	options := &options{
		dir:         filepath.Join(util.CacheDir(), "nvd", "api", "cve"),
		retry:       3,
		concurrency: 1,
	}

	cmd := &cobra.Command{
		Use:   "nvd-api-cve",
		Short: "Fetch NVD API CVE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-api-cve
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := nvdAPICVE.Fetch(
				nvdAPICVE.WithDir(options.dir),
				nvdAPICVE.WithRetry(options.retry),
				nvdAPICVE.WithConcurrency(options.concurrency),
				nvdAPICVE.WithWait(options.wait),
				nvdAPICVE.WithAPIKey(options.apiKey),
			); err != nil {
				return errors.Wrap(err, "failed to fetch nvd api cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nvd", "api", "cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 1, "number of concurrent API requests")
	// Rate limet without API key: 5 requests in a rolling 30 second window, and
	// with API key: 50 requests in a rolling 30 second window.
	cmd.Flags().IntVarP(&options.wait, "wait", "", 6, "sleep duration in seconds between consecutive requests")
	cmd.Flags().StringVar(&options.apiKey, "api-key", "", "API Key to increase rate limit")

	return cmd
}

func newCmdFetchNVDFeedCVE() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nvd", "feed", "cve"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nvd", "feed", "cve"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNVDFeedCPE() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nvd", "feed", "cpe"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nvd", "feed", "cpe"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNVDFeedCPEMatch() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "nvd", "feed", "cpematch"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "nvd", "feed", "cpematch"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchSnort() *cobra.Command {
	options := &options{
		dir:   filepath.Join(util.CacheDir(), "snort"),
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

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "snort"), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
