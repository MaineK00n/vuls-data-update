package fetch

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	almaErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/alma/errata"
	alpineSecDB "github.com/MaineK00n/vuls-data-update/pkg/fetch/alpine/secdb"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/amazon"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/arch"
	debianOval "github.com/MaineK00n/vuls-data-update/pkg/fetch/debian/oval"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/gentoo"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/netbsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/oracle"
	redhatOvalRepositoryToCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/repository2cpe"
	redhatOvalV1 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v1"
	redhatOvalV2 "github.com/MaineK00n/vuls-data-update/pkg/fetch/redhat/oval/v2"
	rockyErrata "github.com/MaineK00n/vuls-data-update/pkg/fetch/rocky/errata"
	suseCSAF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/csaf"
	suseCVRF "github.com/MaineK00n/vuls-data-update/pkg/fetch/suse/cvrf"
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
	exploitGitHub "github.com/MaineK00n/vuls-data-update/pkg/fetch/exploit/githubrepos"
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
	nvdFeedCPE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpe"
	nvdFeedCPEMatch "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cpematch"
	nvdFeedCVE "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/util"
)

type options struct {
	dir   string
	retry int

	concurrency int // SUSE CVRF, SUSE CSAF, Windows WSUSSCN2
	wait        int // SUSE CVRF, SUSE CSAF
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
		newCmdFetchDebianOval(), newCmdFetchDebianSecurityTracker(), newCmdFetchDebianOSV(),
		newCmdFetchEPEL(),
		newCmdFetchFedora(),
		newCmdFetchFreeBSD(),
		newCmdFetchGentoo(),
		newCmdFetchNetBSD(),
		newCmdFetchOracle(),
		newCmdFetchRedhatOvalRepositoryToCPE(), newCmdFetchRedhatOvalV1(), newCmdFetchRedhatOvalV2(), newCmdFetchRedhatSecurityAPI(), newCmdFetchRedhatCVRF(),
		newCmdFetchRockyErrata(), newCmdFetchRockyOSV(),
		newCmdFetchSUSEOval(), newCmdFetchSUSECVRF(), newCmdFetchSUSECSAF(),
		newCmdFetchUbuntuOVAL(), newCmdFetchUbuntuCVETracker(),
		newCmdFetchWindowsBulletin(), newCmdFetchWindowsCVRF(), newCmdFetchWindowsMSUC(), newCmdFetchWindowsWSUSSCN2(),

		newCmdFetchCargoDB(), newCmdFetchCargoGHSA(), newCmdFetchCargoOSV(),
		newCmdFetchComposerDB(), newCmdFetchComposerGHSA(), newCmdFetchComposerGLSA(),
		newCmdFetchConan(),
		newCmdFetchDart(),
		newCmdFetchErlang(),
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
		newCmdFetchNVDAPI(), newCmdFetchNVDFeedCVE(), newCmdFetchNVDFeedCPE(), newCmdFetchNVDFeedCPEMatch(),
	)

	return cmd
}

func newCmdFetchAlmaErrata() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := almaErrata.Fetch(almaErrata.WithDir(filepath.Join(options.dir, "alma", "errata")), almaErrata.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch almalinux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlmaOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := almaOSV.Fetch(almaOSV.WithDir(filepath.Join(options.dir, "alma", "osv")), almaOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch almalinux")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlpineSecDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := alpineSecDB.Fetch(alpineSecDB.WithDir(filepath.Join(options.dir, "alpine", "secdb")), alpineSecDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch alpine linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAlpineOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := alpineOSV.Fetch(alpineOSV.WithDir(filepath.Join(options.dir, "alpine", "osv")), alpineOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch alpine linux")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchAmazon() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := amazon.Fetch(amazon.WithDir(filepath.Join(options.dir, "amazon")), amazon.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch amazon linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchArch() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := arch.Fetch(arch.WithDir(filepath.Join(options.dir, "arch")), arch.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch arch linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianOval() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := debianOval.Fetch(debianOval.WithDir(filepath.Join(options.dir, "debian", "oval")), debianOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch debian oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianSecurityTracker() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "debian-security-tracker",
		Short: "Fetch Debian Security Tracker data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch debian-security-tracker
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// if err := debianSecurityTracker.Fetch(debianSecurityTracker.WithDir(filepath.Join(options.dir, "debian", "security-tracker")), debianSecurityTracker.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch debian security tracker")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDebianOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := debianOSV.Fetch(debianOSV.WithDir(filepath.Join(options.dir, "debian", "osv")), debianOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch debian osv")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchEPEL() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := epel.Fetch(epel.WithDir(filepath.Join(options.dir, "epel")), epel.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch epel")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchFedora() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := fedora.Fetch(fedora.WithDir(filepath.Join(options.dir, "fedora")), fedora.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch fedora")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchFreeBSD() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := freebsd.Fetch(freebsd.WithDir(filepath.Join(options.dir, "freebsd")), freebsd.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch freebsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGentoo() *cobra.Command {
	options := &options{
		dir: util.CacheDir(),
	}

	cmd := &cobra.Command{
		Use:   "gentoo",
		Short: "Fetch Gentoo Linux data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch gentoo
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := gentoo.Fetch(gentoo.WithDir(filepath.Join(options.dir, "gentoo")), gentoo.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch gentoo")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")

	return cmd
}

func newCmdFetchNetBSD() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := netbsd.Fetch(netbsd.WithDir(filepath.Join(options.dir, "netbsd")), netbsd.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch netbsd")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchOracle() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := oracle.Fetch(oracle.WithDir(filepath.Join(options.dir, "oracle")), oracle.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch oracle linux")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalRepositoryToCPE() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "redhat-oval-repository-to-cpe",
		Short: "Fetch RedHat Enterprise Linux Repository-to-CPE data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch redhat-repository-to-cpe
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := redhatOvalRepositoryToCPE.Fetch(redhatOvalRepositoryToCPE.WithDir(filepath.Join(options.dir, "redhat", "oval", "repository-to-cpe")), redhatOvalRepositoryToCPE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalV1() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := redhatOvalV1.Fetch(redhatOvalV1.WithDir(filepath.Join(options.dir, "redhat", "oval", "v1")), redhatOvalV1.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv1")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatOvalV2() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := redhatOvalV2.Fetch(redhatOvalV2.WithDir(filepath.Join(options.dir, "redhat", "oval", "v2")), redhatOvalV2.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch redhat ovalv2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatSecurityAPI() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := redhatSecurityAPI.Fetch(redhatSecurityAPI.WithDir(filepath.Join(options.dir, "redhat", "security-api")), redhatSecurityAPI.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch redhat security api")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRedhatCVRF() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := redhatCSAF.Fetch(redhatCSAF.WithDir(filepath.Join(options.dir, "redhat", "csaf")), redhatCSAF.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch redhat csaf")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRockyErrata() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := rockyErrata.Fetch(rockyErrata.WithDir(filepath.Join(options.dir, "rocky", "errata")), rockyErrata.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch rocky")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRockyOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// if err := rockyOSV.Fetch(rockyOSV.WithDir(filepath.Join(options.dir, "rocky", "osv")), rockyOSV.WithRetry(options.retry)); err != nil {
			// 	return errors.Wrap(err, "failed to fetch rocky")
			// }
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchSUSEOval() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "suse-oval",
		Short: "Fetch SUSE OVAL data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch suse-oval
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if err := suseOval.Fetch(suseOval.WithDir(filepath.Join(options.dir, "suse", "oval")), suseOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch suse oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchSUSECVRF() *cobra.Command {
	options := &options{
		dir:         util.CacheDir(),
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
			if err := suseCVRF.Fetch(suseCVRF.WithDir(filepath.Join(options.dir, "suse", "cvrf")), suseCVRF.WithRetry(options.retry), suseCVRF.WithConcurrency(options.concurrency), suseCVRF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchSUSECSAF() *cobra.Command {
	options := &options{
		dir:         util.CacheDir(),
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
			if err := suseCSAF.Fetch(suseCSAF.WithDir(filepath.Join(options.dir, "suse", "csaf")), suseCSAF.WithRetry(options.retry), suseCSAF.WithConcurrency(options.concurrency), suseCSAF.WithWait(options.wait)); err != nil {
				return errors.Wrap(err, "failed to fetch suse csaf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 20, "number of concurrency http request")
	cmd.Flags().IntVarP(&options.wait, "wait", "", 1, "wait seccond")

	return cmd
}

func newCmdFetchUbuntuOVAL() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := ubuntuOval.Fetch(ubuntuOval.WithDir(filepath.Join(options.dir, "ubuntu", "oval")), ubuntuOval.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu oval")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchUbuntuCVETracker() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := ubuntuCveTracker.Fetch(ubuntuCveTracker.WithDir(filepath.Join(options.dir, "ubuntu", "cve-tracker")), ubuntuCveTracker.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu cve tracker")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")

	return cmd
}

func newCmdFetchWindowsBulletin() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := windowsBulletin.Fetch(windowsBulletin.WithDir(filepath.Join(options.dir, "windows", "bulletin")), windowsBulletin.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows bulletin")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsCVRF() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := windowsCVRF.Fetch(windowsCVRF.WithDir(filepath.Join(options.dir, "windows", "cvrf")), windowsCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsMSUC() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := windowsMSUC.Fetch(args, windowsMSUC.WithDir(filepath.Join(options.dir, "windows", "msuc")), windowsMSUC.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows msuc")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchWindowsWSUSSCN2() *cobra.Command {
	options := &options{
		dir:         util.CacheDir(),
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
			if err := windowsWSUSSCN2.Fetch(windowsWSUSSCN2.WithDir(filepath.Join(options.dir, "windows", "wsusscn2")), windowsWSUSSCN2.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch windows wsusscn2")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", 2, "number of concurrency cabextract")

	return cmd
}

func newCmdFetchCargoDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := cargoDB.Fetch(cargoDB.WithDir(filepath.Join(options.dir, "cargo", "db")), cargoDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchCargoGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := cargoGHSA.Fetch(cargoGHSA.WithDir(filepath.Join(options.dir, "cargo", "ghsa")), cargoGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchCargoOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := cargoOSV.Fetch(cargoOSV.WithDir(filepath.Join(options.dir, "cargo", "osv")), cargoOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch cargo osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := composerDB.Fetch(composerDB.WithDir(filepath.Join(options.dir, "composer", "db")), composerDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := composerGHSA.Fetch(composerGHSA.WithDir(filepath.Join(options.dir, "composer", "ghsa")), composerGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchComposerGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := composerGLSA.Fetch(composerGLSA.WithDir(filepath.Join(options.dir, "composer", "glsa")), composerGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch composer glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchConan() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "conan",
		Short: "Fetch Conan GitLab Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch conan
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := conan.Fetch(conan.WithDir(filepath.Join(options.dir, "conan")), conan.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch conan")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchDart() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "dart",
		Short: "Fetch Dart GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch dart
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := dart.Fetch(dart.WithDir(filepath.Join(options.dir, "dart")), dart.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch dart")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchErlang() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "erlang",
		Short: "Fetch Erlang GitHub Security Advisory data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch erlang
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := erlang.Fetch(erlang.WithDir(filepath.Join(options.dir, "erlang")), erlang.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch erlang")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := golangDB.Fetch(golangDB.WithDir(filepath.Join(options.dir, "golang", "db")), golangDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := golangGHSA.Fetch(golangGHSA.WithDir(filepath.Join(options.dir, "golang", "ghsa")), golangGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := golangGLSA.Fetch(golangGLSA.WithDir(filepath.Join(options.dir, "golang", "glsa")), golangGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := golangOSV.Fetch(golangOSV.WithDir(filepath.Join(options.dir, "golang", "osv")), golangOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchGolangVulnDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := golangVulnDB.Fetch(golangVulnDB.WithDir(filepath.Join(options.dir, "golang", "vulndb")), golangVulnDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch golang vulndb")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMavenGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := mavenGHSA.Fetch(mavenGHSA.WithDir(filepath.Join(options.dir, "maven", "ghsa")), mavenGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch maven ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchMavenGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := mavenGLSA.Fetch(mavenGLSA.WithDir(filepath.Join(options.dir, "maven", "glsa")), mavenGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch maven glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := npmDB.Fetch(npmDB.WithDir(filepath.Join(options.dir, "npm", "db")), npmDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := npmGHSA.Fetch(npmGHSA.WithDir(filepath.Join(options.dir, "npm", "ghsa")), npmGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := npmGLSA.Fetch(npmGLSA.WithDir(filepath.Join(options.dir, "npm", "glsa")),npmGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNpmOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := npmOSV.Fetch(npmOSV.WithDir(filepath.Join(options.dir, "npm", "osv")), npmOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch npm osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNugetGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := nugetGHSA.Fetch(nugetGHSA.WithDir(filepath.Join(options.dir, "nuget", "ghsa")), nugetGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNugetGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := nugetGLSA.Fetch(nugetGLSA.WithDir(filepath.Join(options.dir, "nuget", "glsa")), nugetGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNugetOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := nugetOSV.Fetch(nugetOSV.WithDir(filepath.Join(options.dir, "nuget", "osv")), nugetOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nuget osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchPipDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := pipDB.Fetch(pipDB.WithDir(filepath.Join(options.dir, "pip", "db")), pipDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := pipGHSA.Fetch(pipGHSA.WithDir(filepath.Join(options.dir, "pip", "ghsa")), pipGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := pipGLSA.Fetch(pipGLSA.WithDir(filepath.Join(options.dir, "pip", "glsa")), pipGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchPipOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := pipOSV.Fetch(pipOSV.WithDir(filepath.Join(options.dir, "pip", "osv")), pipOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch pip osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchRubygemsDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := rubygemsDB.Fetch(rubygemsDB.WithDir(filepath.Join(options.dir, "rubygems", "db")), rubygemsDB.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems db")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsGHSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := rubygemsGHSA.Fetch(rubygemsGHSA.WithDir(filepath.Join(options.dir, "rubygems", "ghsa")), rubygemsGHSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems ghsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsGLSA() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := rubygemsGLSA.Fetch(rubygemsGLSA.WithDir(filepath.Join(options.dir, "rubygems", "glsa")), rubygemsGLSA.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems glsa")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchRubygemsOSV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			// 	if err := rubygemsOSV.Fetch(rubygemsOSV.WithDir(filepath.Join(options.dir, "rubygems", "osv")), rubygemsOSV.WithRetry(options.retry)); err != nil {
			// 		return errors.Wrap(err, "failed to fetch rubygems osv")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchAttack() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := attack.Fetch(attack.WithDir(filepath.Join(options.dir, "attack")), attack.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch attack")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchCapec() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := capec.Fetch(capec.WithDir(filepath.Join(options.dir, "capec")), capec.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch capec")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchCWE() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := cwe.Fetch(cwe.WithDir(filepath.Join(options.dir, "cwe")), cwe.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch cwe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchEPSS() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := epss.Fetch(epss.WithDir(filepath.Join(options.dir, "epss")), epss.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch epss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitExploitDB() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := exploitExploitDB.Fetch(exploitExploitDB.WithDir(filepath.Join(options.dir, "exploit", "exploitdb")), exploitExploitDB.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit exploitdb")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitGitHub() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := exploitGitHub.Fetch(exploitGitHub.WithDir(filepath.Join(options.dir, "exploit", "github")), exploitGitHub.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit github")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitInthewild() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := exploitInTheWild.Fetch(exploitInTheWild.WithDir(filepath.Join(options.dir, "exploit", "inthewild")), exploitInTheWild.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit inthewild")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchExploitExploitTrickest() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := exploitTrickest.Fetch(exploitTrickest.WithDir(filepath.Join(options.dir, "exploit", "trickest")), exploitTrickest.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch exploit trickest")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedDetail() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := jvnFeedDetail.Fetch(jvnFeedDetail.WithDir(filepath.Join(options.dir, "jvn", "feed", "detail")), jvnFeedDetail.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed detail")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedProduct() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := jvnFeedProduct.Fetch(jvnFeedProduct.WithDir(filepath.Join(options.dir, "jvn", "feed", "product")), jvnFeedProduct.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed product")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchJVNFeedRSS() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := jvnFeedRSS.Fetch(jvnFeedRSS.WithDir(filepath.Join(options.dir, "jvn", "feed", "rss")), jvnFeedRSS.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch jvn feed rss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchKEV() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := kev.Fetch(kev.WithDir(filepath.Join(options.dir, "kev")), kev.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch kev")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreCVRF() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := mitreCVRF.Fetch(mitreCVRF.WithDir(filepath.Join(options.dir, "mitre", "cvrf")), mitreCVRF.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre cvrf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreV4() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := mitreV4.Fetch(mitreV4.WithDir(filepath.Join(options.dir, "mitre", "v4")), mitreV4.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre v4")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMitreV5() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := mitreV5.Fetch(mitreV5.WithDir(filepath.Join(options.dir, "mitre", "v5")), mitreV5.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch mitre v5")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchMSF() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := msf.Fetch(msf.WithDir(filepath.Join(options.dir, "msf")), msf.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch msf")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
func newCmdFetchNVDAPI() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
		retry: 3,
	}

	cmd := &cobra.Command{
		Use:   "nvd-api",
		Short: "Fetch NVD API data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch nvd-api
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			// 	if err := nvdAPI.Fetch(nvdAPI.WithDir(filepath.Join(options.dir, "nvd", "api"))); err != nil {
			// 		return errors.Wrap(err, "failed to fetch nvd api")
			// 	}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNVDFeedCVE() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := nvdFeedCVE.Fetch(nvdFeedCVE.WithDir(filepath.Join(options.dir, "nvd", "feed", "cve")), nvdFeedCVE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cve")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNVDFeedCPE() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := nvdFeedCPE.Fetch(nvdFeedCPE.WithDir(filepath.Join(options.dir, "nvd", "feed", "cpe")), nvdFeedCPE.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}

func newCmdFetchNVDFeedCPEMatch() *cobra.Command {
	options := &options{
		dir:   util.CacheDir(),
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
			if err := nvdFeedCPEMatch.Fetch(nvdFeedCPEMatch.WithDir(filepath.Join(options.dir, "nvd", "feed", "cpematch")), nvdFeedCPEMatch.WithRetry(options.retry)); err != nil {
				return errors.Wrap(err, "failed to fetch nvd feed cpe")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", util.CacheDir(), "output fetch results to specified directory")
	cmd.Flags().IntVarP(&options.retry, "retry", "", 3, "number of retry http request")

	return cmd
}
