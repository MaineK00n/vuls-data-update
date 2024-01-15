package extract

import (
	"path/filepath"
	"runtime"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	almaErrata "github.com/MaineK00n/vuls-data-update/pkg/extract/alma/errata"
	almaOSV "github.com/MaineK00n/vuls-data-update/pkg/extract/alma/osv"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"
)

func NewCmdExtract() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extract <data source>",
		Short: "Extract data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract vuls-data-raw-debian-security-tracker-salsa
		`),
	}

	cmd.AddCommand(
		newCmdAlmaErrata(), newCmdAlmaOSV(),
		// newCmdAlpineSecDB(), newCmdAlpineOSV(),
		// newCmdAmazon(),
		// newCmdArch(),
		// newCmdDebianOval(), newCmdDebianSecurityTrackerAPI(), newCmdDebianSecurityTrackerSalsa(), newCmdDebianOSV(),
		// newCmdEPEL(),
		// newCmdFedora(),
		// newCmdFortinet(),
		// newCmdFreeBSD(),
		// newCmdGentoo(),
		// newCmdNetBSD(),
		// newCmdOracle(),
		// newCmdRedhatOvalRepositoryToCPE(), newCmdRedhatOvalV1(), newCmdRedhatOvalV2(), newCmdRedhatCVE(), newCmdRedhatCVRF(), newCmdRedhatCSAF(), newCmdRedhatVEX(),
		// newCmdRockyErrata(), newCmdRockyOSV(),
		// newCmdSUSEOval(), newCmdSUSECVRF(), newCmdSUSECVRFCVE(), newCmdSUSECSAF(), newCmdSUSECSAFVEX(),
		// newCmdUbuntuOVAL(), newCmdUbuntuCVETracker(),
		// newCmdWindowsBulletin(), newCmdWindowsCVRF(), newCmdWindowsMSUC(), newCmdWindowsWSUSSCN2(),

		// newCmdCargoDB(), newCmdCargoGHSA(), newCmdCargoOSV(),
		// newCmdComposerDB(), newCmdComposerGHSA(), newCmdComposerGLSA(), newCmdComposerOSV(),
		// newCmdConanGLSA(),
		// newCmdErlangGHSA(), newCmdErlangOSV(),
		// newCmdGolangDB(), newCmdGolangGHSA(), newCmdGolangGLSA(), newCmdGolangVulnDB(), newCmdGolangOSV(),
		// newCmdHaskellOSV(),
		// newCmdMavenGHSA(), newCmdMavenGLSA(), newCmdMavenOSV(),
		// newCmdNpmDB(), newCmdNpmGHSA(), newCmdNpmGLSA(), newCmdNpmOSV(),
		// newCmdNugetGHSA(), newCmdNugetGLSA(), newCmdNugetOSV(),
		// newCmdPipDB(), newCmdPipGHSA(), newCmdPipGLSA(), newCmdPipOSV(),
		// newCmdPubGHSA(), newCmdPubOSV(),
		// newCmdROSV(),
		// newCmdRubygemsDB(), newCmdRubygemsGHSA(), newCmdRubygemsGLSA(), newCmdRubygemsOSV(),
		// newCmdSwiftGHSA(), newCmdSwiftOSV(),

		// newCmdAttack(),
		// newCmdCapec(),
		// newCmdCWE(),
		newCmdEPSS(),
		// newCmdExploitExploitDB(), newCmdExploitGitHub(), newCmdExploitInthewild(), newCmdExploitExploitTrickest(),
		// newCmdJVNFeedDetail(), newCmdJVNFeedProduct(), newCmdJVNFeedRSS(),
		// newCmdKEV(),
		// newCmdMitreCVRF(), newCmdMitreV4(), newCmdMitreV5(),
		// newCmdMSF(),
		// newCmdNVDAPICVE(), newCmdNVDAPICPE(), newCmdNVDAPICPEMatch(), newCmdNVDFeedCVE(), newCmdNVDFeedCPE(), newCmdNVDFeedCPEMatch(),
		// newCmdSnort(),
	)

	return cmd
}

func newCmdAlmaErrata() *cobra.Command {
	options := &struct {
		dir string
	}{
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
	options := &struct {
		dir string
	}{
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

func newCmdEPSS() *cobra.Command {
	options := &struct {
		dir         string
		concurrency int
		since       string
		until       string
	}{
		dir:         filepath.Join(util.CacheDir(), "extract", "epss"),
		concurrency: runtime.NumCPU(),
		since:       "2021-04-14",
	}

	cmd := &cobra.Command{
		Use:   "epss <Raw EPSS Repository PATH>",
		Short: "Extract EPSS data source",
		Example: heredoc.Doc(`
			$ vuls-data-update extract epss vuls-data-raw-epss
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			since, err := time.Parse("2006-01-02", options.since)
			if err != nil {
				return errors.Wrap(errors.Wrap(err, "invalid since format"), "failed to extract epss")
			}

			until, err := time.Parse("2006-01-02", options.until)
			if err != nil {
				return errors.Wrap(errors.Wrap(err, "invalid until format"), "failed to extract epss")
			}

			if err := epss.Extract(args[0], epss.WithDir(options.dir), epss.WithConcurrency(options.concurrency), epss.WithSince(since), epss.WithUntil(until)); err != nil {
				return errors.Wrap(err, "failed to extract epss")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", filepath.Join(util.CacheDir(), "extract", "epss"), "output extract results to specified directory")
	cmd.Flags().IntVarP(&options.concurrency, "concurrency", "", runtime.NumCPU(), "number of concurrency process")
	cmd.Flags().StringVarP(&options.since, "since", "", "2021-04-14", "since date. format: \"yyyy-mm-dd\"")
	cmd.Flags().StringVarP(&options.until, "until", "", time.Now().Format("2006-01-02"), "until date. format: \"yyyy-mm-dd\"")

	return cmd
}
