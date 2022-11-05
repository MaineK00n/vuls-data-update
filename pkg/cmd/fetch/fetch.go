package fetch

import (
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/cargo"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/composer"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/conan"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/erlang"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/golang"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/maven"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/npm"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/nuget"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/pip"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/library/rubygems"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alma"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/alpine"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/amazon"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/arch"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/debian"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/epel"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/fedora"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/freebsd"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/gentoo"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/oracle"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/redhat"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/rocky"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/suse"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/ubuntu"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/os/windows"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/attack"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/capec"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/cwe"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/epss"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/exploit"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/jvn"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/kev"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/mitre"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/msf"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/other/nvd"
)

var (
	supportOS      = []string{"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "freebsd", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows"}
	supportLibrary = []string{"cargo", "composer", "conan", "erlang", "golang", "maven", "npm", "nuget", "pip", "rubygems"}
	supportOther   = []string{"attack", "capec", "cwe", "epss", "exploit", "jvn", "kev", "mitre", "msf", "nvd"}
)

func NewCmdFetch() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fetch <subcommand> <data source>",
		Short: "Fetch data source",
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os debian
			$ vuls-data-update fetch library cargo
			$ vuls-data-update fetch other nvd
		`),
	}

	cmd.AddCommand(newCmdFetchOS())
	cmd.AddCommand(newCmdFetchLibrary())
	cmd.AddCommand(newCmdFetchOther())

	return cmd
}

func newCmdFetchOS() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "os ([os name])",
		Short:     "Fetch OS data source",
		Args:      cobra.MatchAll(cobra.MinimumNArgs(0), cobra.OnlyValidArgs),
		ValidArgs: supportOS,
		RunE: func(_ *cobra.Command, args []string) error {
			as := args
			if len(as) == 0 {
				as = supportOS
			}
			return fetchOSRun(as)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os
			$ vuls-data-update fetch os debian
		`),
	}
	return cmd
}

func fetchOSRun(names []string) error {
	for _, name := range names {
		switch name {
		case "alma":
			if err := alma.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch almalinux")
			}
		case "alpine":
			if err := alpine.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch alpine linux")
			}
		case "amazon":
			if err := amazon.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch amazon linux")
			}
		case "arch":
			if err := arch.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch arch linux")
			}
		case "debian":
			if err := debian.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch debian")
			}
		case "epel":
			if err := epel.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch epel")
			}
		case "fedora":
			if err := fedora.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch fedora")
			}
		case "freebsd":
			if err := freebsd.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch freebsd")
			}
		case "gentoo":
			if err := gentoo.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch gentoo")
			}
		case "oracle":
			if err := oracle.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch oracle linux")
			}
		case "redhat":
			if err := redhat.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch redhat")
			}
		case "rocky":
			if err := rocky.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch rocky")
			}
		case "suse":
			if err := suse.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch suse")
			}
		case "ubuntu":
			if err := ubuntu.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch ubuntu")
			}
		case "windows":
			if err := windows.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch windows")
			}
		default:
			return fmt.Errorf("accepts %q, received %q", supportOS, name)
		}
	}
	return nil
}

func newCmdFetchLibrary() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "library ([library name])",
		Short:     "Fetch Library data source",
		Args:      cobra.MatchAll(cobra.MinimumNArgs(0), cobra.OnlyValidArgs),
		ValidArgs: supportLibrary,
		RunE: func(_ *cobra.Command, args []string) error {
			as := args
			if len(as) == 0 {
				as = supportLibrary
			}
			return fetchLibraryRun(as)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch library
			$ vuls-data-update fetch library cargo
		`),
	}
	return cmd
}

func fetchLibraryRun(names []string) error {
	for _, name := range names {
		switch name {
		case "cargo":
			if err := cargo.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch cargo")
			}
		case "composer":
			if err := composer.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch composer")
			}
		case "conan":
			if err := conan.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch conan")
			}
		case "erlang":
			if err := erlang.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch erlang")
			}
		case "golang":
			if err := golang.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch golang")
			}
		case "maven":
			if err := maven.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch maven")
			}
		case "npm":
			if err := npm.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch npm")
			}
		case "nuget":
			if err := nuget.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch nuget")
			}
		case "pip":
			if err := pip.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch pip")
			}
		case "rubygems":
			if err := rubygems.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch rubygems")
			}
		default:
			return fmt.Errorf("accepts %q, received %q", supportLibrary, name)
		}
	}
	return nil
}

func newCmdFetchOther() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "other ([data name])",
		Short:     "Fetch Other data source",
		Args:      cobra.MatchAll(cobra.MinimumNArgs(0), cobra.OnlyValidArgs),
		ValidArgs: supportOther,
		RunE: func(_ *cobra.Command, args []string) error {
			as := args
			if len(as) == 0 {
				as = supportOther
			}
			return fetchOtherRun(as)
		},
		Example: heredoc.Doc(`
			$ vuls-data-update fetch other	
			$ vuls-data-update fetch other nvd
		`),
	}
	return cmd
}

func fetchOtherRun(names []string) error {
	for _, name := range names {
		switch name {
		case "attack":
			if err := attack.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch attack")
			}
		case "capec":
			if err := capec.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch capec")
			}
		case "cwe":
			if err := cwe.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch cwe")
			}
		case "epss":
			if err := epss.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch epss")
			}
		case "exploit":
			if err := exploit.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch exploit")
			}
		case "jvn":
			if err := jvn.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch jvn")
			}
		case "kev":
			if err := kev.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch kev")
			}
		case "mitre":
			if err := mitre.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch mitre")
			}
		case "msf":
			if err := msf.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch msf")
			}
		case "nvd":
			if err := nvd.Fetch(); err != nil {
				return errors.Wrap(err, "failed to fetch nvd")
			}
		default:
			return fmt.Errorf("accepts %q, received %q", supportOther, name)
		}
	}
	return nil
}
