package build

import (
	"fmt"

	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"
)

var (
	supportOS      = []string{"alma", "alpine", "amazon", "arch", "debian", "epel", "fedora", "gentoo", "oracle", "redhat", "rocky", "suse", "ubuntu", "windows"}
	supportLibrary = []string{"cargo"}
)

func NewCmdBuild() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "build <subcommand> (<os>)",
		Short: "Build data source",
		Example: heredoc.Doc(`
			$ vuls-data-update build os debian
			$ vuls-data-update build library cargo
			$ vuls-data-update build other
		`),
	}

	cmd.AddCommand(newCmdBuildOS())
	cmd.AddCommand(newCmdBuildLibrary())
	cmd.AddCommand(newCmdBuildOther())

	return cmd
}

func newCmdBuildOS() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "os <os name>",
		Short:     "Build OS data source",
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: supportOS,
		RunE: func(_ *cobra.Command, args []string) error {
			return buildOSRun(args[0])
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build os debian
		`),
	}
	return cmd
}

func buildOSRun(name string) error {
	switch name {
	case "alma":
	case "alpine":
	case "amazon":
	case "arch":
	case "debian":
	case "epel":
	case "fedora":
	case "gentoo":
	case "oracle":
	case "redhat":
	case "rocky":
	case "suse":
	case "ubuntu":
	case "windows":
	default:
		return fmt.Errorf("accepts %q, received %q", supportOS, name)
	}
	return nil
}

func newCmdBuildLibrary() *cobra.Command {
	cmd := &cobra.Command{
		Use:       "library <library name>",
		Short:     "Build Library data source",
		Args:      cobra.ExactValidArgs(1),
		ValidArgs: supportLibrary,
		RunE: func(_ *cobra.Command, args []string) error {
			return buildLibraryRun(args[0])
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build library cargo
		`),
	}
	return cmd
}

func buildLibraryRun(name string) error {
	switch name {
	case "cargo":
	default:
		return fmt.Errorf("accepts %q, received %q", supportLibrary, name)
	}
	return nil
}

func newCmdBuildOther() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "other <os name>",
		Short: "Build Other data source",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return buildOtherRun()
		},
		Example: heredoc.Doc(`
			$ vuls-data-update build other
		`),
	}
	return cmd
}

func buildOtherRun() error {
	fmt.Println("other")
	return nil
}
