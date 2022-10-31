package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	buildCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/build"
	fetchCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/fetch"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls-data-update <command> <subcommand> (<os>)",
		Short:         "Vuls data update",
		Long:          "Fetch and Build data source",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os debian
			$ vuls-data-update fetch library cargo
			$ vuls-data-update fetch other nvd
			$ vuls-data-update build
		`),
	}

	cmd.AddCommand(fetchCmd.NewCmdFetch())
	cmd.AddCommand(buildCmd.NewCmdBuild())

	return cmd
}
