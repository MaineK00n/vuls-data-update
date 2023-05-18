package root

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/spf13/cobra"

	fetchCmd "github.com/MaineK00n/vuls-data-update/pkg/cmd/fetch"
)

func NewCmdRoot() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "vuls-data-update <command> <subcommand> ([os|library|other])",
		Short:         "Vuls data update",
		Long:          "Fetch and Build data source",
		SilenceErrors: true,
		SilenceUsage:  true,
		Example: heredoc.Doc(`
			$ vuls-data-update fetch os
			$ vuls-data-update fetch os debian
			$ vuls-data-update fetch library
			$ vuls-data-update fetch library cargo
			$ vuls-data-update fetch other
			$ vuls-data-update fetch other nvd
			$ vuls-data-update build
			$ vuls-data-update build nvd ubuntu
		`),
	}

	cmd.AddCommand(fetchCmd.NewCmdFetch())

	return cmd
}
