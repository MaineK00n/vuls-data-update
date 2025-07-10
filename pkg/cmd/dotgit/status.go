package dotgit

import (
	"encoding/json"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/status/local"
)

func newCmdStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show dotgit status",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit status local vuls-data-raw-debian-security-tracker
			$ vuls-data-update dotgit status remote ghcr.io/vulsio/vuls-data-db:vuls-data-raw-debian-security-tracker
		`),
	}

	cmd.AddCommand(newCmdStatusLocal())

	return cmd
}

func newCmdStatusLocal() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "local <dotgit directory>",
		Short: "Show local dotgit status",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit status local vuls-data-raw-debian-security-tracker
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := local.Status(args[0])
			if err != nil {
				return errors.Wrap(err, "failed to get local dotgit status")
			}
			if err := json.NewEncoder(os.Stdout).Encode(s); err != nil {
				return errors.Wrap(err, "failed to print local dotgit status")
			}
			return nil
		},
	}

	return cmd
}
