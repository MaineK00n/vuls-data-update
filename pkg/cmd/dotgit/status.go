package dotgit

import (
	"encoding/json/v2"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/status"
)

func newCmdStatus() *cobra.Command {
	options := &struct {
		git bool
	}{
		git: false,
	}

	cmd := &cobra.Command{
		Use:   "status <dotgit directory>",
		Short: "Show dotgit status",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit status vuls-data-raw-debian-security-tracker-api
			$ vuls-data-update dotgit status --git vuls-data-raw-debian-security-tracker-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := status.Status(args[0], status.WithGit(options.git))
			if err != nil {
				return errors.Wrap(err, "failed to get local dotgit status")
			}
			if err := json.MarshalWrite(os.Stdout, s, json.Deterministic(true)); err != nil {
				return errors.Wrap(err, "failed to print local dotgit status")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.git, "git", "", options.git, "also show branches, shallow roots, and the on-disk size of all objects and of the branch tips (runs native git)")

	return cmd
}
