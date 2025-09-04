package dotgit

import (
	"encoding/json"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/status"
)

func newCmdStatus() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status <dotgit directory>",
		Short: "Show dotgit status",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit status vuls-data-raw-debian-security-tracker-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			s, err := status.Status(args[0])
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
