package version

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/version"
)

func NewCmdVersion() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Example: heredoc.Doc(`
			$ vuls-data-update version
		`),
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if _, err := fmt.Fprintln(os.Stdout, version.String()); err != nil {
				return errors.Wrap(err, "failed to print version")
			}
			return nil
		},
	}

	return cmd
}
