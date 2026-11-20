package dotgit

import (
	"encoding/json/v2"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/show"
)

func newCmdShow() *cobra.Command {
	options := &struct {
		useNativeGit bool
	}{
		useNativeGit: true,
	}

	cmd := &cobra.Command{
		Use:   "show <dotgit repository> <revision>",
		Short: "Show the full hash and the author and committer times (in UTC) of the commit the revision names",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit show vuls-data-raw-debian-security-tracker-api main
			$ vuls-data-update dotgit show vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			c, err := show.Show(args[0], args[1], show.WithUseNativeGit(options.useNativeGit))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit show")
			}
			if err := json.MarshalWrite(os.Stdout, c, json.Deterministic(true)); err != nil {
				return errors.Wrap(err, "failed to print commit")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")

	return cmd
}
