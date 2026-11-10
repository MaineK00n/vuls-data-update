package dotgit

import (
	"path/filepath"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/shallow"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func newCmdShallow() *cobra.Command {
	options := &struct {
		dir   string
		depth int
	}{
		dir:   filepath.Join(util.CacheDir(), "dotgit", "shallow"),
		depth: 1,
	}

	cmd := &cobra.Command{
		Use:   "shallow <repository path>",
		Short: "Copy the last commits of every branch of vuls-data-* dotgit into a new shallow repository",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit shallow --dir latest vuls-data-raw-debian-security-tracker-api
			$ vuls-data-update dotgit shallow --dir truncated --depth 100 vuls-data-extracted-debian-security-tracker-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if _, err := shallow.Shallow(args[0], shallow.WithDir(options.dir), shallow.WithDepth(options.depth)); err != nil {
				return errors.Wrap(err, "failed to dotgit shallow")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&options.dir, "dir", "d", options.dir, "create the new repository under the specified directory, named after the repository")
	cmd.Flags().IntVarP(&options.depth, "depth", "", options.depth, "number of commits to keep from the tip of each branch")

	return cmd
}
