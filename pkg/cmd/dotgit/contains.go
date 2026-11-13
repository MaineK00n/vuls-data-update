package dotgit

import (
	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
)

func newCmdContains() *cobra.Command {
	options := &struct {
		useNativeGit bool
		branch       string
	}{
		useNativeGit: true,
		branch:       "",
	}

	cmd := &cobra.Command{
		Use:   "contains <dotgit repository> <commit hash>",
		Short: "Check if the commit hash is contained in the dotgit repository",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit contains ~/.cache/vuls-data-update/dotgit/vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3
			$ vuls-data-update dotgit contains --branch main ~/.cache/vuls-data-update/dotgit/vuls-data-raw-debian-security-tracker-api 729c12ba5ff2dafacaf26b9311d8dcbea1d98bd3
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := contains.Contains(args[0], args[1], contains.WithUseNativeGit(options.useNativeGit), contains.WithBranch(options.branch)); err != nil {
				return errors.Wrap(err, "failed to dotgit contains")
			}
			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")
	cmd.Flags().StringVarP(&options.branch, "branch", "", options.branch, "also check that the commit, given as a full hash, is the tip of the specified branch or an ancestor of it")

	return cmd
}
