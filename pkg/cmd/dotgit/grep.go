package dotgit

import (
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/grep"
)

func newCmdGrep() *cobra.Command {
	options := &struct {
		useNativeGit     bool
		treeish          string
		pathspecs        []string
		filesWithMatches bool
	}{
		useNativeGit:     true,
		treeish:          "main",
		pathspecs:        nil,
		filesWithMatches: false,
	}

	cmd := &cobra.Command{
		Use:   "grep <repository> <pattern>...",
		Short: "Grep files in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit grep vuls-data-raw-debian-security-tracker-api CVE-2025-0001
			$ vuls-data-update dotgit grep --pathspec ".*\.json" vuls-data-raw-debian-security-tracker-api "CVE-2025-000." "CVE-2025-001."
		`),
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			r, err := grep.Grep(args[0], args[1:], grep.WithUseNativeGit(options.useNativeGit), grep.WithTreeish(options.treeish), grep.WithPathSpecs(options.pathspecs), grep.WithFilesWithMatches(options.filesWithMatches))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit grep")
			}

			if _, err := fmt.Fprintln(os.Stdout, r); err != nil {
				return errors.Wrap(err, "failed to print to stdout")
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")
	cmd.Flags().StringVarP(&options.treeish, "treeish", "", options.treeish, "grep in specified treeish")
	cmd.Flags().StringArrayVarP(&options.pathspecs, "pathspec", "p", options.pathspecs, "grep in specified pathspec")
	cmd.Flags().BoolVarP(&options.filesWithMatches, "files-with-matches", "l", options.filesWithMatches, "Instead of showing every matched line, show only the names of files that contain matches")

	return cmd
}
