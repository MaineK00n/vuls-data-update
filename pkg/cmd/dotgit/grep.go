package dotgit

import (
	"fmt"
	"maps"
	"os"
	"slices"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/grep"
)

func newCmdGrep() *cobra.Command {
	options := &struct {
		treeish   string
		pathspecs []string

		filesWithMatches bool
	}{
		treeish:   "main",
		pathspecs: nil,

		filesWithMatches: false,
	}

	cmd := &cobra.Command{
		Use:   "grep <repository> [<pattern>]",
		Short: "Grep files in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit grep vuls-data-raw-debian-security-tracker CVE-2025-0001
			$ vuls-data-update dotgit grep --pathspec ".*\.json" vuls-data-raw-debian-security-tracker "CVE-2025-000." "CVE-2025-001."
		`),
		Args: cobra.MinimumNArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			rs, err := grep.Grep(args[0], args[1:], grep.WithTreeish(options.treeish), grep.WithPathSpecs(options.pathspecs))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit grep")
			}

			if options.filesWithMatches {
				m := make(map[string]struct{})
				for _, r := range rs {
					m[r.FileName] = struct{}{}
				}
				ns := slices.Collect(maps.Keys(m))
				slices.Sort(ns)
				for _, n := range ns {
					if _, err := fmt.Fprintln(os.Stdout, n); err != nil {
						return errors.Wrap(err, "failed to print to stdout")
					}
				}
			} else {
				for _, r := range rs {
					if _, err := fmt.Fprintln(os.Stdout, r.String()); err != nil {
						return errors.Wrap(err, "failed to print to stdout")
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&options.treeish, "treeish", "", options.treeish, "grep in specified treeish")
	cmd.Flags().StringArrayVarP(&options.pathspecs, "pathspec", "p", options.pathspecs, "grep in specified pathspec")
	cmd.Flags().BoolVarP(&options.filesWithMatches, "files-with-matches", "l", options.filesWithMatches, "Instead of showing every matched line, show only the names of files that contain matches")

	return cmd
}
