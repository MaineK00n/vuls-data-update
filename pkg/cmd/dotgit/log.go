package dotgit

import (
	"fmt"
	"os"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/log"
)

func newCmdLog() *cobra.Command {
	options := &struct {
		useNativeGit bool
		from         string
		pathspecs    []string
		since        datetimeType
		until        datetimeType
	}{
		useNativeGit: true,
		from:         "",
		pathspecs:    nil,
		since:        datetimeType{value: nil},
		until:        datetimeType{value: nil},
	}

	cmd := &cobra.Command{
		Use:   "log <repository>",
		Short: "Print the commit history of the specified repository",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit log vuls-data-raw-debian-security-tracker-api
		`),
		Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			iter, err := log.Log(args[0], log.WithUseNativeGit(options.useNativeGit), log.WithFrom(options.from), log.WithPathSpecs(options.pathspecs), log.WithSince(options.since.value), log.WithUntil(options.until.value))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit log")
			}

			for commit, err := range iter {
				if err != nil {
					return errors.Wrap(err, "failed to iterate commit")
				}

				if _, err := fmt.Fprintln(os.Stdout, commit); err != nil {
					return errors.Wrap(err, "failed to print commit")
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&options.useNativeGit, "use-native-git", "", options.useNativeGit, "use native git command instead of go-git")
	cmd.Flags().StringVarP(&options.from, "from", "", options.from, "start from the specified commit hash")
	cmd.Flags().StringArrayVarP(&options.pathspecs, "pathspec", "p", options.pathspecs, "filter commits by pathspec")
	cmd.Flags().VarP(&options.since, "since", "", "show commits since the specified date (RFC3339 format)")
	_ = cmd.RegisterFlagCompletionFunc("since", datetimeTypeCompletion)
	cmd.Flags().VarP(&options.until, "until", "", "show commits until the specified date (RFC3339 format)")
	_ = cmd.RegisterFlagCompletionFunc("until", datetimeTypeCompletion)
	return cmd

}

type datetimeType struct {
	value *time.Time
}

func (t *datetimeType) String() string {
	if t == nil || t.value == nil {
		return ""
	}
	return t.value.Format(time.RFC3339)
}

func (t *datetimeType) Set(value string) error {
	tv, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return errors.Wrapf(err, "parse %q as RFC3399", value)
	}
	t.value = &tv
	return nil
}

func (t *datetimeType) Type() string {
	return "datetimeType"
}

func datetimeTypeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{time.Now().Format(time.RFC3339)}, cobra.ShellCompDirectiveDefault
}
