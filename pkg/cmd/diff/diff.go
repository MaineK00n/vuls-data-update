package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/cmd/util/flag"
	"github.com/MaineK00n/vuls-data-update/pkg/diff"
	"github.com/MaineK00n/vuls-data-update/pkg/diff/util"
)

type option struct {
	org          string
	remotePrefix string
	dir          string
	filter       flag.Choices
	diffAlg      flag.Choices
	format       flag.Choices
	outputToFile bool
}

func NewCmdDiff() *cobra.Command {
	opts := &option{
		org:          "vulsio",
		remotePrefix: "https://github.com/vulsio",
		dir:          filepath.Join(util.CacheDir(), "diff"),
		filter:       flag.NewChoices([]string{"tree:0", "blob:none"}, "tree:0"),
		diffAlg:      flag.NewChoices([]string{"default", "patience", "minimal", "histogram", "myers"}, "default"),
		format:       flag.NewChoices([]string{"json", "md"}, "json"),
	}

	cmd := &cobra.Command{
		Use:   "diff <datasource> <root ID> <old commit hash> <new commit hash>",
		Short: "Show diff information",
		Example: heredoc.Doc(`
			$ vuls-data-update diff amazon ALAS2-2022-1768 7d92ee3 d27dae3
			$ vuls-data-update diff nvd-api-cve CVE-2024-33892 e249e6c 0902d12
		`),
		Args: cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := run(cmd, args[0], args[1], args[2], args[3], opts); err != nil {
				return errors.Wrap(err, "failed to diff")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&opts.dir, "dir", "d", filepath.Join(util.CacheDir(), "diff"), "working root directory in diff operation")
	cmd.Flags().Var(&opts.filter, "filter", fmt.Sprintf("fiter for git clone/fetch, one of [%s]", strings.Join(opts.filter.Choices, ", ")))
	cmd.Flags().Var(&opts.diffAlg, "diff-algorithm", fmt.Sprintf("algorithm for git diff, one of [%s] c.f. https://git-scm.com/docs/git-diff", strings.Join(opts.diffAlg.Choices, ", ")))
	cmd.Flags().StringVar(&opts.remotePrefix, "remote-prefix", "https://github.com/vulsio", "prefix of git repository")
	cmd.Flags().VarP(&opts.format, "format", "f", fmt.Sprintf("output format, one of [%s]", strings.Join(opts.format.Choices, ", ")))
	cmd.Flags().BoolVarP(&opts.outputToFile, "output-to-file", "O", false, "output to a file under current dir. The file name is <rootID>-<kind>-<old>-<new>.(json|md)")

	_ = cmd.RegisterFlagCompletionFunc("format", opts.format.Completion)
	_ = cmd.RegisterFlagCompletionFunc("filter", opts.filter.Completion)
	_ = cmd.RegisterFlagCompletionFunc("diff-algorithm", opts.diffAlg.Completion)

	return cmd
}

func run(cmd *cobra.Command, datasource, rootID, old, new string, opts *option) error {
	log.Printf("[INFO] Diff of %s, rootID: %s, commits: %.7s..%.7s", datasource, rootID, old, new)
	wholeDiff, err := diff.Diff(datasource, rootID, old, new,
		diff.WithRemotePrefix(opts.remotePrefix),
		diff.WithDir(opts.dir), diff.WithFilter(opts.filter.String()), diff.WithDiffAlg(opts.diffAlg.String()))
	if err != nil {
		return errors.Wrapf(err, "get whole diff")
	}

	writer := cmd.OutOrStdout()
	if opts.outputToFile {
		filename := fmt.Sprintf("diff_%s_%s_%.7s_%.7s.%s", datasource, rootID, old, new, opts.format.String())
		f, err := os.Create(filename)
		if err != nil {
			return errors.Wrapf(err, "open %s", filename)
		}
		defer f.Close() //nolint:errcheck
		writer = f
	}

	if err := output(wholeDiff, opts.format.String(), writer); err != nil {
		return errors.Wrapf(err, "output")
	}

	return nil
}

func output(whole diff.WholeDiff, format string, writer io.Writer) error {
	switch format {
	case "json":
		e := json.NewEncoder(writer)
		e.SetEscapeHTML(false)
		e.SetIndent("", "\t")
		if err := e.Encode(whole); err != nil {
			return errors.Wrapf(err, "encode json")
		}
		return nil
	case "md":
		if _, err := fmt.Fprintf(writer, "# Root ID: %s\n\n", whole.RootID); err != nil {
			return errors.Wrap(err, "print root ID")
		}
		for n, e := range whole.Extracted {
			if err := formatRepo("extracted", n, e, writer); err != nil {
				return errors.Wrap(err, "format extracted repo")
			}
		}
		for n, r := range whole.Raw {
			if err := formatRepo("raw", n, r, writer); err != nil {
				return errors.Wrap(err, "format raw repo")
			}
		}
		return nil
	default:
		return errors.Errorf("unexpected format. expected: %q, actual: %q", []string{"json", "md"}, format)
	}
}

func formatRepo(kind, name string, r diff.Repository, writer io.Writer) error {
	if _, err := fmt.Fprintf(writer, "## %s\n\n", name); err != nil {
		return errors.Wrap(err, "print repo name")
	}
	if _, err := fmt.Fprintf(writer, "- kind: %s\n", kind); err != nil {
		return errors.Wrap(err, "print repo kind")
	}
	if _, err := fmt.Fprintf(writer, "- old commit: %s\n", r.Commits.Old); err != nil {
		return errors.Wrap(err, "print old commit")
	}
	if _, err := fmt.Fprintf(writer, "- new commit: %s\n", r.Commits.New); err != nil {
		return errors.Wrap(err, "print new commit")
	}
	if _, err := fmt.Fprintf(writer, "- compare URL: %s\n", r.Commits.CompareURL); err != nil {
		return errors.Wrap(err, "print compare URL")
	}
	if _, err := fmt.Fprintf(writer, "\n"); err != nil {
		return errors.Wrap(err, "print newline")
	}
	for _, c := range r.Files {
		if _, err := fmt.Fprintf(writer, "### %s\n\n", func() string {
			if c.Path.New != "" {
				return c.Path.New
			}
			return c.Path.Old
		}()); err != nil {
			return errors.Wrap(err, "print path")
		}
		if _, err := fmt.Fprintf(writer, "- old commit: %s\n", func() string {
			if c.Path.Old != "" {
				return r.Commits.Old
			}
			return ""
		}()); err != nil {
			return errors.Wrap(err, "print old commit")
		}
		if _, err := fmt.Fprintf(writer, "- new commit: %s\n", func() string {
			if c.Path.New != "" {
				return r.Commits.New
			}
			return ""
		}()); err != nil {
			return errors.Wrap(err, "print new commit")
		}
		if _, err := fmt.Fprintf(writer, "- old URL: %s\n", c.URL.Old); err != nil {
			return errors.Wrap(err, "print old url")
		}
		if _, err := fmt.Fprintf(writer, "- new URL: %s\n\n", c.URL.New); err != nil {
			return errors.Wrap(err, "print new url")
		}
		if _, err := fmt.Fprintf(writer, "```diff\n"); err != nil {
			return errors.Wrap(err, "print diff header")
		}
		if _, err := fmt.Fprintf(writer, "%s\n", c.Diff); err != nil {
			return errors.Wrap(err, "print diff")
		}
		if _, err := fmt.Fprintf(writer, "```\n"); err != nil {
			return errors.Wrap(err, "print diff footer")
		}
		if _, err := fmt.Fprintf(writer, "\n"); err != nil {
			return errors.Wrap(err, "print newline")
		}
	}
	return nil
}
