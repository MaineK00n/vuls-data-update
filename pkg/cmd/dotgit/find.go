package dotgit

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/MakeNowJust/heredoc"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/find"
)

func newCmdFind() *cobra.Command {
	options := &struct {
		treeish string

		format formatType
	}{
		treeish: "main",

		format: formatTypePlain,
	}

	cmd := &cobra.Command{
		Use:   "find <repository> <expression>",
		Short: "Find files in the specified treeish",
		Example: heredoc.Doc(`
			$ vuls-data-update dotgit find --treeish HEAD vuls-data-raw-debian-security-tracker CVE-2025-0001.json
			$ vuls-data-update dotgit find --treeish HEAD vuls-data-raw-debian-security-tracker "CVE-2025-\d+\.json"
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(_ *cobra.Command, args []string) error {
			fs, err := find.Find(args[0], args[1], find.WithTreeish(options.treeish))
			if err != nil {
				return errors.Wrap(err, "failed to dotgit find")
			}

			switch options.format {
			case formatTypePlain:
				for _, f := range fs {
					if _, err := fmt.Fprintf(os.Stdout, "%s %s %s\t%d\t%s\n", f.Mode, f.Type, f.Hash, f.Size, f.Name); err != nil {
						return errors.Wrap(err, "failed to print to stdout")
					}
				}
				return nil
			case formatTypeJSON:
				if len(fs) == 0 {
					return nil
				}

				e := json.NewEncoder(os.Stdout)
				e.SetIndent("", "  ")
				if err := e.Encode(fs); err != nil {
					return errors.Wrap(err, "failed to encode json")
				}
				return nil
			default:
				return errors.Errorf("%s is not support format", options.format)
			}
		},
	}

	cmd.Flags().StringVarP(&options.treeish, "treeish", "", options.treeish, "find in specified treeish")
	cmd.Flags().VarP(&options.format, "format", "f", "output format")
	_ = cmd.RegisterFlagCompletionFunc("format", formatTypeCompletion)

	return cmd
}

type formatType string

const (
	formatTypePlain formatType = "plain"
	formatTypeJSON  formatType = "json"
)

func (t *formatType) String() string {
	return string(*t)
}

func (t *formatType) Set(v string) error {
	switch v {
	case "plain", "json":
		*t = formatType(v)
		return nil
	default:
		return errors.Errorf("unexpected formattype. accepts: %q, actual: %q", []formatType{formatTypePlain, formatTypeJSON}, v)
	}
}

func (t *formatType) Type() string {
	return "formatType"
}

func formatTypeCompletion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return []string{string(formatTypePlain), string(formatTypeJSON)}, cobra.ShellCompDirectiveDefault
}
