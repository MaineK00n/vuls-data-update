package flag

import (
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"
)

type Choices struct {
	Choices []string
	Value   string
}

// NewChoices represents a string flag with restricted values
func NewChoices(choices []string, def string) Choices {
	return Choices{
		Choices: choices,
		Value:   def,
	}
}

func (c *Choices) String() string {
	return c.Value
}

func (c *Choices) Set(arg string) error {
	if !slices.Contains(c.Choices, arg) {
		return fmt.Errorf("%s is not included in %s", arg, strings.Join(c.Choices, ","))
	}
	c.Value = arg
	return nil
}

func (c *Choices) Type() string {
	return "string"
}

func (c Choices) Completion(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return c.Choices, cobra.ShellCompDirectiveDefault
}
