package main

import (
	"fmt"
	"os"

	"github.com/MaineK00n/vuls-data-update/pkg/cmd/root"
)

func main() {
	if err := root.NewCmdRoot().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", fmt.Sprintf("%+v", err))
		os.Exit(1)
	}
}
