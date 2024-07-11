package test

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types"
)

func Diff(t *testing.T, expectedAbsPath, gotAbsPath string) {
	for _, name := range []string{"datasource.json", "data", "cpe", "cwe", "capec", "attack", "windowskb", "eol"} {
		if _, err := os.Stat(filepath.Join(gotAbsPath, name)); err != nil {
			continue
		}

		if err := filepath.WalkDir(filepath.Join(gotAbsPath, name), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			_, rhs, ok := strings.Cut(path, fmt.Sprintf("%c%s", os.PathSeparator, name))
			if !ok {
				return fmt.Errorf("not found %q in path: %q", fmt.Sprintf("%c%s", os.PathSeparator, name), path)
			}

			dir, file := filepath.Split(rhs)
			ef, err := os.Open(filepath.Join(expectedAbsPath, name, dir, url.QueryEscape(file)))
			if err != nil {
				return err
			}
			defer ef.Close()

			gf, err := os.Open(path)
			if err != nil {
				return err
			}
			defer gf.Close()

			var diff string
			switch name {
			case "data":
				var want, got types.Data
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			default:
				return fmt.Errorf("unsupported type: %q", name)
			}
			if diff != "" {
				t.Errorf("Extract(). (-expected +got):\n%s", diff)
			}

			return nil
		}); err != nil {
			t.Error("walk error:", err)
		}
	}
}
