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

	attackTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/attack"
	capecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/capec"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cpe"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/cwe"
	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	datasourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource"
	eolTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/eol"
	windowskbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/windowskb"
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
			case "datasource.json":
				var want, got datasourceTypes.DataSource
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "data":
				var want, got dataTypes.Data
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "cpe":
				var want, got cpeTypes.CPE
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "cwe":
				var want, got cweTypes.CWE
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "capec":
				var want, got capecTypes.CAPEC
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "attack":
				var want, got attackTypes.Attack
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "windowskb":
				var want, got windowskbTypes.WindowsKB
				if err := json.NewDecoder(ef).Decode(&want); err != nil {
					return err
				}
				if err := json.NewDecoder(gf).Decode(&got); err != nil {
					return err
				}
				diff = cmp.Diff(want, got)
			case "eol":
				var want, got map[string]eolTypes.EOL
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

// QueryUnescapeFileTree copies a file tree at "from" to <temp-dir>/"to" by query-unscapeing file names.
// It returns <temp-dir>/"to".
func QueryUnescapeFileTree(t *testing.T, from, to string) string {
	toPath := filepath.Join(t.TempDir(), to)
	if err := os.Mkdir(toPath, fs.ModePerm); err != nil {
		t.Error("mkdir error:", err)
	}

	if err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(from, path)
		if err != nil {
			return err
		}
		unescaped, err := url.QueryUnescape(rel)
		if err != nil {
			return err
		}

		targetDir := filepath.Join(toPath, filepath.Dir(unescaped))
		if err := os.MkdirAll(targetDir, fs.ModePerm); err != nil {
			return err
		}
		if err := os.Link(path, filepath.Join(toPath, unescaped)); err != nil {
			return err
		}

		return nil
	}); err != nil {
		t.Error("query unscape tree", err)
	}

	return toPath
}
