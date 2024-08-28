package oracle_test

import (
	"encoding/json"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/oracle"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name        string
		fixturePath string
		goldenPath  string
		hasError    bool
	}{
		{
			name:        "happy",
			fixturePath: "./testdata/fixtures/happy",
			goldenPath:  "./testdata/golden/happy",
		},
		{
			name:        "modularitylabel",
			fixturePath: "./testdata/fixtures/modularitylabel",
			goldenPath:  "./testdata/golden/modularitylabel",
		},
		// Based on "modularitylabel" case, the regexp pattern of module stream is altered and others are identical
		{
			name:        "modularitylabel-stream-reversed",
			fixturePath: "./testdata/fixtures/modularitylabel-stream-reversed",
			goldenPath:  "./testdata/golden/modularitylabel-stream-reversed",
		},
		{
			name:        "majormixed",
			fixturePath: "./testdata/fixtures/majormixed",
			goldenPath:  "./testdata/golden/majormixed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Copy files under fixturePath to temp dir to convert query-escaped names to normal ones
			inputDir := t.TempDir()
			if err := filepath.WalkDir(tt.fixturePath, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() || filepath.Ext(path) != ".json" {
					return nil
				}

				targetDir := filepath.Join(inputDir, filepath.Dir(strings.TrimPrefix(path, strings.TrimPrefix(tt.fixturePath, "./"))))
				if err := os.MkdirAll(targetDir, fs.ModePerm); err != nil {
					return err
				}
				targetBase, err := url.QueryUnescape(filepath.Base(path))
				if err != nil {
					return err
				}
				if err := os.Link(path, filepath.Join(targetDir, targetBase)); err != nil {
					return err
				}

				return nil
			}); err != nil {
				t.Error("copy fixtures", err)
			}

			outputDir := t.TempDir()
			err := oracle.Extract(inputDir, oracle.WithDir(outputDir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			// Rewrite output files under "data/" to erase temp input dir prefix
			if err := filepath.WalkDir(filepath.Join(outputDir, "data"), func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() || filepath.Ext(path) != ".json" {
					return nil
				}

				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()

				var data dataTypes.Data
				if err := json.NewDecoder(f).Decode(&data); err != nil {
					return err
				}
				for i, s := range data.DataSource.Raws {
					data.DataSource.Raws[i] = strings.TrimPrefix(s, inputDir+"/")
				}
				if err := util.Write(path, data, false); err != nil {
					return err
				}

				return nil
			}); err != nil {
				t.Error("Erase output dir prefix", err)
			}

			ep, err := filepath.Abs(tt.goldenPath)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(outputDir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
