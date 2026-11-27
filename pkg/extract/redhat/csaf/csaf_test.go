package csaf_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/csaf"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	type args struct {
		csaf           string
		repository2cpe string
	}
	tests := []struct {
		name     string
		args     args
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				csaf:           "./testdata/fixtures/csaf",
				repository2cpe: "./testdata/fixtures/repository2cpe",
			},
		},
		{
			// A RHEL CPE (cpe:/{o,a}:redhat:enterprise_linux:...) that maps to
			// no major fails the extraction instead of dropping the product.
			name: "RHEL CPE without a known major errors",
			args: args{
				csaf:           "./testdata/fixtures/csaf_rhel_cpe_no_major_error",
				repository2cpe: "./testdata/fixtures/repository2cpe",
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			fixturePath, err := utiltest.QueryUnescapeFileTree(t.TempDir(), tt.args.csaf)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			err = csaf.Extract(fixturePath, tt.args.repository2cpe, csaf.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				if err := utiltest.Diff(filepath.Join("testdata", "golden"), dir); err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
