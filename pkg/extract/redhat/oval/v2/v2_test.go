package v2_test

import (
	"path/filepath"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/oval/v2"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	type args struct {
		oval           string
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
				oval:           "./testdata/fixtures/v2",
				repository2cpe: "./testdata/fixtures/repository2cpe",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := v2.Extract(utiltest.QueryUnescapeFileTree(t, tt.args.oval), tt.args.repository2cpe, v2.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			}

			ep, err := filepath.Abs(filepath.Join("testdata", "golden"))
			if err != nil {
				t.Error("unexpected error:", err)
			}
			gp, err := filepath.Abs(dir)
			if err != nil {
				t.Error("unexpected error:", err)
			}
			utiltest.Diff(t, ep, gp)
		})
	}
}
