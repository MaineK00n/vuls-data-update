package v1_test

import (
	"path/filepath"
	"testing"

	v1 "github.com/MaineK00n/vuls-data-update/pkg/extract/redhat/oval/v1"
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
				oval:           "./testdata/fixtures",
				repository2cpe: "./testdata/fixtures",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := v1.Extract(tt.args.oval, tt.args.repository2cpe, v1.WithDir(dir))
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
