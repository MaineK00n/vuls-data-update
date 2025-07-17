package contains_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/contains"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestContains(t *testing.T) {
	type args struct {
		repository string
		commit     string
		opts       []contains.Option
	}
	tests := []struct {
		name    string
		args    args
		wantErr interface{}
	}{
		{
			name: "contains full commit hash, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d486d4c9414321a2df56f2e007c4c2c8fab",
				opts:       []contains.Option{contains.WithUseNativeGit(true)},
			},
		},
		{
			name: "contains short commit hash, native git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d48",
				opts:       []contains.Option{contains.WithUseNativeGit(true)},
			},
		},
		{
			name: "contains short commit hash, go-git",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d48",
				opts:       []contains.Option{contains.WithUseNativeGit(false)},
			},
		},
		{
			name: "not contains commit hash",
			args: args{
				repository: "testdata/fixtures/vuls-data-raw-test.tar.zst",
				commit:     "9d3d5d486d4c9414321a2df56f2e007c4c2c8fac",
			},
			wantErr: func() interface{} {
				var err *contains.CommitNotFoundError
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.args.repository)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.args.repository, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.args.repository, err)
			}

			err = contains.Contains(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.args.repository), ".tar.zst")), tt.args.commit)
			switch {
			case err != nil && tt.wantErr == nil:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.wantErr != nil:
				t.Error("expected error has not occurred")
			default:
				if err != nil {
					if !errors.As(err, &tt.wantErr) {
						t.Errorf("expected error %T, but got %T", tt.wantErr, err)
					}
				}
			}
		})
	}
}
