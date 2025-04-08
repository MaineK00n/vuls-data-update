package git_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util/test/git"
)

func TestPopulateAndCommitHashes(t *testing.T) {
	type args struct {
		datapath string
	}
	tests := []struct {
		name     string
		args     args
		want     []string
		hasError bool
	}{
		{
			name: "happy",
			args: args{
				datapath: "testdata/fixtures/happy",
			},
			want: []string{
				"bbacda394f23683087d378516645b963f28b8361",
				"79fff0695d3b1a2ac666f8a941274e31494064c1",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			d, err := git.Populate(dir, tt.args.datapath)
			switch {
			case err != nil && !tt.hasError:
				t.Errorf("unexpected err: %v", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			default:
				got, err := git.CommitHashes(d)
				if err != nil {
					t.Errorf("commit hashes. err: %v", err)
				}
				if diff := cmp.Diff(tt.want, got); diff != "" {
					t.Errorf("Pull(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
