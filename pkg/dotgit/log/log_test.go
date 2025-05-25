package log_test

import (
	"iter"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/log"
	"github.com/MaineK00n/vuls-data-update/pkg/dotgit/util"
)

func TestLog(t *testing.T) {
	type args struct {
		opts []log.Option
	}
	tests := []struct {
		name    string
		dotgit  string
		args    args
		want    iter.Seq2[string, error]
		wantErr bool
	}{
		{
			name:   "log",
			dotgit: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
			args:   args{},
			want: func(yield func(string, error) bool) {
				if !yield(`commit 6e6128f16b40edf3963ebb0036a3e0a55a54d0de
Author: GitHub Actions <action@github.com>
Date:   Fri Mar 28 02:22:16 2025 +0000

    update
`, nil) {
					return
				}
				if !yield(`commit 63a30ff24dea0d2198c1e3160c33b52df66970a4
Author: GitHub Actions <action@github.com>
Date:   Wed Jan 29 12:18:24 2025 +0000

    update
`, nil) {
					return
				}
				if !yield(`commit 6c46d130ffee8d2990169f751c0ed9661da95a52
Author: GitHub Actions <action@github.com>
Date:   Thu Oct 31 00:23:18 2024 +0000

    update
`, nil) {
					return
				}
			},
		},
		{
			name:   "log -- 9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json",
			dotgit: "testdata/fixtures/vuls-data-raw-redhat-ovalv2.tar.zst",
			args: args{
				opts: []log.Option{
					log.WithPathSpecs([]string{"9/rhel-9/definitions/oval:com.redhat.rhsa:def:20249315.json"}),
				},
			},
			want: func(yield func(string, error) bool) {
				if !yield(`commit 6e6128f16b40edf3963ebb0036a3e0a55a54d0de
Author: GitHub Actions <action@github.com>
Date:   Fri Mar 28 02:22:16 2025 +0000

    update
`, nil) {
					return
				}
				if !yield(`commit 63a30ff24dea0d2198c1e3160c33b52df66970a4
Author: GitHub Actions <action@github.com>
Date:   Wed Jan 29 12:18:24 2025 +0000

    update
`, nil) {
					return
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.dotgit)
			if err != nil {
				t.Errorf("open %s. err: %v", tt.dotgit, err)
			}
			defer f.Close()

			dir := t.TempDir()
			if err := util.ExtractDotgitTarZst(f, filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst"))); err != nil {
				t.Errorf("extract %s. err: %v", tt.dotgit, err)
			}

			got, err := log.Log(filepath.Join(dir, strings.TrimSuffix(filepath.Base(tt.dotgit), ".tar.zst")), tt.args.opts...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Log() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			wnext, wstop := iter.Pull2(tt.want)
			defer wstop()
			gnext, gstop := iter.Pull2(got)
			defer gstop()

			for {
				want, wantErr, wantOk := wnext()
				if wantErr != nil {
					t.Errorf("want error: %v", wantErr)
					return
				}

				got, gotErr, gotOk := gnext()
				if gotErr != nil {
					if tt.wantErr {
						return
					}
					t.Errorf("got error: %v", gotErr)
					return
				}

				if !wantOk || !gotOk {
					if wantOk != gotOk {
						t.Errorf("want ok: %v, got ok: %v", wantOk, gotOk)
						return
					}
					break
				}

				if diff := cmp.Diff(want, got); diff != "" {
					t.Errorf("Log(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}
