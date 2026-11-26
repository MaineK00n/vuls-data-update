package git_test

import (
	"reflect"
	"testing"
	"time"

	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
	testgit "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test/git"
)

func TestIsGitRepository(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "happy",
			args: args{
				path: "./testdata/fixtures/gitrepo",
			},
			want: true,
		},
		{
			name: "not-gitrepo",
			args: args{
				path: "./testdata/fixtures/not-gitrepo",
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.args.path
			if tt.want {
				d, err := testgit.Populate(t.TempDir(), tt.args.path)
				if err != nil {
					t.Errorf("Populate() error = %v", err)
					return
				}
				dir = d
			}

			if got := git.IsGitRepository(dir); got != tt.want {
				t.Errorf("IsGitRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetOrigin(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				path: "./testdata/fixtures/gitrepo",
			},
			want: "https://github.com/MaineK00n/vuls-data-update-utilgit.git",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := testgit.Populate(t.TempDir(), tt.args.path)
			if err != nil {
				t.Errorf("Populate() error = %v", err)
				return
			}

			got, err := git.GetOrigin(d)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetOrigin() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetOrigin() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDataSourceRepository(t *testing.T) {
	type args struct {
		path string
	}
	tests := []struct {
		name    string
		args    args
		want    *repositoryTypes.Repository
		wantErr bool
	}{
		{
			name: "happy",
			args: args{
				path: "./testdata/fixtures/gitrepo",
			},
			want: &repositoryTypes.Repository{
				URL:    "https://github.com/MaineK00n/vuls-data-update-utilgit.git",
				Commit: "7117b194f33f56922f428afe979a4e5bec1cace8",
				Date:   new(time.Date(2024, time.July, 10, 23, 6, 5, 0, time.FixedZone("", 0))),
			},
		},
		{
			name: "commit naming its build",
			args: args{
				path: "./testdata/fixtures/gitrepo-builds",
			},
			want: &repositoryTypes.Repository{
				URL:    "ghcr.io/vulsio/vuls-data-db:vuls-data-raw-cisa-kev",
				Commit: "a30bfdf790f34c4e842805f5c7d47e23abcc132f",
				Date:   new(time.Date(2026, time.November, 26, 3, 0, 0, 0, time.FixedZone("", 0))),
				Builds: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d, err := testgit.Populate(t.TempDir(), tt.args.path)
			if err != nil {
				t.Errorf("Populate() error = %v", err)
				return
			}

			got, err := git.GetDataSourceRepository(d)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetDataSourceRepository() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetDataSourceRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetExtractedRepository(t *testing.T) {
	type args struct {
		path     string
		populate bool
	}
	tests := []struct {
		name string
		args args
		want *repositoryTypes.Repository
	}{
		{
			name: "git repository with an origin",
			args: args{
				path:     "./testdata/fixtures/gitrepo",
				populate: true,
			},
			want: &repositoryTypes.Repository{
				URL:    "https://github.com/MaineK00n/vuls-data-update-utilgit.git",
				Builds: []string{"vuls-data-update (devel)"},
			},
		},
		{
			name: "plain directory",
			args: args{
				path: "./testdata/fixtures/not-gitrepo",
			},
			want: &repositoryTypes.Repository{
				Builds: []string{"vuls-data-update (devel)"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := tt.args.path
			if tt.args.populate {
				d, err := testgit.Populate(t.TempDir(), tt.args.path)
				if err != nil {
					t.Errorf("Populate() error = %v", err)
					return
				}
				dir = d
			}

			if got := git.GetExtractedRepository(dir); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetExtractedRepository() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuilds(t *testing.T) {
	type args struct {
		message string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "commit action",
			args: args{
				message: "update\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/45586483783/job/139109288093\n\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\nGo-Version: go1.27.3\n",
			},
			want: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"},
		},
		{
			name: "dated subject, no trailing newline",
			args: args{
				message: "update 2026-11-25\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/1/job/2\n\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\nGo-Version: go1.27.3",
			},
			want: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"},
		},
		{
			name: "before the builds were named",
			args: args{
				message: "update\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/26593707876/job/78358934704\n",
			},
		},
		{
			name: "another program",
			args: args{
				message: "update\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/1/job/2\n\nFilter-Vuls-Data-Extracted-Redhat: v0.0.0-20261118010337-fe489607c702\nGo-Version: go1.27.3\n",
			},
		},
		{
			name: "key in another case, space before the colon, blank lines around",
			args: args{
				message: "update\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/1/job/2\n \t\nvuls-data-update : v0.0.0-20261126020019-9f06544f77cb\n\n\n",
			},
			want: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb"},
		},
		{
			name: "folded value",
			args: args{
				message: "update\n\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\n  +dirty\nGo-Version: go1.27.3\n",
			},
			want: []string{"vuls-data-update v0.0.0-20261126020019-9f06544f77cb +dirty"},
		},
		{
			name: "two builds, in order",
			args: args{
				message: "update\n\nVuls-Data-Update: v0.0.0-20261125085959-d8e2902426da\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\n",
			},
			want: []string{"vuls-data-update v0.0.0-20261125085959-d8e2902426da", "vuls-data-update v0.0.0-20261126020019-9f06544f77cb"},
		},
		{
			name: "last paragraph not all trailers",
			args: args{
				message: "update\n\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\nfetched by hand\n",
			},
		},
		{
			name: "trailers in an earlier paragraph only",
			args: args{
				message: "update\n\nVuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\n\nGitHub Actions: https://github.com/vulsio/vuls-data-db/actions/runs/1/job/2\n",
			},
		},
		{
			name: "subject alone",
			args: args{
				message: "Vuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\n",
			},
		},
		{
			name: "empty value",
			args: args{
				message: "update\n\nVuls-Data-Update:\nGo-Version: go1.27.3\n",
			},
		},
		{
			name: "paragraph opening with a continuation",
			args: args{
				message: "update\n\n Vuls-Data-Update: v0.0.0-20261126020019-9f06544f77cb\n",
			},
		},
		{
			name: "empty message",
			args: args{
				message: "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := git.Builds(tt.args.message); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Builds() = %q, want %q", got, tt.want)
			}
		})
	}
}
