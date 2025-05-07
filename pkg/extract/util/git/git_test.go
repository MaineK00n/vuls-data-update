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
				Date: func() *time.Time {
					t := time.Date(2024, time.July, 10, 23, 6, 5, 0, time.FixedZone("", 0))
					return &t
				}(),
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
