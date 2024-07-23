package git_test

import (
	"reflect"
	"testing"
	"time"

	repositoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/datasource/repository"
	"github.com/MaineK00n/vuls-data-update/pkg/extract/util/git"
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
			if got := git.IsGitRepository(tt.args.path); got != tt.want {
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
			got, err := git.GetOrigin(tt.args.path)
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
				Commit: "9fc1fc1f19c2f70661248ab4be66f6aeb79376a5",
				Date: func() *time.Time {
					t := time.Date(2024, time.July, 11, 8, 6, 5, 0, time.FixedZone("", 9*60*60))
					return &t
				}(),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := git.GetDataSourceRepository(tt.args.path)
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
