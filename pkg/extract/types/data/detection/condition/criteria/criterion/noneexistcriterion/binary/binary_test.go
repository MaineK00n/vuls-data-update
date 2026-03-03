package binary

import (
	"testing"
)

func TestPackage_Sort(t *testing.T) {
	type fields struct {
		Name          string
		Architectures []string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Package{
				Name:          tt.fields.Name,
				Architectures: tt.fields.Architectures,
			}
			p.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x Package
		y Package
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackage_Accept(t *testing.T) {
	type fields struct {
		Name          string
		Architectures []string
	}
	type args struct {
		query        Query
		repositories []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "accept: name",
			fields: fields{
				Name: "name",
			},
			args: args{
				query: Query{
					Name: "name",
				},
			},
			want: true,
		},
		{
			name: "not accept: name",
			fields: fields{
				Name: "name",
			},
			args: args{
				query: Query{
					Name: "name2",
				},
			},
			want: false,
		},
		{
			name: "accept: name, arch",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name: "name",
					Arch: "x86_64",
				},
			},
			want: true,
		},
		{
			name: "accept2: name, arch",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name: "name",
				},
			},
			want: true,
		},
		{
			name: "not accept: name, arch",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name: "name",
					Arch: "aarch64",
				},
			},
			want: false,
		},
		{
			name: "accept: name, arch, repo",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name:         "name",
					Arch:         "x86_64",
					Repositories: []string{"repo"},
				},
				repositories: []string{"repo"},
			},
			want: true,
		},
		{
			name: "accept2: name, arch, repo",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name: "name",
				},
				repositories: []string{"repo"},
			},
			want: true,
		},
		{
			name: "not accept: name, arch, repo",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name:         "name",
					Arch:         "x86_64",
					Repositories: []string{"repo2"},
				},
				repositories: []string{"repo"},
			},
			want: false,
		},
		{
			name: "accept: intersection of multiple repos",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name:         "name",
					Arch:         "x86_64",
					Repositories: []string{"repo1", "repo2"},
				},
				repositories: []string{"repo2", "repo3"},
			},
			want: true,
		},
		{
			name: "not accept: no intersection of multiple repos",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name:         "name",
					Arch:         "x86_64",
					Repositories: []string{"repo1", "repo2"},
				},
				repositories: []string{"repo3", "repo4"},
			},
			want: false,
		},
		{
			name: "accept: query repos empty, condition repos set",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name: "name",
					Arch: "x86_64",
				},
				repositories: []string{"repo1"},
			},
			want: true,
		},
		{
			name: "accept: query repos set, condition repos empty",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
			},
			args: args{
				query: Query{
					Name:         "name",
					Arch:         "x86_64",
					Repositories: []string{"repo1"},
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Package{
				Name:          tt.fields.Name,
				Architectures: tt.fields.Architectures,
			}
			got, err := p.Accept(tt.args.query, tt.args.repositories)
			if (err != nil) != tt.wantErr {
				t.Errorf("Package.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Package.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
