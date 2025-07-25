package source

import (
	"testing"

	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestPackage_Sort(t *testing.T) {
	type fields struct {
		Name         string
		Repositories []string
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
				Name:         tt.fields.Name,
				Repositories: tt.fields.Repositories,
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
		Name         string
		Repositories []string
	}
	type args struct {
		family ecosystemTypes.Ecosystem
		query  Query
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
				family: ecosystemTypes.EcosystemTypeRedHat,
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
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: Query{
					Name: "name2",
				},
			},
			want: false,
		},
		{
			name: "accept: name, repo",
			fields: fields{
				Name:         "name",
				Repositories: []string{"repo"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: Query{
					Name:       "name",
					Repository: "repo",
				},
			},
			want: true,
		},
		{
			name: "accept2: name, repo",
			fields: fields{
				Name:         "name",
				Repositories: []string{"repo"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: Query{
					Name: "name",
				},
			},
			want: true,
		},
		{
			name: "not accept: name, repo",
			fields: fields{
				Name:         "name",
				Repositories: []string{"repo"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: Query{
					Name:       "name",
					Repository: "repo2",
				},
			},
			want: false,
		},
		{
			name: "debian accept: name",
			fields: fields{
				Name: "linux",
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeDebian,
				query: Query{
					Name: "linux-signed-amd64",
				},
			},
			want: true,
		},
		{
			name: "ubuntu accept: name",
			fields: fields{
				Name: "linux",
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeUbuntu,
				query: Query{
					Name: "linux-signed",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Package{
				Name:         tt.fields.Name,
				Repositories: tt.fields.Repositories,
			}
			got, err := p.Accept(tt.args.family, tt.args.query)
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
