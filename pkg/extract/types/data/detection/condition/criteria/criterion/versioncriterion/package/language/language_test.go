package language

import (
	"testing"
)

func TestPackage_Sort(t *testing.T) {
	type fields struct {
		Name          string
		Architectures []string
		Functions     []string
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
				Functions:     tt.fields.Functions,
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
		Functions     []string
	}
	type args struct {
		query Query
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
			name: "accept: name, arch, func",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
				Functions:     []string{"func"},
			},
			args: args{
				query: Query{
					Name:      "name",
					Arch:      "x86_64",
					Functions: []string{"func"},
				},
			},
			want: true,
		},
		{
			name: "accept2: name, arch, func",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
				Functions:     []string{"func1", "func3"},
			},
			args: args{
				query: Query{
					Name:      "name",
					Arch:      "x86_64",
					Functions: []string{"func2", "func3"},
				},
			},
			want: true,
		},
		{
			name: "accept3: name, arch, repo",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
				Functions:     []string{"func"},
			},
			args: args{
				query: Query{
					Name: "name",
				},
			},
			want: true,
		},
		{
			name: "not accept: name, arch, repo",
			fields: fields{
				Name:          "name",
				Architectures: []string{"x86_64"},
				Functions:     []string{"func1"},
			},
			args: args{
				query: Query{
					Name:      "name",
					Arch:      "x86_64",
					Functions: []string{"func2"},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Package{
				Name:          tt.fields.Name,
				Architectures: tt.fields.Architectures,
				Functions:     tt.fields.Functions,
			}
			got, err := p.Accept(tt.args.query)
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
