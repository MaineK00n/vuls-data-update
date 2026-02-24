package source

import (
	"testing"
)

func TestPackage_Sort(t *testing.T) {
	type fields struct {
		Name string
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
				Name: tt.fields.Name,
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
		Name string
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
			name: "accept: name, repo",
			fields: fields{
				Name: "name",
			},
			args: args{
				query: Query{
					Name:       "name",
					Repository: "repo",
				},
				repositories: []string{"repo"},
			},
			want: true,
		},
		{
			name: "accept2: name, repo",
			fields: fields{
				Name: "name",
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
			name: "not accept: name, repo",
			fields: fields{
				Name: "name",
			},
			args: args{
				query: Query{
					Name:       "name",
					Repository: "repo2",
				},
				repositories: []string{"repo"},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Package{
				Name: tt.fields.Name,
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
