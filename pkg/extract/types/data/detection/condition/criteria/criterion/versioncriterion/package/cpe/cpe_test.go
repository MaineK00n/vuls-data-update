package cpe

import "testing"

func TestCPE_Accept(t *testing.T) {
	type args struct {
		query Query
	}
	tests := []struct {
		name    string
		c       CPE
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "accept",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "query version wildcard against specific version",
			c:    CPE("cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "different vendor",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:other:product:0.0.1:*:*:*:*:*:*:*"),
			},
			want: false,
		},
		{
			name: "different product",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:other:0.0.1:*:*:*:*:*:*:*"),
			},
			want: false,
		},
		{
			name: "pattern has target_sw, query has wildcard",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "pattern has target_sw, query has same target_sw",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:1.0:*:*:*:*:wordpress:*:*"),
			},
			want: true,
		},
		{
			name: "pattern has target_sw, query has different target_sw",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:1.0:*:*:*:*:node.js:*:*"),
			},
			want: false,
		},
		{
			name: "pattern has sw_edition, query has wildcard",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:enterprise:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "both wildcard versions",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "both specific same version",
			c:    CPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "both specific different version",
			c:    CPE("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:2.0:*:*:*:*:*:*:*"),
			},
			want: false,
		},
		{
			name: "different part",
			c:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.c.Accept(tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("CPE.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("CPE.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
