package cpe

import "testing"

func TestCPE_Accept(t *testing.T) {
	type args struct {
		query Query
	}
	tests := []struct {
		name    string
		p       CPE
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "accept",
			p:    CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"),
			},
			want: true,
		},
		{
			name: "not accept",
			p:    CPE("cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"),
			args: args{
				query: Query("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"),
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.p.Accept(tt.args.query)
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
