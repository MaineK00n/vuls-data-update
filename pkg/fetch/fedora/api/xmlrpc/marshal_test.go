package xmlrpc_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora/api/xmlrpc"
)

func TestMarshal(t *testing.T) {
	type args struct {
		method string
		args   []interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "findBuildID(iperf3-3.14-1.fc39)",
			args: args{
				method: "findBuildID",
				args:   []interface{}{"iperf3-3.14-1.fc39"},
			},
			want: []byte("<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>findBuildID</methodName><params><param><value><string>iperf3-3.14-1.fc39</string></value></param></params></methodCall>"),
		},
		{
			name: "getBuild(mysql-8.0-3820230907003352.75741a8b)",
			args: args{
				method: "getBuild",
				args:   []interface{}{"mysql-8.0-3820230907003352.75741a8b"},
			},
			want: []byte("<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>getBuild</methodName><params><param><value><string>mysql-8.0-3820230907003352.75741a8b</string></value></param></params></methodCall>"),
		},
		{
			name: "listArchives(2284719)",
			args: args{
				method: "listArchives",
				args:   []interface{}{2284719},
			},
			want: []byte("<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>listArchives</methodName><params><param><value><int>2284719</int></value></param></params></methodCall>"),
		},
		{
			name: "listRPMs(2234486)",
			args: args{
				method: "listRPMs",
				args:   []interface{}{2234486},
			},
			want: []byte("<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>listRPMs</methodName><params><param><value><int>2234486</int></value></param></params></methodCall>"),
		},
		{
			name: "listRPMs(nil,nil,766629)",
			args: args{
				method: "listRPMs",
				args:   []interface{}{nil, nil, 766629},
			},
			want: []byte("<?xml version='1.0' encoding='UTF-8'?><methodCall><methodName>listRPMs</methodName><params><param><value><nil/></value></param><param><value><nil/></value></param><param><value><int>766629</int></value></param></params></methodCall>"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := xmlrpc.Marshal(tt.args.method, tt.args.args...)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Marshal(). (-expected +got):\n%s", diff)
			}
		})
	}
}
