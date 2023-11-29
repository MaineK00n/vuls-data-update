package xmlrpc_test

import (
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora"
	"github.com/MaineK00n/vuls-data-update/pkg/fetch/fedora/xmlrpc"
)

func TestUnmarshal(t *testing.T) {
	type args struct {
		testdata string
		v        interface{}
	}

	tests := []struct {
		name    string
		args    args
		cmpopts []cmp.Option
		want    interface{}
		wantErr bool
	}{
		{
			name: "<boolean></boolean>",
			args: args{
				testdata: "<value><boolean></boolean></value>",
				v:        new(bool),
			},
			want: false,
		},
		{
			name: "<boolean>0</boolean>",
			args: args{
				testdata: "<value><boolean>0</boolean></value>",
				v:        new(bool),
			},
			want: false,
		},
		{
			name: "<boolean>1</boolean>",
			args: args{
				testdata: "<value><boolean>1</boolean></value>",
				v:        new(bool),
			},
			want: true,
		},
		{
			name: "<int></int>",
			args: args{
				testdata: "<value><int></int></value>",
				v:        new(int),
			},
			want: 0,
		},
		{
			name: "<int>1</int>",
			args: args{
				testdata: "<value><int>1</int></value>",
				v:        new(int),
			},
			want: 1,
		},
		{
			name: "<i4>1</i4>",
			args: args{
				testdata: "<value><i4>1</i4></value>",
				v:        new(int),
			},
			want: 1,
		},
		{
			name: "<double></double>",
			args: args{
				testdata: "<value><double></double></value>",
				v:        new(float64),
			},
			want: 0.0,
		},
		{
			name: "<double>1.2</double>",
			args: args{
				testdata: "<value><double>1.2</double></value>",
				v:        new(float64),
			},
			want: 1.2,
		},
		{
			name: "<double>-1.2</double>",
			args: args{
				testdata: "<value><double>-1.2</double></value>",
				v:        new(float64),
			},
			want: -1.2,
		},
		{
			name: "<string></string>",
			args: args{
				testdata: "<value><string></string></value>",
				v:        new(string),
			},
			want: "",
		},
		{
			name: "<string>test</string>",
			args: args{
				testdata: "<value><string>test</string></value>",
				v:        new(string),
			},
			want: "test",
		},
		{
			name: "<base64></base64>",
			args: args{
				testdata: "<value><base64></base64></value>",
				v:        new([]byte),
			},
			want: []byte(nil),
		},
		{
			name: "<base64>dGVzdA==</base64>",
			args: args{
				testdata: "<value><base64>dGVzdA==</base64></value>",
				v:        new(interface{}),
			},
			want: []byte("test"),
		},
		{
			name: "<base64>dGVzdA==</base64>",
			args: args{
				testdata: "<value><base64>dGVzdA==</base64></value>",
				v:        new([4]byte),
			},
			want: [4]byte{0x74, 0x65, 0x73, 0x74},
		},
		{
			name: "<base64>dGVzdA==</base64>",
			args: args{
				testdata: "<value><base64>dGVzdA==</base64></value>",
				v:        new([4]interface{}),
			},
			want: [4]interface{}{byte(0x74), byte(0x65), byte(0x73), byte(0x74)},
		},
		{
			name: "<base64>dGVzdA==</base64>",
			args: args{
				testdata: "<value><base64>dGVzdA==</base64></value>",
				v:        new([]byte),
			},
			want: []byte("test"),
		},
		{
			name: "<base64>dGVzdA==</base64>",
			args: args{
				testdata: "<value><base64>dGVzdA==</base64></value>",
				v:        new([]interface{}),
			},
			want: []interface{}{byte(0x74), byte(0x65), byte(0x73), byte(0x74)},
		},
		{
			name: "<dateTime.iso8601></dateTime.iso8601>",
			args: args{
				testdata: "<value><dateTime.iso8601></dateTime.iso8601></value>",
				v:        new(time.Time),
			},
			want: time.Time{},
		},
		{
			name: "<dateTime.iso8601>19980717T14:08:55Z</dateTime.iso8601>",
			args: args{
				testdata: "<value><dateTime.iso8601>19980717T14:08:55Z</dateTime.iso8601></value>",
				v:        new(time.Time),
			},
			want: time.Date(1998, time.July, 17, 14, 8, 55, 0, time.UTC),
		},
		{
			name: "<nil/>",
			args: args{
				testdata: "<value><nil/></value>",
				v:        new(interface{}),
			},
			want: nil,
		},
		{
			name: "<array><data></data></array>",
			args: args{
				testdata: "<value><array><data></data></array></value>",
				v:        new([]interface{}),
			},
			want: []interface{}(nil),
		},
		{
			name: "<array><data><value><int>1</int></value></data></array>",
			args: args{
				testdata: "<value><array><data><value><int>1</int></value></data></array></value>",
				v:        new([]int),
			},
			want: []int{1},
		},
		{
			name: "<array><data><value><nil/></value><value><int>1</int></value></data></array>",
			args: args{
				testdata: "<value><array><data><value><nil/></value><value><int>1</int></value></data></array></value>",
				v:        new([]*int),
			},
			want: []*int{nil, func(n int) *int { return &n }(1)},
		},
		{
			name: "<array><data><value><boolean>0</boolean></value><value><int>0</int></value><value><string>0</string></value></data></array>",
			args: args{
				testdata: "<value><array><data><value><boolean>0</boolean></value><value><int>0</int></value><value><string>0</string></value></data></array></value>",
				v:        new([]interface{}),
			},
			want: []interface{}{false, int64(0), "0"},
		},
		{
			name: "<struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct>",
			args: args{
				testdata: "<value><struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct></value>",
				v: new(struct {
					foo int
					bar string
				}),
			},
			cmpopts: []cmp.Option{cmpopts.IgnoreUnexported(struct {
				foo int
				bar string
			}{})},
			want: struct {
				foo int
				bar string
			}{},
		},
		{
			name: "<struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct>",
			args: args{
				testdata: "<value><struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct></value>",
				v: new(struct {
					Foo int    `xmlrpc:"foo"`
					Bar string `xmlrpc:"bar"`
				}),
			},
			want: struct {
				Foo int    `xmlrpc:"foo"`
				Bar string `xmlrpc:"bar"`
			}{
				Foo: 1,
				Bar: "2",
			},
		},
		{
			name: "<struct><member><name>foo</name><value><nil/></value></member><member><name>bar</name><value><string>2</string></value></member></struct>",
			args: args{
				testdata: "<value><struct><member><name>foo</name><value><nil/></value></member><member><name>bar</name><value><string>2</string></value></member></struct></value>",
				v: new(struct {
					Foo *int   `xmlrpc:"foo"`
					Bar string `xmlrpc:"bar"`
				}),
			},
			want: struct {
				Foo *int   `xmlrpc:"foo"`
				Bar string `xmlrpc:"bar"`
			}{
				Foo: nil,
				Bar: "2",
			},
		},
		{
			name: "<struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct>",
			args: args{
				testdata: "<value><struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct></value>",
				v:        new(map[string]interface{}),
			},
			want: map[string]interface{}{"foo": int64(1), "bar": "2"},
		},
		{
			name: "<struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct>",
			args: args{
				testdata: "<value><struct><member><name>foo</name><value><int>1</int></value></member><member><name>bar</name><value><string>2</string></value></member></struct></value>",
				v:        new(interface{}),
			},
			want: map[string]interface{}{"foo": int64(1), "bar": "2"},
		},
		{
			name: "findBuildID(iperf3-3.14-1.fc39)",
			args: args{
				testdata: "testdata/fixtures/findBuildID.xml",
				v:        new(int),
			},
			want: 2234486,
		},
		{
			name: "listArchives(2284719)",
			args: args{
				testdata: "testdata/fixtures/listArchives.xml",
				v: new(([]struct {
					ID int `xmlrpc:"id"`
				})),
			},
			want: []struct {
				ID int `xmlrpc:"id"`
			}{
				{ID: 766623},
				{ID: 766624},
				{ID: 766625},
				{ID: 766626},
				{ID: 766627},
				{ID: 766628},
				{ID: 766629},
			},
		},
		{
			name: "listRPMs(2234486)",
			args: args{
				testdata: "testdata/fixtures/listRPMs-rpm.xml",
				v:        new([]fedora.Package),
			},
			want: []fedora.Package{
				{
					Name:    "iperf3",
					Epoch:   nil,
					Version: "3.14",
					Release: "1.fc39",
					Arch:    "src",
				},
				{
					Name:    "iperf3-debugsource",
					Epoch:   nil,
					Version: "3.14",
					Release: "1.fc39",
					Arch:    "i686",
				},
				{
					Name:    "iperf3-debuginfo",
					Epoch:   nil,
					Version: "3.14",
					Release: "1.fc39",
					Arch:    "i686",
				},
			},
		},
		{
			name: "listRPMs(2234486)",
			args: args{
				testdata: "testdata/fixtures/listRPMs-module.xml",
				v:        new([]fedora.Package),
			},
			want: []fedora.Package{
				{
					Name:    "community-mysql",
					Epoch:   func(n int) *int { return &n }(0),
					Version: "8.0.34",
					Release: "2.module_f38+17431+1f3fdb0a",
					Arch:    "src",
				},
				{
					Name:    "community-mysql-server-debuginfo",
					Epoch:   func(n int) *int { return &n }(0),
					Version: "8.0.34",
					Release: "2.module_f38+17431+1f3fdb0a",
					Arch:    "aarch64",
				},
				{
					Name:    "community-mysql-debuginfo",
					Epoch:   func(n int) *int { return &n }(0),
					Version: "8.0.34",
					Release: "2.module_f38+17431+1f3fdb0a",
					Arch:    "aarch64",
				},
			},
		},
		{
			name: "fault",
			args: args{
				testdata: "testdata/fixtures/fault.xml",
				v:        new(interface{}),
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(tt.args.testdata)
			if _, err := os.Stat(tt.args.testdata); err == nil {
				bs, err := os.ReadFile(tt.args.testdata)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				body = bs
			}

			if err := xmlrpc.Unmarshal(body, tt.args.v); (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, reflect.ValueOf(tt.args.v).Elem().Interface(), tt.cmpopts...); diff != "" {
				t.Errorf("Unmarshal(). (-expected +got):\n%s", diff)
			}
		})
	}
}
