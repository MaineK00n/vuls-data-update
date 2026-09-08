package ecosystem_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestGetEcosystem(t *testing.T) {
	type args struct {
		family  string
		release string
	}
	tests := []struct {
		name    string
		args    args
		want    ecosystem.Ecosystem
		wantErr bool
	}{
		{
			name: "centos 8.0",
			args: args{
				family:  "centos",
				release: "8.0",
			},
			want: ecosystem.Ecosystem("redhat:8"),
		},
		{
			name: "oracle 9",
			args: args{
				family:  "oracle",
				release: "9",
			},
			want: ecosystem.Ecosystem("oracle:9"),
		},
		{
			name: "oracle 9.0",
			args: args{
				family:  "oracle",
				release: "9.0",
			},
			want: ecosystem.Ecosystem("oracle:9"),
		},
		{
			name: "cpe",
			args: args{
				family:  "cpe",
				release: "",
			},
			want: ecosystem.Ecosystem("cpe"),
		},
		{
			name: "solaris 10",
			args: args{
				family:  "solaris",
				release: "10",
			},
			want: ecosystem.Ecosystem("solaris:10"),
		},
		{
			name: "solaris 10 with update",
			args: args{
				family:  "solaris",
				release: "10.1",
			},
			want: ecosystem.Ecosystem("solaris:10"),
		},
		{
			name: "solaris 10 with update and trailing part",
			args: args{
				family:  "solaris",
				release: "10.11.0",
			},
			want: ecosystem.Ecosystem("solaris:10"),
		},
		{
			name: "solaris 10 with trailing dot",
			args: args{
				family:  "solaris",
				release: "10.",
			},
			wantErr: true,
		},
		{
			name: "solaris 10 with non numeric part",
			args: args{
				family:  "solaris",
				release: "10.x",
			},
			wantErr: true,
		},
		{
			name: "solaris 11.4",
			args: args{
				family:  "solaris",
				release: "11.4",
			},
			want: ecosystem.Ecosystem("solaris:11.4"),
		},
		{
			name: "solaris 11.4 with update",
			args: args{
				family:  "solaris",
				release: "11.4.1",
			},
			want: ecosystem.Ecosystem("solaris:11.4"),
		},
		{
			name: "solaris 11.3 with more parts",
			args: args{
				family:  "solaris",
				release: "11.3.36.0.1",
			},
			want: ecosystem.Ecosystem("solaris:11.3"),
		},
		{
			name: "solaris 11 without minor",
			args: args{
				family:  "solaris",
				release: "11",
			},
			wantErr: true,
		},
		{
			name: "solaris 11 with trailing dot",
			args: args{
				family:  "solaris",
				release: "11.",
			},
			wantErr: true,
		},
		{
			name: "solaris 11 with non numeric minor",
			args: args{
				family:  "solaris",
				release: "11.foo",
			},
			wantErr: true,
		},
		{
			name: "solaris 11.4 with trailing dot",
			args: args{
				family:  "solaris",
				release: "11.4.",
			},
			wantErr: true,
		},
		{
			name: "solaris non numeric release",
			args: args{
				family:  "solaris",
				release: "foo.bar",
			},
			wantErr: true,
		},
		{
			name: "solaris unknown major",
			args: args{
				family:  "solaris",
				release: "12.3",
			},
			wantErr: true,
		},
		{
			name: "solaris empty release",
			args: args{
				family:  "solaris",
				release: "",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ecosystem.GetEcosystem(tt.args.family, tt.args.release)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetEcosystem() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetEcosystem() = %v, want %v", got, tt.want)
			}
		})
	}
}
