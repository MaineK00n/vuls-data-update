package ecosystem_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/scope/ecosystem"
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
