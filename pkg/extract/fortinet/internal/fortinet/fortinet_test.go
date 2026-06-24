package fortinet_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/fortinet/internal/fortinet"
)

func TestYearDir(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		want    string
		wantErr bool
	}{
		{name: "2-digit year", id: "FG-IR-24-041", want: "2024"},
		{name: "legacy 3-digit year", id: "FG-IR-012-003", want: "2012"},
		{name: "missing dashes", id: "FG-IR-24", wantErr: true},
		{name: "wrong prefix", id: "XX-IR-24-041", wantErr: true},
		{name: "non-numeric year", id: "FG-IR-2x-041", wantErr: true},
		{name: "non-numeric number segment", id: "FG-IR-24-04x", wantErr: true},
		{name: "path traversal in number segment", id: "FG-IR-24-0/../x", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := fortinet.YearDir(tt.id)
			if (err != nil) != tt.wantErr {
				t.Fatalf("YearDir(%q) error = %v, wantErr %v", tt.id, err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Errorf("YearDir(%q) = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}
