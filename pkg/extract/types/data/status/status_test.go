package status_test

import (
	"testing"

	statusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/status"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want statusTypes.Status
	}{
		{name: "empty", s: "", want: ""},
		{name: "rejected collapses onto constant", s: "Rejected", want: statusTypes.StatusRejected},
		{name: "analyzed", s: "Analyzed", want: "analyzed"},
		{name: "awaiting analysis", s: "Awaiting Analysis", want: "awaiting-analysis"},
		{name: "undergoing analysis", s: "Undergoing Analysis", want: "undergoing-analysis"},
		{name: "modified", s: "Modified", want: "modified"},
		{name: "deferred", s: "Deferred", want: "deferred"},
		{name: "received", s: "Received", want: "received"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusTypes.Normalize(tt.s); got != tt.want {
				t.Errorf("Normalize(%q) = %q, want %q", tt.s, got, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	tests := []struct {
		name string
		x, y statusTypes.Status
		want int
	}{
		{name: "equal", x: statusTypes.StatusRejected, y: statusTypes.StatusRejected, want: 0},
		{name: "empty less", x: "", y: statusTypes.StatusRejected, want: -1},
		{name: "greater", x: statusTypes.StatusWithdrawn, y: statusTypes.StatusRejected, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := statusTypes.Compare(tt.x, tt.y); got != tt.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tt.x, tt.y, got, tt.want)
			}
		})
	}
}
