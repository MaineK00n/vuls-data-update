package status_test

import (
	"testing"

	statusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/status"
)

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
