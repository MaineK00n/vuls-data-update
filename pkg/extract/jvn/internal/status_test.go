package internal_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/jvn/internal"
	statusTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/status"
)

func TestStatus(t *testing.T) {
	tests := []struct {
		name  string
		texts []string
		want  statusTypes.Status
	}{
		{
			name:  "deleted",
			texts: []string{"** 削除 ** Linux の Linux Kernel における脆弱性"},
			want:  statusTypes.StatusWithdrawn,
		},
		{
			name:  "unconfirmed",
			texts: []string{"** 未確定 ** 何らかの脆弱性"},
			want:  statusTypes.StatusUnconfirmed,
		},
		{
			name:  "unsupported",
			texts: []string{"** サポート外 ** 何らかの脆弱性"},
			want:  statusTypes.StatusUnsupported,
		},
		{
			name:  "no marker",
			texts: []string{"Linux Kernel における権限昇格の脆弱性"},
			want:  "",
		},
		{
			name:  "marker in second text",
			texts: []string{"", "** 削除 ** foo"},
			want:  statusTypes.StatusWithdrawn,
		},
		{
			name:  "first match wins",
			texts: []string{"** 未確定 ** foo", "** 削除 ** bar"},
			want:  statusTypes.StatusUnconfirmed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := internal.Status(tt.texts...); got != tt.want {
				t.Errorf("Status(%q) = %q, want %q", tt.texts, got, tt.want)
			}
		})
	}
}
