package filepath_test

import (
	"testing"

	utilfilepath "github.com/MaineK00n/vuls-data-update/pkg/extract/util/filepath"
)

func TestJoin(t *testing.T) {
	type args struct {
		root  string
		elems []string
	}
	tests := []struct {
		name     string
		args     args
		want     string
		hasError bool
	}{
		{
			name: "happy",
			args: args{root: "/d", elems: []string{"2024", "CVE-2024-6923.json"}},
			want: "/d/2024/CVE-2024-6923.json",
		},
		{
			name: "relative root",
			args: args{root: "d", elems: []string{"2024", "CVE-2024-6923.json"}},
			want: "d/2024/CVE-2024-6923.json",
		},
		{
			name: "no elems",
			args: args{root: "/d"},
			want: "/d",
		},
		{
			name: "empty elem",
			args: args{root: "/d", elems: []string{"", "CVE-2024-6923.json"}},
			want: "/d/CVE-2024-6923.json",
		},
		{
			// cleans back inside, so it is not an escape
			name: "parent inside the root",
			args: args{root: "/d", elems: []string{"2024", "x/../CVE-2024-6923.json"}},
			want: "/d/2024/CVE-2024-6923.json",
		},
		{
			// an ID carrying .. reaches Join as one element
			name:     "id escapes the root",
			args:     args{root: "/d/e/f", elems: []string{"2024", "CVE-2024-../../../../../../tmp/pwned.json"}},
			hasError: true,
		},
		{
			// a shorter climb lands back on the root itself. Join is about
			// the root, so this is allowed: which directory under it an ID
			// belongs in is the caller's grammar, not Join's
			name: "id escapes the year but not the root",
			args: args{root: "/d", elems: []string{"2024", "CVE-2024-../../../outside.json"}},
			want: "/d/outside.json",
		},
		{
			name:     "elem is absolute",
			args:     args{root: "/d", elems: []string{"2024", "/etc/passwd"}},
			want:     "/d/2024/etc/passwd",
			hasError: false,
		},
		{
			name:     "elem is the parent itself",
			args:     args{root: "/d", elems: []string{".."}},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := utilfilepath.Join(tt.args.root, tt.args.elems...)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err == nil:
				if got != tt.want {
					t.Errorf("Join() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
