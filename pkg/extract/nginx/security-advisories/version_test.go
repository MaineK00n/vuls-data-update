package securityadvisories

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseVulnerable(t *testing.T) {
	type args struct {
		s string
	}
	tests := []struct {
		name     string
		args     args
		want     vulnerableRange
		hasError bool
	}{
		{
			name: "range",
			args: args{s: "0.9.6-1.31.2"},
			want: vulnerableRange{Lower: version{0, 9, 6}, Upper: version{1, 31, 2}},
		},
		{
			name: "single release",
			args: args{s: "1.26.0"},
			want: vulnerableRange{Lower: version{1, 26, 0}, Upper: version{1, 26, 0}},
		},
		{
			name: "all",
			args: args{s: "all"},
			want: vulnerableRange{All: true},
		},
		{
			name: "windows only",
			args: args{s: "nginx/Windows 0.7.52-1.3.0"},
			want: vulnerableRange{Windows: true, Lower: version{0, 7, 52}, Upper: version{1, 3, 0}},
		},
		{
			name:     "reversed bounds",
			args:     args{s: "1.31.2-0.9.6"},
			hasError: true,
		},
		{
			name:     "two component version",
			args:     args{s: "1.31-1.32"},
			hasError: true,
		},
		{
			name:     "unknown platform prefix",
			args:     args{s: "nginx/Darwin 1.0.0-1.0.1"},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseVulnerable(tt.args.s)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			default:
				if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(version{})); diff != "" {
					t.Errorf("parseVulnerable(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func TestParseNotVulnerable(t *testing.T) {
	type args struct {
		ss []string
	}
	tests := []struct {
		name     string
		args     args
		want     []version
		hasError bool
	}{
		{
			name: "sorted ascending",
			args: args{ss: []string{"1.31.3+", "1.30.4+"}},
			want: []version{{1, 30, 4}, {1, 31, 3}},
		},
		{
			name: "three branches",
			args: args{ss: []string{"1.5.0+", "1.4.1+", "1.2.9+"}},
			want: []version{{1, 2, 9}, {1, 4, 1}, {1, 5, 0}},
		},
		{
			name: "none",
			args: args{ss: []string{"none"}},
			want: nil,
		},
		{
			name:     "missing plus",
			args:     args{ss: []string{"1.31.3"}},
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseNotVulnerable(tt.args.ss)
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				return
			default:
				if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(version{})); diff != "" {
					t.Errorf("parseNotVulnerable(). (-expected +got):\n%s", diff)
				}
			}
		})
	}
}

func TestAffectedIntervals(t *testing.T) {
	v := func(major, minor, patch int) *version {
		return &version{major, minor, patch}
	}

	type args struct {
		r     vulnerableRange
		fixes []version
	}
	tests := []struct {
		name string
		args args
		want []interval
	}{
		{
			// CVE-2026-42533: the stable fix 1.30.4 sits inside the stated
			// range, so the range must not be emitted verbatim.
			name: "fix inside the range splits it",
			args: args{
				r:     vulnerableRange{Lower: version{0, 9, 6}, Upper: version{1, 31, 2}},
				fixes: []version{{1, 30, 4}, {1, 31, 3}},
			},
			want: []interval{
				{GreaterEqual: version{0, 9, 6}, LessThan: v(1, 30, 4), Fixed: v(1, 30, 4)},
				{GreaterEqual: version{1, 31, 0}, LessEqual: v(1, 31, 2), Fixed: v(1, 31, 3)},
			},
		},
		{
			// CVE-2011-4963, which NVD publishes as 0.7.52 <= v < 1.2.1 plus
			// the single release 1.3.0.
			name: "trailing interval is a single release",
			args: args{
				r:     vulnerableRange{Windows: true, Lower: version{0, 7, 52}, Upper: version{1, 3, 0}},
				fixes: []version{{1, 2, 1}, {1, 3, 1}},
			},
			want: []interval{
				{GreaterEqual: version{0, 7, 52}, LessThan: v(1, 2, 1), Fixed: v(1, 2, 1)},
				{GreaterEqual: version{1, 3, 0}, LessEqual: v(1, 3, 0), Fixed: v(1, 3, 1)},
			},
		},
		{
			// CVE-2013-2070 states its ranges pre-split, so every fix falls
			// outside and nothing more is cut.
			name: "fixes above the range leave it whole",
			args: args{
				r:     vulnerableRange{Lower: version{1, 1, 4}, Upper: version{1, 2, 8}},
				fixes: []version{{1, 2, 9}, {1, 4, 1}, {1, 5, 0}},
			},
			want: []interval{
				{GreaterEqual: version{1, 1, 4}, LessEqual: v(1, 2, 8), Fixed: v(1, 2, 9)},
			},
		},
		{
			// CVE-2024-32760's "1.26.0" entry: the nearest upgrade target is
			// on another branch than the affected release.
			name: "single release with the fix on another branch",
			args: args{
				r:     vulnerableRange{Lower: version{1, 26, 0}, Upper: version{1, 26, 0}},
				fixes: []version{{1, 26, 1}, {1, 27, 0}},
			},
			want: []interval{
				{GreaterEqual: version{1, 26, 0}, LessEqual: v(1, 26, 0), Fixed: v(1, 26, 1)},
			},
		},
		{
			name: "no fix at all",
			args: args{
				r:     vulnerableRange{Lower: version{1, 0, 0}, Upper: version{1, 0, 5}},
				fixes: nil,
			},
			want: []interval{
				{GreaterEqual: version{1, 0, 0}, LessEqual: v(1, 0, 5)},
			},
		},
		{
			// The range ends before the branch that follows the last fix,
			// so no trailing interval is emitted.
			name: "range ends inside the fixed branch",
			args: args{
				r:     vulnerableRange{Lower: version{1, 0, 0}, Upper: version{1, 2, 5}},
				fixes: []version{{1, 2, 3}},
			},
			want: []interval{
				{GreaterEqual: version{1, 0, 0}, LessThan: v(1, 2, 3), Fixed: v(1, 2, 3)},
			},
		},
		{
			name: "all versions affected",
			args: args{r: vulnerableRange{All: true}},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := affectedIntervals(tt.args.r, tt.args.fixes)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(version{})); diff != "" {
				t.Errorf("affectedIntervals(). (-expected +got):\n%s", diff)
			}
		})
	}
}
