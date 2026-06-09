package v2

import (
	"testing"

	"github.com/hashicorp/go-version"

	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

func mustSemver(t *testing.T, s string) *version.Version {
	t.Helper()
	v, err := version.NewSemver(s)
	if err != nil {
		t.Fatalf("NewSemver(%q): %v", s, err)
	}
	return v
}

func TestParseSemverBounds(t *testing.T) {
	// boundsStr collapses semverBounds into comparable endpoint strings
	// ("" for nil) so the table can assert without comparing *version.Version.
	type boundsStr struct{ ge, gt, le, lt string }
	str := func(b semverBounds) boundsStr {
		s := func(v *version.Version) string {
			if v == nil {
				return ""
			}
			return v.String()
		}
		return boundsStr{s(b.ge), s(b.gt), s(b.le), s(b.lt)}
	}

	tests := []struct {
		name   string
		match  cveTypes.CPEMatch
		want   boundsStr
		wantOK bool
	}{
		{
			name:   "all empty",
			match:  cveTypes.CPEMatch{},
			want:   boundsStr{},
			wantOK: true,
		},
		{
			name:   "ge and lt",
			match:  cveTypes.CPEMatch{VersionStartIncluding: "1.0.0", VersionEndExcluding: "2.0.0"},
			want:   boundsStr{ge: "1.0.0", lt: "2.0.0"},
			wantOK: true,
		},
		{
			name:   "gt and le",
			match:  cveTypes.CPEMatch{VersionStartExcluding: "1.0.0", VersionEndIncluding: "2.0.0"},
			want:   boundsStr{gt: "1.0.0", le: "2.0.0"},
			wantOK: true,
		},
		{
			name:   "non-semver start downgrades to not-ok",
			match:  cveTypes.CPEMatch{VersionStartIncluding: "15.1(4)m3", VersionEndExcluding: "2.0.0"},
			want:   boundsStr{},
			wantOK: false,
		},
		{
			name:   "non-semver end downgrades to not-ok",
			match:  cveTypes.CPEMatch{VersionEndExcluding: "21.4r3"},
			want:   boundsStr{},
			wantOK: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseSemverBounds(tt.match)
			if ok != tt.wantOK {
				t.Fatalf("parseSemverBounds() ok = %v, want %v", ok, tt.wantOK)
			}
			if gotStr := str(got); gotStr != tt.want {
				t.Errorf("parseSemverBounds() bounds = %+v, want %+v", gotStr, tt.want)
			}
		})
	}
}

func TestVersionInBounds(t *testing.T) {
	tests := []struct {
		name  string
		v     string
		setup func(t *testing.T) semverBounds
		want  bool
	}{
		{
			name:  "no bounds always in range",
			v:     "9.9.9",
			setup: func(t *testing.T) semverBounds { return semverBounds{} },
			want:  true,
		},
		{
			name:  "inside ge/lt",
			v:     "1.5.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{ge: mustSemver(t, "1.0.0"), lt: mustSemver(t, "2.0.0")} },
			want:  true,
		},
		{
			name:  "equal to ge is included",
			v:     "1.0.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{ge: mustSemver(t, "1.0.0")} },
			want:  true,
		},
		{
			name:  "below ge excluded",
			v:     "0.9.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{ge: mustSemver(t, "1.0.0")} },
			want:  false,
		},
		{
			name:  "equal to lt excluded",
			v:     "2.0.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{lt: mustSemver(t, "2.0.0")} },
			want:  false,
		},
		{
			name:  "equal to gt excluded",
			v:     "1.0.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{gt: mustSemver(t, "1.0.0")} },
			want:  false,
		},
		{
			name:  "above gt included",
			v:     "1.0.1",
			setup: func(t *testing.T) semverBounds { return semverBounds{gt: mustSemver(t, "1.0.0")} },
			want:  true,
		},
		{
			name:  "equal to le included",
			v:     "2.0.0",
			setup: func(t *testing.T) semverBounds { return semverBounds{le: mustSemver(t, "2.0.0")} },
			want:  true,
		},
		{
			name:  "above le excluded",
			v:     "2.0.1",
			setup: func(t *testing.T) semverBounds { return semverBounds{le: mustSemver(t, "2.0.0")} },
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := versionInBounds(mustSemver(t, tt.v), tt.setup(t)); got != tt.want {
				t.Errorf("versionInBounds(%q) = %v, want %v", tt.v, got, tt.want)
			}
		})
	}
}

func TestUnescapeWFN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "escaped dots", in: `7\.1\.2`, want: "7.1.2"},
		{name: "no escaping", in: "7.1.2", want: "7.1.2"},
		{name: "escaped colon", in: `a\:b`, want: "a:b"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeWFN(tt.in); got != tt.want {
				t.Errorf("unescapeWFN(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
