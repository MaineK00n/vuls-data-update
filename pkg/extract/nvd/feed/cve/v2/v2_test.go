package v2_test

import (
	"path/filepath"
	"testing"

	"github.com/hashicorp/go-version"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cve/v2"
	ccRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	cveTypes "github.com/MaineK00n/vuls-data-update/pkg/fetch/nvd/feed/cve/v2"
)

func TestExtract(t *testing.T) {
	type args struct {
		cveDir      string
		cpematchDir string
	}
	tests := []struct {
		name     string
		args     args
		golden   string
		hasError bool
	}{
		{
			name: "semver-range",
			args: args{
				cveDir:      "./testdata/fixtures/semver-range/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/semver-range/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/semver-range",
		},
		{
			// SEMVER range whose cpematch mixes semver and non-semver versions:
			// only the non-semver versions are carried in the cpe_matches field
			// of the single CPE criterion; semver versions inside the range stay
			// covered by the criterion's range alone.
			name: "semver-range-mixed",
			args: args{
				cveDir:      "./testdata/fixtures/semver-range-mixed/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/semver-range-mixed/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/semver-range-mixed",
		},
		{
			name: "non-semver-range",
			args: args{
				cveDir:      "./testdata/fixtures/non-semver-range/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/non-semver-range/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/non-semver-range",
		},
		{
			name: "exact-match",
			args: args{
				cveDir:      "./testdata/fixtures/exact-match/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/exact-match/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/exact-match",
		},
		{
			// References carry NVD tags. The "Exploit" tag is lifted into
			// an Exploit entry (URL in Link) and the "Mitigation" tag into
			// a Mitigation entry (URL in Description); all other tags
			// ("Vendor Advisory", "Third Party Advisory", …) are dropped,
			// the reference itself being preserved untagged.
			name: "reference-tags",
			args: args{
				cveDir:      "./testdata/fixtures/reference-tags/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/reference-tags/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/reference-tags",
		},
		{
			// AND configuration with mixed vulnerable flags: one child node
			// carries vulnerable=true (the firmware that's affected), the
			// other carries vulnerable=false (the hardware guard — the
			// firmware is only vulnerable when running on this hardware).
			// Verifies that the extractor preserves both branches under
			// the AND criteria so a detector can enforce both before
			// reporting a hit.
			name: "and-vulnerable-mixed",
			args: args{
				cveDir:      "./testdata/fixtures/and-vulnerable-mixed/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/and-vulnerable-mixed/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/and-vulnerable-mixed",
		},
		{
			// SEMVER range whose matchCriteriaId is absent from the
			// cpematch dir (the two feeds cannot be snapshotted
			// atomically). The extractor must log slog.Warn, drop the
			// cpematch expansion, and still emit the range criterion so
			// detection of semver-parseable versions is preserved.
			name: "cpematch-missing-semver",
			args: args{
				cveDir:      "./testdata/fixtures/cpematch-missing-semver/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/cpematch-missing-semver/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			golden: "./testdata/golden/cpematch-missing-semver",
		},
		{
			// Unknown range (non-semver endpoint) whose matchCriteriaId
			// is absent from the cpematch dir. The Range alone cannot
			// be evaluated at detection time and we have no CPEMatches
			// fallback, so the extractor must fail rather than emit a
			// criterion that would be silently undetectable. The
			// operator is expected to refresh the cpematch snapshot
			// and re-run.
			name: "cpematch-missing-unknown",
			args: args{
				cveDir:      "./testdata/fixtures/cpematch-missing-unknown/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/cpematch-missing-unknown/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			hasError: true,
		},
		{
			// negate=true on a configuration object is not implemented.
			// The extractor must return an explicit error rather than
			// silently emit non-negated criteria, which would invert
			// detection semantics.
			name: "config-negate",
			args: args{
				cveDir:      "./testdata/fixtures/config-negate/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/config-negate/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			hasError: true,
		},
		{
			// The CVE ID carries path-traversal characters in its year
			// segment ("CVE-2024/../../x-0001"). data.ID is used to build
			// the output path, so the extractor must reject a malformed ID
			// rather than let it escape outputDir via filepath.Join.
			name: "malformed-id",
			args: args{
				cveDir:      "./testdata/fixtures/malformed-id/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/malformed-id/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			hasError: true,
		},
		{
			// negate=true on a node object is not implemented. Symmetric
			// with the configuration-negate case — the extractor must
			// reject negated nodes explicitly.
			name: "node-negate",
			args: args{
				cveDir:      "./testdata/fixtures/node-negate/vuls-data-raw-nvd-feed-cve-v2",
				cpematchDir: "./testdata/fixtures/node-negate/vuls-data-raw-nvd-feed-cpematch-v2",
			},
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := v2.Extract(tt.args.cveDir, tt.args.cpematchDir, v2.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case err != nil && tt.hasError:
				// error was expected and occurred, test passed
				return
			default:
				ep, err := filepath.Abs(tt.golden)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				gp, err := filepath.Abs(dir)
				if err != nil {
					t.Error("unexpected error:", err)
				}
				utiltest.Diff(t, ep, gp)
			}
		})
	}
}

func mustSemver(t *testing.T, s string) *version.Version {
	t.Helper()
	v, err := version.NewSemver(s)
	if err != nil {
		t.Fatalf("NewSemver(%q): %v", s, err)
	}
	return v
}

func TestParseRange(t *testing.T) {
	// boundsStr collapses Bounds into comparable endpoint strings ("" for nil)
	// so the table can assert without comparing *version.Version.
	type boundsStr struct{ ge, gt, le, lt string }
	str := func(b v2.Bounds) boundsStr {
		s := func(v *version.Version) string {
			if v == nil {
				return ""
			}
			return v.String()
		}
		return boundsStr{s(b.GE), s(b.GT), s(b.LE), s(b.LT)}
	}

	tests := []struct {
		name     string
		match    cveTypes.CPEMatch
		want     boundsStr
		wantType ccRangeTypes.RangeType
	}{
		{
			name:     "all empty",
			match:    cveTypes.CPEMatch{},
			want:     boundsStr{},
			wantType: ccRangeTypes.RangeTypeSEMVER,
		},
		{
			name:     "ge and lt",
			match:    cveTypes.CPEMatch{VersionStartIncluding: "1.0.0", VersionEndExcluding: "2.0.0"},
			want:     boundsStr{ge: "1.0.0", lt: "2.0.0"},
			wantType: ccRangeTypes.RangeTypeSEMVER,
		},
		{
			name:     "gt and le",
			match:    cveTypes.CPEMatch{VersionStartExcluding: "1.0.0", VersionEndIncluding: "2.0.0"},
			want:     boundsStr{gt: "1.0.0", le: "2.0.0"},
			wantType: ccRangeTypes.RangeTypeSEMVER,
		},
		{
			name:     "non-semver start downgrades to unknown",
			match:    cveTypes.CPEMatch{VersionStartIncluding: "15.1(4)m3", VersionEndExcluding: "2.0.0"},
			want:     boundsStr{},
			wantType: ccRangeTypes.RangeTypeUnknown,
		},
		{
			name:     "non-semver end downgrades to unknown",
			match:    cveTypes.CPEMatch{VersionEndExcluding: "21.4r3"},
			want:     boundsStr{},
			wantType: ccRangeTypes.RangeTypeUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotType := v2.ParseRange(tt.match)
			if gotType != tt.wantType {
				t.Fatalf("ParseRange() type = %v, want %v", gotType, tt.wantType)
			}
			if gotStr := str(got); gotStr != tt.want {
				t.Errorf("ParseRange() bounds = %+v, want %+v", gotStr, tt.want)
			}
		})
	}
}

func TestVersionInBounds(t *testing.T) {
	tests := []struct {
		name  string
		v     string
		setup func(t *testing.T) v2.Bounds
		want  bool
	}{
		{
			name:  "no bounds always in range",
			v:     "9.9.9",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{} },
			want:  true,
		},
		{
			name:  "inside ge/lt",
			v:     "1.5.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{GE: mustSemver(t, "1.0.0"), LT: mustSemver(t, "2.0.0")} },
			want:  true,
		},
		{
			name:  "equal to ge is included",
			v:     "1.0.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{GE: mustSemver(t, "1.0.0")} },
			want:  true,
		},
		{
			name:  "below ge excluded",
			v:     "0.9.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{GE: mustSemver(t, "1.0.0")} },
			want:  false,
		},
		{
			name:  "equal to lt excluded",
			v:     "2.0.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{LT: mustSemver(t, "2.0.0")} },
			want:  false,
		},
		{
			name:  "equal to gt excluded",
			v:     "1.0.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{GT: mustSemver(t, "1.0.0")} },
			want:  false,
		},
		{
			name:  "above gt included",
			v:     "1.0.1",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{GT: mustSemver(t, "1.0.0")} },
			want:  true,
		},
		{
			name:  "equal to le included",
			v:     "2.0.0",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{LE: mustSemver(t, "2.0.0")} },
			want:  true,
		},
		{
			name:  "above le excluded",
			v:     "2.0.1",
			setup: func(t *testing.T) v2.Bounds { return v2.Bounds{LE: mustSemver(t, "2.0.0")} },
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := v2.VersionInBounds(mustSemver(t, tt.v), tt.setup(t)); got != tt.want {
				t.Errorf("VersionInBounds(%q) = %v, want %v", tt.v, got, tt.want)
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
			if got := v2.UnescapeWFN(tt.in); got != tt.want {
				t.Errorf("UnescapeWFN(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
