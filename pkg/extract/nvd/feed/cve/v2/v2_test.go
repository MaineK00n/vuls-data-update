package v2_test

import (
	"path/filepath"
	"testing"

	v2 "github.com/MaineK00n/vuls-data-update/pkg/extract/nvd/feed/cve/v2"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
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
