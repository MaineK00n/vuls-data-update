package nistnvd2_test

import (
	"path/filepath"
	"testing"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
	nistnvd2 "github.com/MaineK00n/vuls-data-update/pkg/extract/vulncheck/nist-nvd2"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		golden   string
		hasError bool
	}{
		{
			// vcConfigurations with two SEMVER ranges over the same product
			// and vcVulnerableCPEs enumerating versions inside them. The
			// detection criteria come from vcConfigurations only — the plain
			// NVD configurations field in the same file is ignored — and
			// every vcVulnerableCPEs entry is semver-parseable, so no
			// cpe_matches are carried (the ranges already cover them).
			name:   "happy",
			args:   "./testdata/fixtures/happy/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/happy",
		},
		{
			// vulnStatus=Deferred entry that carries vcConfigurations but no
			// plain NVD configurations — the VulnCheck enrichment NVD has
			// not analyzed. Also exercises the empty node operator (""),
			// which VulnCheck leaves unset and is treated as OR.
			name:   "vc-only",
			args:   "./testdata/fixtures/vc-only/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/vc-only",
		},
		{
			// Range endpoint "8.0_patch_34" is not semver, so the range type
			// is unknown and the product-matched vcVulnerableCPEs entries
			// are carried in cpe_matches as the detection fallback.
			name:   "non-semver-range",
			args:   "./testdata/fixtures/non-semver-range/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/non-semver-range",
		},
		{
			// Criterion without any range endpoint (version "-"): no Range
			// and no cpe_matches expansion.
			name:   "exact-match",
			args:   "./testdata/fixtures/exact-match/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/exact-match",
		},
		{
			// vulnStatus=Rejected entry without configurations: emitted as a
			// vulnerability without detections, matching extract/nvd/feed/cve/v2
			// which does not filter by vulnStatus either.
			name:   "rejected",
			args:   "./testdata/fixtures/rejected/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/rejected",
		},
		{
			// negate=true on a configuration cannot be expressed in the
			// criteria tree. Unlike extract/nvd/feed/cve/v2 this must not
			// fail the extraction (VulnCheck data is not under NVD's quality
			// control): the configuration is skipped with a WARN and the
			// entry is emitted without detections.
			name:   "config-negate",
			args:   "./testdata/fixtures/config-negate/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/config-negate",
		},
		{
			// Symmetric with config-negate: negate=true on a node drops the
			// node (and with it the only configuration) with a WARN instead
			// of failing.
			name:   "node-negate",
			args:   "./testdata/fixtures/node-negate/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/node-negate",
		},
		{
			// The CVE ID carries path-traversal characters in its year
			// segment ("CVE-2024/../../x-0001"). data.ID is used to build
			// the output path, so the extractor must reject a malformed ID
			// rather than let it escape outputDir via filepath.Join.
			name:     "malformed-id",
			args:     "./testdata/fixtures/malformed-id/vuls-data-raw-vulncheck-nist-nvd2",
			hasError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := nistnvd2.Extract(tt.args, nistnvd2.WithDir(dir))
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
