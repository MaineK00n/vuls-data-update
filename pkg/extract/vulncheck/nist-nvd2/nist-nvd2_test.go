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
			// vcConfigurations (two SEMVER ranges) with vcVulnerableCPEs that
			// all fall inside those ranges. Because the ranges already detect
			// every concrete version, the supplement (condition 2) is empty and
			// only the configuration condition is emitted — collapsed to a
			// single flat OR of the two range criteria (the plain NVD
			// configurations field is ignored).
			name:   "happy",
			args:   "./testdata/fixtures/happy/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/happy",
		},
		{
			// Entry that carries vcConfigurations but no plain configurations:
			// the detection is still built from vcConfigurations. Also
			// exercises the empty node operator (""), which is mapped to OR.
			name:   "vc-only",
			args:   "./testdata/fixtures/vc-only/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/vc-only",
		},
		{
			// Range endpoint "8.0_patch_34" is not semver, so the
			// vcConfigurations condition's Range is typed unknown; the concrete
			// versions a Range cannot express are carried by the separate
			// vcVulnerableCPEs condition.
			name:   "non-semver-range",
			args:   "./testdata/fixtures/non-semver-range/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/non-semver-range",
		},
		{
			// Criterion without any range endpoint (version "-"): the
			// vcConfigurations condition emits the CPE with no Range.
			name:   "exact-match",
			args:   "./testdata/fixtures/exact-match/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/exact-match",
		},
		{
			// The vcVulnerableCPEs supplement condition, exercised end to end:
			// its product (sun_zfs_storage_appliance_kit, an alternate spelling)
			// is absent from vcConfigurations (zfs_storage_appliance_kit), so no
			// configuration range covers it and it is kept in condition 2. The
			// fixture adds ANY ("*") and NA ("-") versioned entries, which must
			// be skipped — only the concrete versions land in cpe_matches.
			name:   "vuln-cpes",
			args:   "./testdata/fixtures/vuln-cpes/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/vuln-cpes",
		},
		{
			// vulnStatus=Rejected entries: the vulnerability content (the
			// rejection reason) is still emitted, but detections are
			// suppressed — a rejected CVE is withdrawn, so flagging it would
			// be a false positive. Covers a hollow reject (CVE-2024-2652, no
			// vcConfigurations) and a reject that still carries
			// vcConfigurations (CVE-2022-49267), proving the latter's
			// detections are dropped.
			name:   "rejected",
			args:   "./testdata/fixtures/rejected/vuls-data-raw-vulncheck-nist-nvd2",
			golden: "./testdata/golden/rejected",
		},
		{
			// negate=true on a configuration cannot be expressed in the
			// criteria tree and never appears in the real feed, so the
			// extractor fails hard rather than silently emitting inverted
			// detection semantics.
			name:     "config-negate",
			args:     "./testdata/fixtures/config-negate/vuls-data-raw-vulncheck-nist-nvd2",
			hasError: true,
		},
		{
			// Symmetric with config-negate: negate=true on a node is a hard
			// error too.
			name:     "node-negate",
			args:     "./testdata/fixtures/node-negate/vuls-data-raw-vulncheck-nist-nvd2",
			hasError: true,
		},
		{
			// A cpeMatch whose criteria is not a CPE 2.3 formatted string is
			// a hard error rather than a skipped criterion — silently
			// dropping it would weaken the enclosing configuration into an
			// over-broad detection. Does not occur in the real feed.
			name:     "invalid-cpe",
			args:     "./testdata/fixtures/invalid-cpe/vuls-data-raw-vulncheck-nist-nvd2",
			hasError: true,
		},
		{
			// The first segment is not a valid year ("CVE-2024/../../x-0001"
			// → year segment "2024/../../x"), so time.Parse rejects it and the
			// extractor errors. (Validation matches the sibling extractors and
			// does not specifically harden the serial segment.)
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
