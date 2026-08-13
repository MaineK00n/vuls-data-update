package security_test

import (
	"path/filepath"
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/openssh/security"
	utiltest "github.com/MaineK00n/vuls-data-update/pkg/extract/util/test"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		golden   string
		hasError bool
	}{
		{
			name:   "happy",
			args:   "./testdata/fixtures/happy",
			golden: "./testdata/golden/happy",
		},
		{
			// raw/ is model-produced, so a version that is not one has to stop
			// the extract rather than pass through as an unmatchable bound.
			name:     "invalid-version",
			args:     "./testdata/fixtures/invalid-version",
			hasError: true,
		},
		{
			// Same reasoning for an annotation filed under a field nothing
			// dispatches on: dropping it would look exactly like the annotated
			// document having stated nothing.
			name:     "invalid-annotation",
			args:     "./testdata/fixtures/invalid-annotation",
			hasError: true,
		},
		{
			// And the field is checked before absent is honoured, because that
			// is the case where a misfiled annotation does its damage: an
			// absent record says the document was read and states nothing, so
			// filed where nothing looks for it, it reads as never having been
			// looked at and the next pass re-reads the document.
			name:     "absent-invalid-field",
			args:     "./testdata/fixtures/absent-invalid-field",
			hasError: true,
		},
		{
			// A CVE folded into an entry recording that no release was ever
			// vulnerable inverts what the entry says, and those entries are
			// exactly the ones linking notes about SSH at large. Marking it
			// inapplicable is the way to record such a reading, and the happy
			// fixture carries one.
			name:     "unaffected-cve-annotation",
			args:     "./testdata/fixtures/unaffected-cve-annotation",
			hasError: true,
		},
		{
			// An inapplicable annotation without the value it is about records
			// only that something did not apply, leaving the next pass to
			// re-read the document to find out what.
			name:     "inapplicable-no-value",
			args:     "./testdata/fixtures/inapplicable-no-value",
			hasError: true,
		},
		{
			// The two outcomes describe the evidence differently -- states
			// nothing versus states something that is not ours -- so a record
			// claiming both describes nothing.
			name:     "absent-and-inapplicable",
			args:     "./testdata/fixtures/absent-and-inapplicable",
			hasError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := security.Extract(tt.args, security.WithDir(dir))
			switch {
			case err != nil && !tt.hasError:
				t.Error("unexpected error:", err)
			case err == nil && tt.hasError:
				t.Error("expected error has not occurred")
			case tt.hasError:
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
