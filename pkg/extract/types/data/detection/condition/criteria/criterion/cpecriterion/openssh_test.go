package cpecriterion_test

import (
	"testing"

	ccTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	rangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

// TestCriterion_Accept_openssh pins what the openssh range type is for: a
// portable release must be told apart from the base release it derives from,
// on either side of the query, so that the release carrying a fix is not
// reported as the vulnerability it fixes.
func TestCriterion_Accept_openssh(t *testing.T) {
	// The 2025-02-18 VerifyHostKeyDNS advisory: ssh(1) 6.8p1 to 9.9p1
	// inclusive, fixed in 9.9p2.
	c := ccTypes.Criterion{
		Vulnerable: true,
		CPE:        "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
		Range: &rangeTypes.Range{
			Type:         rangeTypes.RangeTypeOpenSSH,
			GreaterEqual: "6.8p1",
			LessEqual:    "9.9p1",
		},
	}

	tests := []struct {
		name  string
		query string
		want  ccTypes.MatchQuality
	}{
		{
			// NVD's form, which is the one that matters: the portable release
			// is in the update attribute and has to be folded back in.
			name:  "the fixed release, portable in update",
			query: "cpe:2.3:a:openbsd:openssh:9.9:p2:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
		{
			name:  "the last affected release, portable in update",
			query: "cpe:2.3:a:openbsd:openssh:9.9:p1:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityExact,
		},
		{
			// A scanner may instead carry it in the version, where there is
			// nothing to fold.
			name:  "the fixed release, portable in version",
			query: "cpe:2.3:a:openbsd:openssh:9.9p2:*:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
		{
			name:  "the last affected release, portable in version",
			query: "cpe:2.3:a:openbsd:openssh:9.9p1:*:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityExact,
		},
		{
			// The base of the upper bound: 9.9 precedes 9.9p1, so it is in.
			name:  "the base of the upper bound",
			query: "cpe:2.3:a:openbsd:openssh:9.9:*:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityExact,
		},
		{
			// And the base of the lower bound precedes it, so it is out --
			// the advisory names 6.8p1, not 6.8.
			name:  "the base of the lower bound",
			query: "cpe:2.3:a:openbsd:openssh:6.8:*:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
		{
			name:  "below the range",
			query: "cpe:2.3:a:openbsd:openssh:6.7:p1:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
		{
			// Minor segments compare numerically, so 9.10 is later than 9.9p1.
			name:  "above the range",
			query: "cpe:2.3:a:openbsd:openssh:9.10:*:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
		{
			name:  "inside the range",
			query: "cpe:2.3:a:openbsd:openssh:8.4:p1:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityExact,
		},
		{
			name:  "another product",
			query: "cpe:2.3:a:openbsd:opensmtpd:9.9:p1:*:*:*:*:*:*",
			want:  ccTypes.MatchQualityNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := c.Accept(ccTypes.Query{CPE: tt.query})
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if got != tt.want {
				t.Errorf("Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
