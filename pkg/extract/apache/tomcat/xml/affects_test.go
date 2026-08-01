package xml

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func Test_parseAffects(t *testing.T) {
	type want struct {
		affected []affected
		unknown  []string
	}
	tests := []struct {
		name string
		args string
		want want
	}{
		{
			name: "lower to upper",
			args: "11.0.0-M1 to 11.0.23",
			want: want{affected: []affected{{GreaterEqual: "11.0.0-M1", LessEqual: "11.0.23"}}},
		},
		{
			name: "dotted milestone is normalized to the hyphenated spelling",
			args: "9.0.0.M1 to 9.0.80",
			want: want{affected: []affected{{GreaterEqual: "9.0.0-M1", LessEqual: "9.0.80"}}},
		},
		{
			name: "dotted release candidate is normalized too",
			args: "8.0.0.RC1 to 8.0.3",
			want: want{affected: []affected{{GreaterEqual: "8.0.0-RC1", LessEqual: "8.0.3"}}},
		},
		{
			name: "comma separated list of dash ranges and singles",
			args: "3.0, 3.1-3.1.1, 3.2-3.2.4, 3.3a-3.3.2",
			want: want{affected: []affected{
				{Equal: "3.0"},
				{GreaterEqual: "3.1", LessEqual: "3.1.1"},
				{GreaterEqual: "3.2", LessEqual: "3.2.4"},
				{GreaterEqual: "3.3a", LessEqual: "3.3.2"},
			}},
		},
		{
			name: "unverified marker is dropped from either bound",
			args: "3.2?, 3.2.1, 3.2.2-3.2.3?",
			want: want{affected: []affected{
				{Equal: "3.2"},
				{Equal: "3.2.1"},
				{GreaterEqual: "3.2.2", LessEqual: "3.2.3"},
			}},
		},
		{
			name: "open lower bound",
			args: "All versions prior to 1.2.3",
			want: want{affected: []affected{{LessEqual: "1.2.3"}}},
		},
		{
			name: "pre-release builds assert no released range",
			args: "Pre-release builds of 4.0.0",
			want: want{},
		},
		{
			name: "product prefix and platform qualifier are stripped",
			args: "JK 1.2.0-1.2.26 (mod_jk on Unix like platforms only)",
			want: want{affected: []affected{{GreaterEqual: "1.2.0", LessEqual: "1.2.26"}}},
		},
		{
			name: `"and" separates ranges but not inside a qualifier`,
			args: "1.3.0 to 1.3.6 and 2.0.0 to 2.0.13",
			want: want{affected: []affected{
				{GreaterEqual: "1.3.0", LessEqual: "1.3.6"},
				{GreaterEqual: "2.0.0", LessEqual: "2.0.13"},
			}},
		},
		{
			name: `"and" inside a qualifier stays with its range`,
			args: "4.0.0-4.0.6 (DataSource and JDBC Realms)",
			want: want{affected: []affected{{GreaterEqual: "4.0.0", LessEqual: "4.0.6"}}},
		},
		{
			name: "missing space after the colon is already trimmed by the fetcher",
			args: "3.1-3.1.1, 3.2-3.2.4",
			want: want{affected: []affected{
				{GreaterEqual: "3.1", LessEqual: "3.1.1"},
				{GreaterEqual: "3.2", LessEqual: "3.2.4"},
			}},
		},
		{
			name: "branch-only SVN placeholder is not a usable bound",
			args: "5.0.0-5.0.SVN",
			want: want{unknown: []string{"5.0.0-5.0.SVN"}},
		},
		{
			name: "downstream distributions are reported, not silently dropped",
			args: "Debian, Ubuntu and potentially other downstream distributions",
			want: want{unknown: []string{"Debian", "Ubuntu", "potentially other downstream distributions"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			as, unknown := parseAffects(tt.args)
			if diff := cmp.Diff(tt.want.affected, as); diff != "" {
				t.Errorf("parseAffects() affected. (-expected +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want.unknown, unknown); diff != "" {
				t.Errorf("parseAffects() unknown. (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_fixedVersions(t *testing.T) {
	tests := []struct {
		name string
		args string
		want []string
	}{
		{
			name: "single release",
			args: "Fixed in Apache Tomcat 11.0.24",
			want: []string{"11.0.24"},
		},
		{
			name: "a fix shipped across two maintenance lines",
			args: "Fixed in Apache Tomcat 4.1.13, 4.0.6",
			want: []string{"4.1.13", "4.0.6"},
		},
		{
			name: "component page keeps only the version, not the product number",
			args: "Fixed in Apache Tomcat JK Connector 1.2.50",
			want: []string{"1.2.50"},
		},
		{
			name: "milestone release is normalized",
			args: "Fixed in Apache Tomcat 9.0.0.M22",
			want: []string{"9.0.0-M22"},
		},
		{
			name: "branch-only SVN placeholder is not a release",
			args: "Fixed in Apache Tomcat 5.5.13, 5.0.SVN",
			want: []string{"5.5.13"},
		},
		{
			name: "a section that fixes nothing has no fixed version",
			args: "Not fixed in Apache Tomcat 3.x",
		},
		{
			name: "not-a-vulnerability section has no fixed version",
			args: "Not a vulnerability in Tomcat",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, fixedVersions(tt.args)); diff != "" {
				t.Errorf("fixedVersions(). (-expected +got):\n%s", diff)
			}
		})
	}
}
