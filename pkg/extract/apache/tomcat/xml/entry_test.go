package xml

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	tomcatXML "github.com/MaineK00n/vuls-data-update/pkg/fetch/apache/tomcat/xml"
)

func ps(xs ...string) []tomcatXML.Block {
	bs := make([]tomcatXML.Block, 0, len(xs))
	for _, x := range xs {
		bs = append(bs, tomcatXML.Block{Tag: "p", XML: x})
	}
	return bs
}

func Test_entries(t *testing.T) {
	type want struct {
		entries []entry
		notes   []string
	}
	tests := []struct {
		name string
		args tomcatXML.Section
		want want
	}{
		{
			name: "an entry runs from its header to the next one",
			args: tomcatXML.Section{
				Name: "Fixed in Apache Tomcat 11.0.24",
				Blocks: ps(
					`<strong>Low: EncryptInterceptor requirements not clearly
       documented</strong>
       <cve>CVE-2026-59084</cve>`,
					`The requirements were not clearly documented.`,
					`This was fixed with commit
       <hashlink hash="57e80e9b"/>.`,
					`Affects: 11.0.0-M1 to 11.0.23`,
					`<strong>Low: Second issue</strong> <cve>CVE-2026-59083</cve>`,
					`Affects: 11.0.0-M1 to 11.0.23`,
				),
			},
			want: want{entries: []entry{
				{
					CVEs:     []string{"CVE-2026-59084"},
					Severity: "Low",
					// The source hard-wraps prose; its newlines are not content.
					Title:       "EncryptInterceptor requirements not clearly documented",
					Affects:     "11.0.0-M1 to 11.0.23",
					Description: []string{"The requirements were not clearly documented.", "This was fixed with commit 57e80e9b."},
					Commits:     []string{"57e80e9b"},
				},
				{
					CVEs:     []string{"CVE-2026-59083"},
					Severity: "Low",
					Title:    "Second issue",
					Affects:  "11.0.0-M1 to 11.0.23",
				},
			}},
		},
		{
			name: "a CVE quoted inside the title is not one of the entry's own",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>Important: The fix for <cve>CVE-2026-29146</cve> allowed the
       bypass of the EncryptInterceptor</strong>
       <cve>CVE-2026-34486</cve>`,
			)},
			want: want{entries: []entry{{
				CVEs:     []string{"CVE-2026-34486"},
				Severity: "Important",
				Title:    "The fix for CVE-2026-29146 allowed the bypass of the EncryptInterceptor",
			}}},
		},
		{
			name: "a legacy entry links its CVE with a plain anchor",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>Moderate: Multiple weaknesses in HTTP DIGEST authentication</strong>
       <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-1184"
       rel="nofollow">CVE-2011-1184</a>`,
			)},
			want: want{entries: []entry{{
				CVEs:     []string{"CVE-2011-1184"},
				Severity: "Moderate",
				Title:    "Multiple weaknesses in HTTP DIGEST authentication",
			}}},
		},
		{
			name: "a <strong> block carrying no CVE is prose, not a header",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>Note: The issue below was fixed in 6.0.34 but the release vote did not pass.</strong>`,
				`<strong>Low: Real issue</strong> <cve>CVE-2011-0001</cve>`,
				`<strong>Note: All of conditions above must be true.</strong>`,
			)},
			want: want{
				entries: []entry{{
					CVEs:        []string{"CVE-2011-0001"},
					Severity:    "Low",
					Title:       "Real issue",
					Description: []string{"Note: All of conditions above must be true."},
				}},
				notes: []string{"Note: The issue below was fixed in 6.0.34 but the release vote did not pass."},
			},
		},
		{
			name: "list items and a mistyped <o> paragraph are description lines",
			args: tomcatXML.Section{Blocks: []tomcatXML.Block{
				{Tag: "p", XML: `<strong>Important: RCE</strong> <cve>CVE-2020-9484</cve>`},
				{Tag: "p", XML: `If:`},
				{Tag: "ul", XML: `<li>an attacker controls a file; and</li><li>the server uses the PersistenceManager</li>`},
				{Tag: "o", XML: `Applications that do not use non-blocking I/O are not exposed.`},
			}},
			want: want{entries: []entry{{
				CVEs:     []string{"CVE-2020-9484"},
				Severity: "Important",
				Title:    "RCE",
				Description: []string{
					"If:",
					"an attacker controls a file; and",
					"the server uses the PersistenceManager",
					"Applications that do not use non-blocking I/O are not exposed.",
				},
			}}},
		},
		{
			name: "prose after a <br/> on the Affects line is not part of the range",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>Low: DoS</strong> <cve>CVE-2026-66299</cve>`,
				`Affects: 11.0.0-M20 to 11.0.24<br/>
       Users who followed the security guidance to remove the examples web
       application are not affected.`,
			)},
			want: want{entries: []entry{{
				CVEs:        []string{"CVE-2026-66299"},
				Severity:    "Low",
				Title:       "DoS",
				Affects:     "11.0.0-M20 to 11.0.24",
				Description: []string{"Users who followed the security guidance to remove the examples web application are not affected."},
			}}},
		},
		{
			name: "a header with no severity rating keeps the whole title",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>JavaMail information disclosure</strong> <cve>CVE-2026-33333</cve>`,
			)},
			want: want{entries: []entry{{
				CVEs:  []string{"CVE-2026-33333"},
				Title: "JavaMail information disclosure",
			}}},
		},
		{
			name: "connector commits are kept apart from tomcat commits",
			args: tomcatXML.Section{Blocks: ps(
				`<strong>Low: Incorrect default permissions</strong> <cve>CVE-2024-46544</cve>`,
				`This was fixed with commit <connectorshashlink hash="d55706e9"/>.`,
			)},
			want: want{entries: []entry{{
				CVEs:             []string{"CVE-2024-46544"},
				Severity:         "Low",
				Title:            "Incorrect default permissions",
				Description:      []string{"This was fixed with commit d55706e9."},
				ConnectorCommits: []string{"d55706e9"},
			}}},
		},
		{
			name: "the page preamble holds no entry",
			args: tomcatXML.Section{
				Name:   "Apache Tomcat 11.x vulnerabilities",
				Blocks: ps(`This page lists all security vulnerabilities fixed in released versions.`),
			},
			want: want{notes: []string{"This page lists all security vulnerabilities fixed in released versions."}},
		},
		{
			name: "the table of contents holds nothing at all",
			args: tomcatXML.Section{Name: "Table of Contents", Blocks: []tomcatXML.Block{{Tag: "toc"}}},
			want: want{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			es, notes, err := entries(tt.args)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if diff := cmp.Diff(tt.want.entries, es); diff != "" {
				t.Errorf("entries(). (-expected +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.want.notes, notes); diff != "" {
				t.Errorf("entries() notes. (-expected +got):\n%s", diff)
			}
		})
	}
}

func Test_entries_malformedFragment(t *testing.T) {
	if _, _, err := entries(tomcatXML.Section{
		Name:   "Fixed in Apache Tomcat 11.0.1",
		Blocks: []tomcatXML.Block{{Tag: "p", XML: "<strong>unclosed"}},
	}); err == nil {
		t.Error("expected error has not occurred")
	}
}
