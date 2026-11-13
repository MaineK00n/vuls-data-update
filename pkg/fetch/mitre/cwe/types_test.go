package cwe

import (
	"encoding/json/v2"
	"encoding/xml"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestOneOrMany_UnmarshalJSONFrom(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		want    ContentHistory
		wantErr bool
	}{
		{
			name: "lists",
			json: `{"submission":[{"submission_name":["Alice","Bob"]},{"submission_name":["Carol"]}]}`,
			want: ContentHistory{Submission: OneOrMany[Submission]{{SubmissionName: OneOrMany[string]{"Alice", "Bob"}}, {SubmissionName: OneOrMany[string]{"Carol"}}}},
		},
		{
			name: "single values written before schema v8.0 support",
			json: `{"submission":{"submission_name":"Alice","submission_date":"2006-07-19"}}`,
			want: ContentHistory{Submission: OneOrMany[Submission]{{SubmissionName: OneOrMany[string]{"Alice"}, SubmissionDate: "2006-07-19"}}},
		},
		{
			name: "null",
			json: `{"submission":null}`,
			want: ContentHistory{},
		},
		{
			name:    "wrong type",
			json:    `{"submission":[{"submission_name":1}]}`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ContentHistory
			err := json.Unmarshal([]byte(tt.json), &got)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}
		})
	}
}

func TestStructuredText_String(t *testing.T) {
	tests := []struct {
		name string
		xml  string
		want string
	}{
		{
			name: "plain text",
			xml:  `<Note>Plain text.</Note>`,
			want: "Plain text.",
		},
		{
			name: "plain text keeps its entities decoded",
			xml:  `<Objective>Consortium for Information &amp; Software Quality, a &lt; b</Objective>`,
			want: "Consortium for Information & Software Quality, a < b",
		},
		{
			name: "xhtml is kept as raw inner xml",
			xml:  "<Note xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n\t<xhtml:p>First &amp; second.</xhtml:p>\n\t<xhtml:p>Third.</xhtml:p>\n</Note>",
			want: "\n\t<xhtml:p>First &amp; second.</xhtml:p>\n\t<xhtml:p>Third.</xhtml:p>\n",
		},
		{
			name: "empty",
			xml:  `<Note/>`,
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got structuredText
			if err := xml.Unmarshal([]byte(tt.xml), &got); err != nil {
				t.Fatal("unexpected error:", err)
			}
			if got.String() != tt.want {
				t.Errorf("String() = %q, want %q", got.String(), tt.want)
			}
		})
	}
}
