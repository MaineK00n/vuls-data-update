package cwe

import (
	"encoding/xml"
	"testing"
)

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
