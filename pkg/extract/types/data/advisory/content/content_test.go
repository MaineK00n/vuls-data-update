package content_test

import (
	"testing"
	"time"

	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	cweTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/cwe"
	referenceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
	severityTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/severity"
)

func TestContent_Sort(t *testing.T) {
	type fields struct {
		ID          contentTypes.AdvisoryID
		Title       string
		Description string
		Severity    []severityTypes.Severity
		CWE         []cweTypes.CWE
		References  []referenceTypes.Reference
		Published   *time.Time
		Modified    *time.Time
		Optional    map[string]interface{}
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &contentTypes.Content{
				ID:          tt.fields.ID,
				Title:       tt.fields.Title,
				Description: tt.fields.Description,
				Severity:    tt.fields.Severity,
				CWE:         tt.fields.CWE,
				References:  tt.fields.References,
				Published:   tt.fields.Published,
				Modified:    tt.fields.Modified,
				Optional:    tt.fields.Optional,
			}
			c.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x contentTypes.Content
		y contentTypes.Content
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contentTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
