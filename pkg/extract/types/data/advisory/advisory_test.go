package advisory_test

import (
	"testing"

	advisoryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory"
	contentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/advisory/content"
	segmentTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment"
)

func TestAdvisory_Sort(t *testing.T) {
	type fields struct {
		Content  contentTypes.Content
		Segments []segmentTypes.Segment
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &advisoryTypes.Advisory{
				Content:  tt.fields.Content,
				Segments: tt.fields.Segments,
			}
			a.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x advisoryTypes.Advisory
		y advisoryTypes.Advisory
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
			if got := advisoryTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
