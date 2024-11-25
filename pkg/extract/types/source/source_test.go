package source_test

import (
	"testing"

	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/source"
)

func TestSource_Sort(t *testing.T) {
	type fields struct {
		ID   sourceTypes.SourceID
		Raws []string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &sourceTypes.Source{
				ID:   tt.fields.ID,
				Raws: tt.fields.Raws,
			}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x sourceTypes.Source
		y sourceTypes.Source
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
			if got := sourceTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
