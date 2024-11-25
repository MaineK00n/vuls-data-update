package detection_test

import (
	"testing"

	detectionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection"
	conditionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestDetection_Sort(t *testing.T) {
	type fields struct {
		Ecosystem  ecosystemTypes.Ecosystem
		Conditions []conditionTypes.Condition
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &detectionTypes.Detection{
				Ecosystem:  tt.fields.Ecosystem,
				Conditions: tt.fields.Conditions,
			}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x detectionTypes.Detection
		y detectionTypes.Detection
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
			if got := detectionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
