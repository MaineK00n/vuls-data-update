package supersededby

import (
	"testing"
)

func TestSupersededBy_Sort(t *testing.T) {
	type fields struct {
		KBID     string
		UpdateID string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &SupersededBy{
				KBID:     tt.fields.KBID,
				UpdateID: tt.fields.UpdateID,
			}
			d.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x SupersededBy
		y SupersededBy
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
			if got := Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
