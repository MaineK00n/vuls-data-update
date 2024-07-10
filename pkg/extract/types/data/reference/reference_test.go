package reference_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/reference"
)

func TestCompare(t *testing.T) {
	type args struct {
		x reference.Reference
		y reference.Reference
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: reference.Reference{
					Source: "source1",
					URL:    "http://example.com",
				},
				y: reference.Reference{
					Source: "source1",
					URL:    "http://example.com",
				},
			},
			want: 0,
		},
		{
			name: "x:source < y:source",
			args: args{
				x: reference.Reference{
					Source: "source1",
					URL:    "http://example.com",
				},
				y: reference.Reference{
					Source: "source2",
					URL:    "http://example.com",
				},
			},
			want: -1,
		},
		{
			name: "x:url > y:url",
			args: args{
				x: reference.Reference{
					Source: "source",
					URL:    "http://example1.com",
				},
				y: reference.Reference{
					Source: "source",
					URL:    "http://example.com",
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reference.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
