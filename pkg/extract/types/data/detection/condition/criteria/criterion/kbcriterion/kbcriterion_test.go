package kbcriterion_test

import (
	"testing"

	kbcriterionTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/kbcriterion"
)

func TestCriterion_Sort(t *testing.T) {
	tests := []struct {
		name      string
		criterion kbcriterionTypes.Criterion
	}{
		{
			name: "sort is no-op",
			criterion: kbcriterionTypes.Criterion{
				Product: "Windows 10",
				KBID:    "5025239",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := tt.criterion
			c.Sort()
			if c != tt.criterion {
				t.Errorf("Sort() changed criterion, got %v, want %v", c, tt.criterion)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x kbcriterionTypes.Criterion
		y kbcriterionTypes.Criterion
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "equal",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
				y: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
			},
			want: 0,
		},
		{
			name: "product less",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
				y: kbcriterionTypes.Criterion{Product: "Windows 11", KBID: "5025239"},
			},
			want: -1,
		},
		{
			name: "product greater",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 11", KBID: "5025239"},
				y: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
			},
			want: 1,
		},
		{
			name: "same product, kbid less",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025238"},
				y: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
			},
			want: -1,
		},
		{
			name: "same product, kbid greater",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025239"},
				y: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "5025238"},
			},
			want: 1,
		},
		{
			name: "product takes precedence over kbid",
			args: args{
				x: kbcriterionTypes.Criterion{Product: "Windows 10", KBID: "9999999"},
				y: kbcriterionTypes.Criterion{Product: "Windows 11", KBID: "0000001"},
			},
			want: -1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kbcriterionTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCriterion_Accept(t *testing.T) {
	tests := []struct {
		name      string
		criterion kbcriterionTypes.Criterion
		query     kbcriterionTypes.Query
		want      bool
		wantErr   bool
	}{
		{
			name: "kbid in unapplied list",
			criterion: kbcriterionTypes.Criterion{
				Product: "Windows 10",
				KBID:    "5025239",
			},
			query: kbcriterionTypes.Query{
				UnappliedKBs: []string{"5025239", "5025305"},
			},
			want: true,
		},
		{
			name: "kbid not in unapplied list",
			criterion: kbcriterionTypes.Criterion{
				Product: "Windows 10",
				KBID:    "5025239",
			},
			query: kbcriterionTypes.Query{
				UnappliedKBs: []string{"5025305", "5025306"},
			},
			want: false,
		},
		{
			name: "empty unapplied list",
			criterion: kbcriterionTypes.Criterion{
				Product: "Windows 10",
				KBID:    "5025239",
			},
			query: kbcriterionTypes.Query{
				UnappliedKBs: []string{},
			},
			want: false,
		},
		{
			name: "nil unapplied list",
			criterion: kbcriterionTypes.Criterion{
				Product: "Windows 10",
				KBID:    "5025239",
			},
			query: kbcriterionTypes.Query{},
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.criterion.Accept(tt.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
