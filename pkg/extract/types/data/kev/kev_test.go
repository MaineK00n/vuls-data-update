package kev_test

import (
	"testing"
	"time"

	kevTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev"
	vulncheckTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck"
	reportedExploitationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/reportedexploitation"
	xdbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/xdb"
)

func TestSort(t *testing.T) {
	tests := []struct {
		name  string
		input kevTypes.KEV
		want  kevTypes.KEV
	}{
		{
			name: "sorts VulnCheck sub-fields",
			input: kevTypes.KEV{
				VulnCheck: &vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{
						{XDBID: "zzz"},
						{XDBID: "aaa"},
					},
					ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
						{URL: "https://zzz.example.com"},
						{URL: "https://aaa.example.com"},
					},
				},
			},
			want: kevTypes.KEV{
				VulnCheck: &vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{
						{XDBID: "aaa"},
						{XDBID: "zzz"},
					},
					ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
						{URL: "https://aaa.example.com"},
						{URL: "https://zzz.example.com"},
					},
				},
			},
		},
		{
			name:  "nil VulnCheck",
			input: kevTypes.KEV{VendorProject: "Apple"},
			want:  kevTypes.KEV{VendorProject: "Apple"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.Sort()
			if kevTypes.Compare(tt.input, tt.want) != 0 {
				t.Errorf("Sort() result mismatch: got %+v, want %+v", tt.input, tt.want)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x kevTypes.KEV
		y kevTypes.KEV
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: kevTypes.KEV{
					VendorProject: "Microsoft",
					Product:       "Windows",
					DateAdded:     time.Date(2022, time.August, 18, 0, 0, 0, 0, time.UTC),
					DueDate:       time.Date(2022, time.September, 8, 0, 0, 0, 0, time.UTC),
				},
				y: kevTypes.KEV{
					VendorProject: "Microsoft",
					Product:       "Windows",
					DateAdded:     time.Date(2022, time.August, 18, 0, 0, 0, 0, time.UTC),
					DueDate:       time.Date(2022, time.September, 8, 0, 0, 0, 0, time.UTC),
				},
			},
			want: 0,
		},
		{
			name: "x:vendorProject < y:vendorProject",
			args: args{
				x: kevTypes.KEV{VendorProject: "Apple"},
				y: kevTypes.KEV{VendorProject: "Microsoft"},
			},
			want: -1,
		},
		{
			name: "x:product > y:product",
			args: args{
				x: kevTypes.KEV{VendorProject: "Microsoft", Product: "Windows"},
				y: kevTypes.KEV{VendorProject: "Microsoft", Product: "Edge"},
			},
			want: +1,
		},
		{
			name: "x:dateAdded < y:dateAdded",
			args: args{
				x: kevTypes.KEV{
					VendorProject: "Microsoft",
					Product:       "Windows",
					DateAdded:     time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
				y: kevTypes.KEV{
					VendorProject: "Microsoft",
					Product:       "Windows",
					DateAdded:     time.Date(2023, time.January, 1, 0, 0, 0, 0, time.UTC),
				},
			},
			want: -1,
		},
		{
			name: "x has VulnCheck, y does not",
			args: args{
				x: kevTypes.KEV{
					VulnCheck: &vulncheckTypes.VulnCheck{
						XDB: []xdbTypes.XDB{{XDBID: "abc"}},
					},
				},
				y: kevTypes.KEV{},
			},
			want: +1,
		},
		{
			name: "x has VulnCheck with ReportedExploitation, y has empty VulnCheck",
			args: args{
				x: kevTypes.KEV{
					VulnCheck: &vulncheckTypes.VulnCheck{
						ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{{URL: "https://example.com"}},
					},
				},
				y: kevTypes.KEV{
					VulnCheck: &vulncheckTypes.VulnCheck{},
				},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := kevTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
