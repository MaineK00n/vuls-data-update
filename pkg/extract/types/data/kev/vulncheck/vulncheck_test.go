package vulncheck_test

import (
	"testing"
	"time"

	vulncheckTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck"
	reportedExploitationTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/reportedexploitation"
	xdbTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/kev/vulncheck/xdb"
)

func TestSort(t *testing.T) {
	tests := []struct {
		name    string
		input   vulncheckTypes.VulnCheck
		wantXDB []xdbTypes.XDB
		wantRE  []reportedExploitationTypes.ReportedExploitation
	}{
		{
			name: "sorts XDB and ReportedExploitation",
			input: vulncheckTypes.VulnCheck{
				XDB: []xdbTypes.XDB{
					{XDBID: "zzz", DateAdded: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)},
					{XDBID: "aaa", DateAdded: time.Date(2023, time.June, 1, 0, 0, 0, 0, time.UTC)},
				},
				ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
					{URL: "https://zzz.example.com", DateAdded: time.Date(2022, time.March, 1, 0, 0, 0, 0, time.UTC)},
					{URL: "https://aaa.example.com", DateAdded: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)},
				},
			},
			wantXDB: []xdbTypes.XDB{
				{XDBID: "aaa", DateAdded: time.Date(2023, time.June, 1, 0, 0, 0, 0, time.UTC)},
				{XDBID: "zzz", DateAdded: time.Date(2022, time.January, 1, 0, 0, 0, 0, time.UTC)},
			},
			wantRE: []reportedExploitationTypes.ReportedExploitation{
				{URL: "https://aaa.example.com", DateAdded: time.Date(2021, time.January, 1, 0, 0, 0, 0, time.UTC)},
				{URL: "https://zzz.example.com", DateAdded: time.Date(2022, time.March, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
		{
			name:    "empty slices",
			input:   vulncheckTypes.VulnCheck{},
			wantXDB: nil,
			wantRE:  nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.input.Sort()
			if len(tt.input.XDB) != len(tt.wantXDB) {
				t.Fatalf("XDB length = %d, want %d", len(tt.input.XDB), len(tt.wantXDB))
			}
			for i := range tt.input.XDB {
				if xdbTypes.Compare(tt.input.XDB[i], tt.wantXDB[i]) != 0 {
					t.Errorf("XDB[%d] = %+v, want %+v", i, tt.input.XDB[i], tt.wantXDB[i])
				}
			}
			if len(tt.input.ReportedExploitation) != len(tt.wantRE) {
				t.Fatalf("ReportedExploitation length = %d, want %d", len(tt.input.ReportedExploitation), len(tt.wantRE))
			}
			for i := range tt.input.ReportedExploitation {
				if reportedExploitationTypes.Compare(tt.input.ReportedExploitation[i], tt.wantRE[i]) != 0 {
					t.Errorf("ReportedExploitation[%d] = %+v, want %+v", i, tt.input.ReportedExploitation[i], tt.wantRE[i])
				}
			}
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x vulncheckTypes.VulnCheck
		y vulncheckTypes.VulnCheck
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "x == y",
			args: args{
				x: vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{{XDBID: "abc"}},
					ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
						{URL: "https://example.com"},
					},
				},
				y: vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{{XDBID: "abc"}},
					ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
						{URL: "https://example.com"},
					},
				},
			},
			want: 0,
		},
		{
			name: "x:xdb < y:xdb",
			args: args{
				x: vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{{XDBID: "aaa"}},
				},
				y: vulncheckTypes.VulnCheck{
					XDB: []xdbTypes.XDB{{XDBID: "bbb"}},
				},
			},
			want: -1,
		},
		{
			name: "x has reportedExploitation, y does not",
			args: args{
				x: vulncheckTypes.VulnCheck{
					ReportedExploitation: []reportedExploitationTypes.ReportedExploitation{
						{URL: "https://example.com"},
					},
				},
				y: vulncheckTypes.VulnCheck{},
			},
			want: +1,
		},
		{
			name: "both empty",
			args: args{
				x: vulncheckTypes.VulnCheck{},
				y: vulncheckTypes.VulnCheck{},
			},
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := vulncheckTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}
