package cpecriterion_test

import (
	"testing"

	cpecTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion"
	cpecRangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/cpecriterion/range"
)

func TestCriterion_Accept(t *testing.T) {
	type fields struct {
		Vulnerable bool
		CPE        cpecTypes.CPE
		CPEMatches []cpecTypes.CPE
		Range      *cpecRangeTypes.Range
	}
	type args struct {
		query cpecTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "cpe in semver range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "accept with target_sw in pattern, wildcard in query",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.8"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "not accept with different target_sw",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5:*:*:*:*:node.js:*:*"}},
			want: false,
		},
		{
			name: "not accept with different part",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:o:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "query version wildcard with range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "query version wildcard without range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "query version wildcard against specific pattern version",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version ANY, query version NA",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "1.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version ANY, query version not in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern version NA",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern version NA with range, range is ignored",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "0.0.2"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version with range, query same version in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version with range, query same version out of range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern specific version with range, query version ANY",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "pattern specific version outside range, query version ANY short-circuits",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:3.0.0:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "ge/lt range, query in range",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "ge/lt range, query below lower bound",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, GreaterEqual: "1.0.0", LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.9.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "cpe_matches: query matches one entry, main CPE disjoint",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				CPEMatches: []cpecTypes.CPE{
					"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*",
					"cpe:2.3:a:vendor:product:15.4\\(3\\)m:*:*:*:*:*:*:*",
				},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:other:product:1.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "cpe_matches: query matches one entry exactly via cpematch fallback",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:productX:*:*:*:*:*:*:*:*",
				CPEMatches: []cpecTypes.CPE{
					"cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*",
				},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:productY:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "unparseable query version with range yields false",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "Range out, CPEMatches in: NVD listed an out-of-range version",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []cpecTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "Range in, CPEMatches non-matching: Range short-circuits",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []cpecTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.5.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "Range out, CPEMatches non-matching: neither narrowing matches",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeSEMVER, LessThan: "2.0.0"},
				CPEMatches: []cpecTypes.CPE{"cpe:2.3:a:vendor:product:3.5.0:*:*:*:*:*:*:*"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:5.0.0:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "accept (no narrowing): wildcard pattern matches concrete query",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:0.0.1:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "different vendor",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:other:product:0.0.1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "different product",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:other:0.0.1:*:*:*:*:*:*:*"}},
			want: false,
		},
		{
			name: "pattern has target_sw, query has same target_sw",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:wordpress:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:wordpress:*:*"}},
			want: true,
		},
		{
			name: "pattern has sw_edition, query has wildcard",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:enterprise:*:*:*",
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}},
			want: true,
		},
		{
			name: "non-semver Range stored as-is, CPEMatches covers all enumerated versions",
			fields: fields{
				Vulnerable: true,
				CPE:        "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
				Range:      &cpecRangeTypes.Range{Type: cpecRangeTypes.RangeTypeUnknown, LessThan: "15.4(3)m"},
				CPEMatches: []cpecTypes.CPE{"cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"},
			},
			args: args{query: cpecTypes.Query{CPE: "cpe:2.3:a:vendor:product:15.4\\(2\\)t1:*:*:*:*:*:*:*"}},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := cpecTypes.Criterion{
				Vulnerable: tt.fields.Vulnerable,
				CPE:        tt.fields.CPE,
				CPEMatches: tt.fields.CPEMatches,
				Range:      tt.fields.Range,
			}
			got, err := c.Accept(tt.args.query)
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

