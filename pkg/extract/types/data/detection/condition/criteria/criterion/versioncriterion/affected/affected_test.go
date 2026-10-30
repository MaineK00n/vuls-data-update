package affected_test

import (
	"testing"

	affectedTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestAffected_Sort(t *testing.T) {
	type fields struct {
		Type  affectedrangeTypes.RangeType
		Range []affectedrangeTypes.Range
		Fixed []string
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &affectedTypes.Affected{
				Type:  tt.fields.Type,
				Range: tt.fields.Range,
				Fixed: tt.fields.Fixed,
			}
			a.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x affectedTypes.Affected
		y affectedTypes.Affected
	}
	tests := []struct {
		name string
		args args
		want int
	}{
		{
			name: "equal unresolved",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a", Description: "d", URL: "u"}},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a", Description: "d", URL: "u"}},
			},
			want: 0,
		},
		{
			name: "unset unresolved sorts first",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{}},
			},
			want: -1,
		},
		{
			name: "unresolved fixed greater",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "b"}},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a", Description: "z"}},
			},
			want: +1,
		},
		{
			name: "unresolved description less",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a", Description: "Click to Run"}},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a", Description: "Release Notes"}},
			},
			want: -1,
		},
		{
			name: "unresolved url greater",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{URL: "v"}},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{URL: "u"}},
			},
			want: +1,
		},
		{
			name: "type decides before unresolved",
			args: args{
				x: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeUnresolved, Unresolved: &affectedTypes.Unresolved{Fixed: "a"}},
				y: affectedTypes.Affected{Type: affectedrangeTypes.RangeTypeMicrosoftWindows, Range: []affectedrangeTypes.Range{{LessThan: "10.0.1.1"}}},
			},
			want: +1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := affectedTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAffected_Accept(t *testing.T) {
	type fields struct {
		Type       affectedrangeTypes.RangeType
		Range      []affectedrangeTypes.Range
		Fixed      []string
		Unresolved *affectedTypes.Unresolved
	}
	type args struct {
		family ecosystemTypes.Ecosystem
		v      string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "0.0.0 [= 0.0.1]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						Equal: "0.0.1",
					}},
			},
			args: args{
				v: "0.0.0",
			},
			want: false,
		},
		{
			name: "0.0.1, [= 0.0.1]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						Equal: "0.0.1",
					}},
			},
			args: args{
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [>0.0.0]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						GreaterThan: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [>0.0.0, <0.0.2]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						LessThan:    "0.0.2",
						GreaterThan: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.1 [<0.0.2]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						LessThan: "0.0.2",
					}},
			},
			args: args{
				v: "0.0.1",
			},
			want: true,
		},
		{
			name: "0.0.3 [>0.0.0, <0.0.2]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						LessThan:    "0.0.2",
						GreaterThan: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.3",
			},
			want: false,
		},
		{
			name: "0.0.0 [>=0.0.0]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						GreaterEqual: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.0",
			},
			want: true,
		},
		{
			name: "0.0.0 [<=0.0.0]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						LessEqual: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.0",
			},
			want: true,
		},
		{
			name: "0.0.0 [>=0.0.0, <=0.0.0]",
			fields: fields{
				Type: affectedrangeTypes.RangeTypeSEMVER,
				Range: []affectedrangeTypes.Range{
					{
						LessEqual:    "0.0.0",
						GreaterEqual: "0.0.0",
					}},
			},
			args: args{
				v: "0.0.0",
			},
			want: true,
		},
		{
			// Data written by a newer vuls-data-update may carry a range type
			// this build does not know. Accept reports the non-fatal
			// *warning.UnevaluableError — a sentinel for the criterion layer
			// to catch and record as a skip, not a fatal abort of detection.
			name: "unsupported range type (newer data) reports unevaluable",
			fields: fields{
				Type:  affectedrangeTypes.RangeType("future-type"),
				Range: []affectedrangeTypes.Range{{LessThan: "1.0.0"}},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v:      "0.9.0",
			},
			want:    false,
			wantErr: true,
		},
		{
			// An endpoint-less element expresses nothing regardless of the
			// type: it cannot be evaluated and is reported as a non-fatal
			// empty-range warning.
			name: "comparator-less vocabulary type with empty range reports empty-range",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypePacman,
				Range: []affectedrangeTypes.Range{{}},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeArch,
				v:      "0.9.0",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "comparator-less vocabulary type with bounds reports unevaluable",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypePacman,
				Range: []affectedrangeTypes.Range{{LessThan: "1.0.0"}},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeArch,
				v:      "0.9.0",
			},
			want:    false,
			wantErr: true,
		},
		{
			// Unknown's empty bounds mean "the source declared a constraint we
			// could not translate", not "no constraint" — mirroring
			// cpecriterion/range, it must not get the all-empty match-all.
			// The empty-ness is the anomaly, so it warns like any other type.
			name: "unknown range type with empty range reports empty-range",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeUnknown,
				Range: []affectedrangeTypes.Range{{}},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v:      "0.9.0",
			},
			want:    false,
			wantErr: true,
		},
		{
			// An endpoint-less element expresses nothing regardless of the
			// type — it may also be a newer range type whose constraints live
			// in JSON fields this build's unmarshal dropped, so it is
			// reported rather than silently skipped.
			name: "unsupported range type (newer data) with empty range reports empty-range",
			fields: fields{
				Type:  affectedrangeTypes.RangeType("future-type"),
				Range: []affectedrangeTypes.Range{{}},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				v:      "0.9.0",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "solaris-ips-pattern 11.4-11.4.93.0.1.110.0:20260101T000000Z [< 11.4-11.4.94]",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessThan: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.4-11.4.93.0.1.110.0:20260101T000000Z"},
			want: true,
		},
		{
			name: "solaris-ips-pattern 11.4-11.4.94.0.1.113.1:20260201T000000Z [< 11.4-11.4.94]",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessThan: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.4-11.4.94.0.1.113.1:20260201T000000Z"},
			want: false,
		},
		{
			name: "solaris-ips 11.4-11.4.94.0.1.113.1:20260201T000000Z [<= 11.4-11.4.94]: the endpoint is a version, a build of it sorts after it, no match",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPS,
				Range: []affectedrangeTypes.Range{{LessEqual: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.4-11.4.94.0.1.113.1:20260201T000000Z"},
			want: false,
		},
		{
			name: "solaris-ips-pattern 11.4-11.4.94.0.1.113.1:20260201T000000Z [<= 11.4-11.4.94]: a level is met by every build on it",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessEqual: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.4-11.4.94.0.1.113.1:20260201T000000Z"},
			want: true,
		},
		{
			name: "solaris-ips-pattern 11.4 without a branch [< 11.4-11.4.94]: the pattern names a branch the version lacks, no match",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessThan: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.4"},
			want: false,
		},
		{
			name: "solaris-ips-pattern 11.3 [<= 11.4:20180817T004203Z]: the pattern names a timestamp the version lacks, no match whatever the release",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessEqual: "11.4:20180817T004203Z"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "11.3"},
			want: false,
		},
		{
			name: "solaris-ips-pattern 1.8.0.181.12:20180711T215531Z [< 1.8.0.471]: a release-only pattern reaches a version with a timestamp",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessThan: "1.8.0.471"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "1.8.0.181.12:20180711T215531Z"},
			want: true,
		},
		{
			name: "solaris-ips-pattern not an ips version [< 11.4-11.4.94]: no match, no error",
			fields: fields{
				Type:  affectedrangeTypes.RangeTypeSolarisIPSPattern,
				Range: []affectedrangeTypes.Range{{LessThan: "11.4-11.4.94"}},
			},
			args: args{family: ecosystemTypes.Ecosystem("solaris:11.4"), v: "1.0.2k-8.el7"},
			want: false,
		},
		{
			name: "unresolved accepts any version",
			fields: fields{
				Type:       affectedrangeTypes.RangeTypeUnresolved,
				Unresolved: &affectedTypes.Unresolved{Fixed: "https://aka.ms/OfficeSecurityReleases", Description: "Click to Run"},
			},
			args: args{v: "16.0.10417.20030"},
			want: true,
		},
		{
			name: "unresolved accepts an empty version",
			fields: fields{
				Type:       affectedrangeTypes.RangeTypeUnresolved,
				Unresolved: &affectedTypes.Unresolved{},
			},
			args: args{v: ""},
			want: true,
		},
		{
			name:    "unresolved type without unresolved is an error",
			fields:  fields{Type: affectedrangeTypes.RangeTypeUnresolved},
			args:    args{v: "1.0.0"},
			wantErr: true,
		},
		{
			name: "unresolved with another type is an error",
			fields: fields{
				Type:       affectedrangeTypes.RangeTypeMicrosoftVisualStudio,
				Unresolved: &affectedTypes.Unresolved{Fixed: "18.12 Insiders 3"},
			},
			args:    args{v: "18.12.0"},
			wantErr: true,
		},
		{
			name: "unresolved with a range is an error",
			fields: fields{
				Type:       affectedrangeTypes.RangeTypeUnresolved,
				Range:      []affectedrangeTypes.Range{{LessThan: "1.0.0"}},
				Unresolved: &affectedTypes.Unresolved{Fixed: "1.0.0"},
			},
			args:    args{v: "0.9.0"},
			wantErr: true,
		},
		{
			name: "unresolved with fixed is an error",
			fields: fields{
				Type:       affectedrangeTypes.RangeTypeUnresolved,
				Fixed:      []string{"1.0.0"},
				Unresolved: &affectedTypes.Unresolved{Fixed: "1.0.0"},
			},
			args:    args{v: "0.9.0"},
			wantErr: true,
		},
		{
			// What a build without Unresolved sees for such data: the unknown
			// member is dropped on unmarshal and there is no range to accept.
			name:   "range type outside the vocabulary and no range: no match (how a build without unresolved sees such data)",
			fields: fields{Type: affectedrangeTypes.RangeType("unresolved-from-newer-data")},
			args:   args{v: "1.0.0"},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (affectedTypes.Affected{
				Type:       tt.fields.Type,
				Range:      tt.fields.Range,
				Fixed:      tt.fields.Fixed,
				Unresolved: tt.fields.Unresolved,
			}).Accept(tt.args.family, tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("Affected.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Affected.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
