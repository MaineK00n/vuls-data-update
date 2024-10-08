package affected_test

import (
	"testing"

	"github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected"
	affectedrangeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/criteria/criterion/affected/range"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/ecosystem"
)

func TestCompare(t *testing.T) {
	type args struct {
		x affected.Affected
		y affected.Affected
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
			if got := affected.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAffected_Accept(t *testing.T) {
	type fields struct {
		Type  affectedrangeTypes.RangeType
		Range []affectedrangeTypes.Range
		Fixed []string
	}
	type args struct {
		ecosystem ecosystemTypes.Ecosystem
		v         string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (affected.Affected{
				Type:  tt.fields.Type,
				Range: tt.fields.Range,
				Fixed: tt.fields.Fixed,
			}).Accept(tt.args.ecosystem, tt.args.v)
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
