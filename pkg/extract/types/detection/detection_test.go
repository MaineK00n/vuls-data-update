package detection

import "testing"

func TestAffected_LessThan(t *testing.T) {
	type fields struct {
		Type  RangeType
		Range []Range
		Fixed []string
	}
	type args struct {
		v string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Affected{
				Type:  tt.fields.Type,
				Range: tt.fields.Range,
				Fixed: tt.fields.Fixed,
			}
			got, err := a.LessThan(tt.args.v)
			if (err != nil) != tt.wantErr {
				t.Errorf("Affected.LessThan() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Affected.LessThan() = %v, want %v", got, tt.want)
			}
		})
	}
}
