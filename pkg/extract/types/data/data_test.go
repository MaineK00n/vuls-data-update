package data_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	dataTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data"
)

func TestData_Merge(t *testing.T) {
	type args struct {
		ds []dataTypes.Data
	}
	tests := []struct {
		name     string
		fields   dataTypes.Data
		args     args
		expected dataTypes.Data
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			(&tt.fields).Merge(tt.args.ds...)
			if diff := cmp.Diff(tt.expected, tt.fields); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}
