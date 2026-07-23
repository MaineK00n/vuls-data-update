package warning_test

import (
	stderrors "errors"
	"testing"

	warningTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/warning"
)

func TestUnevaluableError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *warningTypes.UnevaluableError
		want string
	}{
		{
			name: "kind only",
			err:  &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}},
			want: "unevaluable: empty-range",
		},
		{
			name: "kind and cause",
			err:  &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"}},
			want: `unevaluable: unevaluable-range-type "future-range"`,
		},
		{
			name: "kind, cause and underlying error",
			err:  &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"}, Err: stderrors.New("no comparator")},
			want: `unevaluable: unevaluable-range-type "future-range": no comparator`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUnevaluableError_Unwrap(t *testing.T) {
	underlying := stderrors.New("underlying")
	err := &warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindUnevaluableRangeType, Cause: "future-range"}, Err: underlying}
	if !stderrors.Is(err, underlying) {
		t.Errorf("errors.Is() = false, want the underlying error reachable through Unwrap")
	}
	if got := stderrors.Unwrap(&warningTypes.UnevaluableError{Warning: warningTypes.Warning{Kind: warningTypes.KindEmptyRange}}); got != nil {
		t.Errorf("Unwrap() = %v, want nil for a data-derived warning", got)
	}
}
