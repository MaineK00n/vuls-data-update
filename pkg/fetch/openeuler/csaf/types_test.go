package csaf_test

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	stderrors "errors"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/MaineK00n/vuls-data-update/pkg/fetch/openeuler/csaf"
)

func TestProductIDs_UnmarshalJSONFrom(t *testing.T) {
	tests := []struct {
		name     string
		args     string
		want     csaf.ProductIDs
		wantJSON string // what is written back, if not args
		wantErr  bool
	}{
		{
			name: "array",
			args: `["openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src","openEuler-22.03-LTS-SP4:python3-pyasn1-0.4.8-4.oe2203sp4.noarch"]`,
			want: csaf.ProductIDs{IDs: []csaf.ProductID{"openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src", "openEuler-22.03-LTS-SP4:python3-pyasn1-0.4.8-4.oe2203sp4.noarch"}},
		},
		{
			name: "empty array",
			args: `[]`,
			want: csaf.ProductIDs{IDs: []csaf.ProductID{}},
		},
		{
			// null reads as no list, which is written as [], as a nil
			// []ProductID is.
			name:     "null",
			args:     `null`,
			want:     csaf.ProductIDs{},
			wantJSON: `[]`,
		},
		{
			name: "reference",
			args: `{"$ref":"$.vulnerabilities[0].product_status.fixed"}`,
			want: csaf.ProductIDs{Ref: "$.vulnerabilities[0].product_status.fixed"},
		},
		{
			name:    "reference with another member",
			args:    `{"$ref":"$.vulnerabilities[0].product_status.fixed","product_ids":[]}`,
			wantErr: true,
		},
		{
			name:    "empty reference",
			args:    `{"$ref":""}`,
			wantErr: true,
		},
		{
			name:    "object without a reference",
			args:    `{}`,
			wantErr: true,
		},
		{
			name:    "reference not a string",
			args:    `{"$ref":0}`,
			wantErr: true,
		},
		{
			name:    "string",
			args:    `"openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src"`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got csaf.ProductIDs
			err := json.Unmarshal([]byte(tt.args), &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("(-expected +got):\n%s", diff)
			}

			// What is read is written back as it was.
			want := tt.args
			if tt.wantJSON != "" {
				want = tt.wantJSON
			}
			bs, err := json.Marshal(got)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(bs) != want {
				t.Errorf("Marshal() = %s, want %s", bs, want)
			}
		})
	}
}

func TestProductIDs_MarshalJSONTo(t *testing.T) {
	type args struct {
		Fixed    csaf.ProductIDs `json:"fixed,omitempty"`
		Products csaf.ProductIDs `json:"products"`
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "array",
			args: args{
				Fixed:    csaf.ProductIDs{IDs: []csaf.ProductID{"openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src"}},
				Products: csaf.ProductIDs{IDs: []csaf.ProductID{"openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src"}},
			},
			want: `{"fixed":["openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src"],"products":["openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src"]}`,
		},
		{
			name: "reference",
			args: args{
				Fixed:    csaf.ProductIDs{Ref: "$.vulnerabilities[0].product_status.fixed"},
				Products: csaf.ProductIDs{Ref: "$.vulnerabilities[0].product_status.fixed"},
			},
			want: `{"fixed":{"$ref":"$.vulnerabilities[0].product_status.fixed"},"products":{"$ref":"$.vulnerabilities[0].product_status.fixed"}}`,
		},
		{
			// An empty list is left out under omitempty and written as [] without
			// it, as a []ProductID is.
			name: "empty",
			args: args{},
			want: `{"products":[]}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.args)
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestProductIDs_UnmarshalJSONFrom_syntacticError(t *testing.T) {
	// Fetch skips a document that is not valid JSON, which it tells apart by
	// a *jsontext.SyntacticError, so one inside a list must still read as one.
	tests := []struct {
		name string
		args string
	}{
		{
			name: "array",
			args: `{"product_ids":["openEuler-22.03-LTS-SP4:python-pyasn1-0.4.8-4.oe2203sp4.src",]}`,
		},
		{
			name: "reference",
			args: `{"product_ids":{"$ref":"$.vulnerabilities[0].product_status.fixed",}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var v struct {
				ProductIDs csaf.ProductIDs `json:"product_ids"`
			}
			err := json.Unmarshal([]byte(tt.args), &v)
			if _, ok := stderrors.AsType[*jsontext.SyntacticError](err); !ok {
				t.Errorf("Unmarshal() error = %v, want a *jsontext.SyntacticError", err)
			}
		})
	}
}
