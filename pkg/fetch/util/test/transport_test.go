package test_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	utiltest "github.com/MaineK00n/vuls-data-update/pkg/fetch/util/test"
)

func TestCutBody(t *testing.T) {
	errCut := errors.New("stream error: stream ID 1; INTERNAL_ERROR; received from peer")

	tests := []struct {
		name    string
		after   int
		want    []string
		wantErr []error
		wantCut bool
	}{
		{
			// The first body fails after its first 3 bytes, and the second
			// is read whole.
			name:    "cut",
			after:   3,
			want:    []string{"012", "0123456789"},
			wantErr: []error{errCut, nil},
			wantCut: true,
		},
		{
			// A body shorter than After is read whole, and nothing is cut.
			name:    "body too short",
			after:   20,
			want:    []string{"0123456789", "0123456789"},
			wantErr: []error{nil, nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "0123456789")
			}))

			transport := &utiltest.CutBody{Next: ts.Client().Transport, After: tt.after, Err: errCut}
			client := &http.Client{Transport: transport}
			for i := range tt.want {
				got, err := func() (string, error) {
					resp, err := client.Get("https://example.com/")
					if err != nil {
						t.Fatal("unexpected error:", err)
					}
					defer resp.Body.Close()
					bs, err := io.ReadAll(resp.Body)
					return string(bs), err
				}()
				if !errors.Is(err, tt.wantErr[i]) {
					t.Errorf("response %d: err = %v, want %v", i, err, tt.wantErr[i])
				}
				if got != tt.want[i] {
					t.Errorf("response %d: body = %q, want %q", i, got, tt.want[i])
				}
			}
			if got := transport.Cut(); got != tt.wantCut {
				t.Errorf("Cut() = %v, want %v", got, tt.wantCut)
			}
		})
	}
}
