package oval

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseFileName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    *FileName
		wantErr bool
	}{
		{
			name:  "suse.linux.enterprise major patch",
			input: "suse.linux.enterprise.15-patch.xml.gz",
			want: &FileName{
				Raw:     "suse.linux.enterprise.15-patch.xml.gz",
				OS:      "suse.linux.enterprise",
				Version: "15",
				Variant: VariantPatch,
			},
		},
		{
			name:  "suse.linux.enterprise sp affected",
			input: "suse.linux.enterprise.15-sp1-affected.xml.gz",
			want: &FileName{
				Raw:     "suse.linux.enterprise.15-sp1-affected.xml.gz",
				OS:      "suse.linux.enterprise",
				Version: "15-sp1",
				Variant: VariantAffected,
			},
		},
		{
			name:  "suse.linux.enterprise sp none",
			input: "suse.linux.enterprise.15-sp1.xml.gz",
			want: &FileName{
				Raw:     "suse.linux.enterprise.15-sp1.xml.gz",
				OS:      "suse.linux.enterprise",
				Version: "15-sp1",
				Variant: VariantNone,
			},
		},
		{
			name:    "reject non xml.gz",
			input:   "suse.linux.enterprise.15.xml",
			wantErr: true,
		},
		{
			name:  "reject unknown os",
			input: "unknownos.1.xml.gz",
			want:  nil,
		},
		{
			name:    "nil for missing version",
			input:   "opensuse..xml.gz",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseFileName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseFileName() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Fetch(). (-expected +got):\n%s", diff)
			}
		})
	}
}

func TestFileName_ShouldInclude(t *testing.T) {
	tests := []struct {
		name string
		in   FileName
		want bool
	}{
		{
			name: "opensuse always included",
			in:   FileName{OS: "opensuse", Version: "tumbleweed"},
			want: true,
		},
		{
			name: "opensuse.leap always included",
			in:   FileName{OS: "opensuse.leap", Version: "15.2"},
			want: true,
		},
		{
			name: "opensuse.leap.micro always included",
			in:   FileName{OS: "opensuse.leap.micro", Version: "5.2"},
			want: true,
		},
		{
			name: "suse.linux.enterprise.server 9 included",
			in:   FileName{OS: "suse.linux.enterprise.server", Version: "9"},
			want: true,
		},
		{
			name: "suse.linux.enterprise.server 10 included",
			in:   FileName{OS: "suse.linux.enterprise.server", Version: "10"},
			want: true,
		},
		{
			name: "suse.linux.enterprise.server other excluded",
			in:   FileName{OS: "suse.linux.enterprise.server", Version: "12"},
			want: false,
		},
		{
			name: "suse.linux.enterprise.desktop 10 included",
			in:   FileName{OS: "suse.linux.enterprise.desktop", Version: "10"},
			want: true,
		},
		{
			name: "suse.linux.enterprise.desktop other excluded",
			in:   FileName{OS: "suse.linux.enterprise.desktop", Version: "11"},
			want: false,
		},
		{
			name: "suse.linux.enterprise.micro 5 excluded",
			in:   FileName{OS: "suse.linux.enterprise.micro", Version: "5"},
			want: false,
		},
		{
			name: "suse.linux.enterprise.micro 5.2 included",
			in:   FileName{OS: "suse.linux.enterprise.micro", Version: "5.2"},
			want: true,
		},
		{
			name: "suse.linux.enterprise major included",
			in:   FileName{OS: "suse.linux.enterprise", Version: "15"},
			want: true,
		},
		{
			name: "suse.linux.enterprise sp excluded",
			in:   FileName{OS: "suse.linux.enterprise", Version: "15-sp1"},
			want: false,
		},
		{
			name: "suse.linux.enterprise dot excluded",
			in:   FileName{OS: "suse.linux.enterprise", Version: "16.0"},
			want: false,
		},
		{
			name: "unknown os excluded",
			in:   FileName{OS: "unknownos", Version: "1"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.in.ShouldInclude()); diff != "" {
				t.Errorf("ShouldInclude(). (-expected +got):\n%s", diff)
			}
		})
	}
}
