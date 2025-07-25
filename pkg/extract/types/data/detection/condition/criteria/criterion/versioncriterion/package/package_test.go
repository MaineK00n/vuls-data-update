package criterionpackage_test

import (
	"testing"

	packageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package"
	binaryTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/binary"
	cpeTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/cpe"
	languageTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/language"
	sourceTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/condition/criteria/criterion/versioncriterion/package/source"
	ecosystemTypes "github.com/MaineK00n/vuls-data-update/pkg/extract/types/data/detection/segment/ecosystem"
)

func TestPackage_Sort(t *testing.T) {
	type fields struct {
		Type     packageTypes.PackageType
		Binary   *binaryTypes.Package
		Source   *sourceTypes.Package
		CPE      *cpeTypes.CPE
		Language *languageTypes.Package
	}
	tests := []struct {
		name   string
		fields fields
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &packageTypes.Package{
				Type:     tt.fields.Type,
				Binary:   tt.fields.Binary,
				Source:   tt.fields.Source,
				CPE:      tt.fields.CPE,
				Language: tt.fields.Language,
			}
			p.Sort()
		})
	}
}

func TestCompare(t *testing.T) {
	type args struct {
		x packageTypes.Package
		y packageTypes.Package
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
			if got := packageTypes.Compare(tt.args.x, tt.args.y); got != tt.want {
				t.Errorf("Compare() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPackage_Accept(t *testing.T) {
	type fields struct {
		Type     packageTypes.PackageType
		Binary   *binaryTypes.Package
		Source   *sourceTypes.Package
		CPE      *cpeTypes.CPE
		Language *languageTypes.Package
	}
	type args struct {
		family ecosystemTypes.Ecosystem
		query  packageTypes.Query
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "binary",
			fields: fields{
				Type:   packageTypes.PackageTypeBinary,
				Binary: &binaryTypes.Package{Name: "name"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: packageTypes.Query{
					Binary: &binaryTypes.Query{Name: "name"},
					Source: &sourceTypes.Query{Name: "name"},
				},
			},
			want: true,
		},
		{
			name: "source",
			fields: fields{
				Type:   packageTypes.PackageTypeSource,
				Source: &sourceTypes.Package{Name: "name"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeRedHat,
				query: packageTypes.Query{
					Binary: &binaryTypes.Query{Name: "name"},
					Source: &sourceTypes.Query{Name: "name"},
				},
			},
			want: true,
		},
		{
			name: "cpe",
			fields: fields{
				Type: packageTypes.PackageTypeCPE,
				CPE:  func() *cpeTypes.CPE { s := cpeTypes.CPE("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeCPE,
				query: packageTypes.Query{
					CPE: func() *cpeTypes.Query { s := cpeTypes.Query("cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*"); return &s }(),
				},
			},
			want: true,
		},
		{
			name: "language",
			fields: fields{
				Type:     packageTypes.PackageTypeLanguage,
				Language: &languageTypes.Package{Name: "name"},
			},
			args: args{
				family: ecosystemTypes.EcosystemTypeCargo,
				query: packageTypes.Query{
					Language: &languageTypes.Query{Name: "name"},
				},
			},
			want: true,
		},
		{
			name:    "unknown",
			fields:  fields{Type: packageTypes.PackageTypeUnknown},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := packageTypes.Package{
				Type:     tt.fields.Type,
				Binary:   tt.fields.Binary,
				Source:   tt.fields.Source,
				CPE:      tt.fields.CPE,
				Language: tt.fields.Language,
			}
			got, err := p.Accept(tt.args.family, tt.args.query)
			if (err != nil) != tt.wantErr {
				t.Errorf("Package.Accept() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Package.Accept() = %v, want %v", got, tt.want)
			}
		})
	}
}
