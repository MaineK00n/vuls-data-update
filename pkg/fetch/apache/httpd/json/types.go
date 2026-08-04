package json

// The ASF serves two generations of CVE records side by side under
// /security/json/. Records that predate the migration keep the CVE JSON 4.0
// schema, the rest use the CVE Record Format. Both carry CNA_private, an
// ASF-only member that belongs to neither schema and whose shape differs
// between the two generations.
//
// A field is a pointer or carries omitempty only where the ASF actually omits
// it; members it always emits are required, so that a missing one is a decode
// error rather than a silently zeroed value.

// CVE4 is a record in the CVE JSON 4.0 schema, identified by data_version 4.0.
type CVE4 struct {
	DataType    string `json:"data_type"`
	DataFormat  string `json:"data_format"`
	DataVersion string `json:"data_version"`
	Generator   struct {
		Engine string `json:"engine"`
	} `json:"generator"`
	CVEDataMeta struct {
		ID         string  `json:"ID"`
		Assigner   string  `json:"ASSIGNER"`
		State      string  `json:"STATE"`
		Title      string  `json:"TITLE"`
		AKA        *string `json:"AKA,omitempty"`
		DatePublic *string `json:"DATE_PUBLIC,omitempty"`
	} `json:"CVE_data_meta"`
	Source struct {
		Discovery string   `json:"discovery"`
		Advisory  *string  `json:"advisory,omitempty"`
		Defect    []string `json:"defect,omitempty"`
	} `json:"source"`
	Affects struct {
		Vendor struct {
			VendorData []struct {
				VendorName string `json:"vendor_name"`
				Product    struct {
					ProductData []struct {
						ProductName string `json:"product_name"`
						Version     struct {
							VersionData []Version4 `json:"version_data"`
						} `json:"version"`
					} `json:"product_data"`
				} `json:"product"`
			} `json:"vendor_data"`
		} `json:"vendor"`
	} `json:"affects"`
	ProblemType struct {
		ProblemTypeData []struct {
			Description []LangValue4 `json:"description"`
		} `json:"problemtype_data"`
	} `json:"problemtype"`
	Description struct {
		DescriptionData []LangValue4 `json:"description_data"`
	} `json:"description"`
	References struct {
		ReferenceData []Reference4 `json:"reference_data,omitempty"`
	} `json:"references"`
	Impact []struct {
		Other string `json:"other"`
	} `json:"impact"`
	Timeline      []Timeline4  `json:"timeline"`
	Credit        []LangValue4 `json:"credit,omitempty"`
	Configuration []LangValue4 `json:"configuration,omitempty"`
	Exploit       []LangValue4 `json:"exploit,omitempty"`
	Solution      []LangValue4 `json:"solution,omitempty"`
	WorkAround    []LangValue4 `json:"work_around,omitempty"`
	CNAPrivate    *CNAPrivate4 `json:"CNA_private,omitempty"`
}

type Version4 struct {
	VersionAffected string  `json:"version_affected"`
	VersionValue    string  `json:"version_value"`
	VersionName     *string `json:"version_name,omitempty"`
	Platform        *string `json:"platform,omitempty"`
}

type LangValue4 struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type Reference4 struct {
	Refsource string  `json:"refsource"`
	Name      *string `json:"name,omitempty"`
	URL       *string `json:"url,omitempty"`
}

type Timeline4 struct {
	Lang  string `json:"lang"`
	Time  string `json:"time"`
	Value string `json:"value"`
}

// CNAPrivate4 is the ASF-only extension as it appears in the CVE JSON 4.0
// records. It tracks the security team's internal handling of the report and is
// part of no CVE schema.
type CNAPrivate4 struct {
	Owner               string   `json:"owner"`
	Userslist           *string  `json:"userslist,omitempty"`
	Email               *string  `json:"email,omitempty"`
	Emailed             *string  `json:"emailed,omitempty"`
	InternalComments    *string  `json:"internal_comments,omitempty"`
	ShareWithCVE        *bool    `json:"share_with_CVE,omitempty"`
	CVEList             []string `json:"CVE_list,omitempty"`
	CVETableDescription []string `json:"CVE_table_description,omitempty"`
	Todo                []string `json:"todo,omitempty"`
	Publish             *struct {
		Month string `json:"month"`
		Year  string `json:"year"`
		YM    string `json:"ym"`
	} `json:"publish,omitempty"`
}

// CVE5 is a record in the CVE Record Format, identified by dataVersion 5.x. It
// is the same schema as pkg/fetch/mitre/cve/v5, narrowed to the members the ASF
// emits and extended with CNA_private.
type CVE5 struct {
	DataType    string `json:"dataType"`
	DataVersion string `json:"dataVersion"`
	CVEMetadata struct {
		CVEID         string `json:"cveId"`
		AssignerOrgID string `json:"assignerOrgId"`
		Serial        int    `json:"serial"`
		State         string `json:"state"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			ProviderMetadata struct {
				OrgID string `json:"orgId"`
			} `json:"providerMetadata"`
			Title        string         `json:"title"`
			Descriptions []Description5 `json:"descriptions"`
			Affected     []Affected5    `json:"affected"`
			ProblemTypes []struct {
				Descriptions []struct {
					Lang        string  `json:"lang"`
					Description string  `json:"description"`
					CWEID       *string `json:"cweId,omitempty"`
					Type        *string `json:"type,omitempty"`
				} `json:"descriptions"`
			} `json:"problemTypes"`
			Metrics []struct {
				Other struct {
					Type    string `json:"type"`
					Content struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"other"`
			} `json:"metrics"`
			Timeline []Timeline5 `json:"timeline"`
			Source   struct {
				Discovery string `json:"discovery"`
			} `json:"source"`
			XGenerator struct {
				Engine string `json:"engine"`
			} `json:"x_generator"`
			References []Reference5 `json:"references,omitempty"`
			Credits    []Credit5    `json:"credits,omitempty"`
		} `json:"cna"`
	} `json:"containers"`
	CNAPrivate *CNAPrivate5 `json:"CNA_private,omitempty"`
}

type Description5 struct {
	Lang            string `json:"lang"`
	Value           string `json:"value"`
	SupportingMedia []struct {
		Type   string `json:"type"`
		Base64 bool   `json:"base64"`
		Value  string `json:"value"`
	} `json:"supportingMedia"`
}

type Affected5 struct {
	Vendor        string `json:"vendor"`
	Product       string `json:"product"`
	DefaultStatus string `json:"defaultStatus"`
	Versions      []struct {
		Status          string  `json:"status"`
		Version         string  `json:"version"`
		VersionType     *string `json:"versionType,omitempty"`
		LessThan        *string `json:"lessThan,omitempty"`
		LessThanOrEqual *string `json:"lessThanOrEqual,omitempty"`
	} `json:"versions"`
	CPEs []string `json:"cpes,omitempty"`
}

type Reference5 struct {
	URL  string   `json:"url"`
	Tags []string `json:"tags"`
}

type Credit5 struct {
	Lang  string `json:"lang"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Timeline5 struct {
	Lang  string `json:"lang"`
	Time  string `json:"time"`
	Value string `json:"value"`
}

// CNAPrivate5 is the ASF-only extension as it appears in the CVE Record Format
// records. Its member set differs from CNAPrivate4, so the two generations do
// not share a type.
type CNAPrivate5 struct {
	Owner      string   `json:"owner"`
	State      string   `json:"state"`
	Type       string   `json:"type"`
	Todo       []string `json:"todo"`
	Emailed    *string  `json:"emailed,omitempty"`
	ProjectURL *string  `json:"projecturl,omitempty"`
	Userslist  *string  `json:"userslist,omitempty"`
}
