package oval

import "encoding/xml"

type root struct {
	XMLName   xml.Name `xml:"oval_definitions" json:"oval_definitions,omitempty"`
	Xmlns     string   `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Oval      string   `xml:"oval,attr" json:"oval,omitempty"`
	Generator struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
	} `xml:"generator" json:"generator,omitempty"`
	Definitions struct {
		Definition []Definition `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitempty"`
	Tests struct {
		RpminfoTest []RpminfoTest `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	} `xml:"tests" json:"tests,omitempty"`
	Objects struct {
		RpminfoObject []RpminfoObject `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	} `xml:"objects" json:"objects,omitempty"`
	States struct {
		RpminfoState []RpminfoState `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	} `xml:"states" json:"states,omitempty"`
}

type Definition struct {
	Class    string `xml:"class,attr" json:"class,omitempty"`
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Metadata struct {
		Title    string `xml:"title"`
		Affected struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform"`
		} `xml:"affected" json:"affected,omitempty"`
		Reference []struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitempty"`
		Description string `xml:"description"`
		Advisory    struct {
			From     string `xml:"from,attr" json:"from,omitempty"`
			Severity string `xml:"severity"`
			Rights   string `xml:"rights"`
			Issued   struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"issued" json:"issued,omitempty"`
			Updated struct {
				Date string `xml:"date,attr" json:"date,omitempty"`
			} `xml:"updated" json:"updated,omitempty"`
			Cve []string `xml:"cve"`
		} `xml:"advisory" json:"advisory,omitempty"`
	} `xml:"metadata" json:"metadata,omitempty"`
	Criteria struct {
		Operator  string `xml:"operator,attr" json:"operator,omitempty"`
		Criterion struct {
			Comment string `xml:"comment,attr" json:"comment,omitempty"`
			TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
		} `xml:"criterion" json:"criterion,omitempty"`
		Criteria struct {
			Operator string `xml:"operator,attr" json:"operator,omitempty"`
			Criteria []struct {
				Operator  string `xml:"operator,attr" json:"operator,omitempty"`
				Criterion []struct {
					Comment string `xml:"comment,attr" json:"comment,omitempty"`
					TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
				} `xml:"criterion" json:"criterion,omitempty"`
			} `xml:"criteria" json:"criteria,omitempty"`
		} `xml:"criteria" json:"criteria,omitempty"`
	} `xml:"criteria" json:"criteria,omitempty"`
}

type RpminfoTest struct {
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitempty"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitempty"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Xmlns   string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Name    string `xml:"name"`
}

type RpminfoState struct {
	ID          string `xml:"id,attr" json:"id,omitempty"`
	AttrVersion string `xml:"version,attr" json:"attr_version,omitempty"`
	Xmlns       string `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Version     struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"version" json:"version,omitempty"`
	Evr struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitempty"`
	SignatureKeyid struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"signature_keyid" json:"signature_keyid,omitempty"`
}
