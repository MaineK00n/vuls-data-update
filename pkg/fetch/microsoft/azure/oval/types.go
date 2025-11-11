package oval

import "encoding/xml"

type root struct {
	XMLName        xml.Name `xml:"oval_definitions" json:"oval_definitions,omitzero"`
	Xmlns          string   `xml:"xmlns,attr" json:"xmlns,omitempty"`
	Oval           string   `xml:"oval,attr" json:"oval,omitempty"`
	LinuxDef       string   `xml:"linux-def,attr" json:"linux-def,omitempty"`
	Xsi            string   `xml:"xsi,attr" json:"xsi,omitempty"`
	SchemaLocation string   `xml:"schemaLocation,attr" json:"schemalocation,omitempty"`
	Generator      struct {
		ProductName    string `xml:"product_name"`
		ProductVersion string `xml:"product_version"`
		SchemaVersion  string `xml:"schema_version"`
		Timestamp      string `xml:"timestamp"`
		ContentVersion string `xml:"content_version"`
	} `xml:"generator" json:"generator,omitzero"`
	Definitions struct {
		Definition []Definition `xml:"definition" json:"definition,omitempty"`
	} `xml:"definitions" json:"definitions,omitzero"`
	Tests struct {
		RpminfoTest []RpminfoTest `xml:"rpminfo_test" json:"rpminfo_test,omitempty"`
	} `xml:"tests" json:"tests,omitzero"`
	Objects struct {
		RpminfoObject []RpminfoObject `xml:"rpminfo_object" json:"rpminfo_object,omitempty"`
	} `xml:"objects" json:"objects,omitzero"`
	States struct {
		RpminfoState []RpminfoState `xml:"rpminfo_state" json:"rpminfo_state,omitempty"`
	} `xml:"states" json:"states,omitzero"`
}

type Definition struct {
	Class    string `xml:"class,attr" json:"class,omitempty"`
	ID       string `xml:"id,attr" json:"id,omitempty"`
	Version  string `xml:"version,attr" json:"version,omitempty"`
	Metadata struct {
		Title    string `xml:"title" json:"Title,omitempty"`
		Affected struct {
			Family   string `xml:"family,attr" json:"family,omitempty"`
			Platform string `xml:"platform" json:"Platform,omitempty"`
		} `xml:"affected" json:"affected,omitzero"`
		Reference struct {
			RefID  string `xml:"ref_id,attr" json:"ref_id,omitempty"`
			RefURL string `xml:"ref_url,attr" json:"ref_url,omitempty"`
			Source string `xml:"source,attr" json:"source,omitempty"`
		} `xml:"reference" json:"reference,omitzero"`
		Patchable    string `xml:"patchable" json:"Patchable,omitempty"`
		AdvisoryDate string `xml:"advisory_date" json:"AdvisoryDate,omitempty"`
		AdvisoryID   string `xml:"advisory_id" json:"AdvisoryID,omitempty"`
		Severity     string `xml:"severity" json:"Severity,omitempty"`
		Description  string `xml:"description" json:"Description,omitempty"`
	} `xml:"metadata" json:"metadata,omitzero"`
	Criteria struct {
		Operator  string `xml:"operator,attr" json:"operator,omitempty"`
		Criterion []struct {
			Comment string `xml:"comment,attr" json:"comment,omitempty"`
			TestRef string `xml:"test_ref,attr" json:"test_ref,omitempty"`
		} `xml:"criterion" json:"criterion,omitempty"`
	} `xml:"criteria" json:"criteria,omitzero"`
}

type RpminfoTest struct {
	Check   string `xml:"check,attr" json:"check,omitempty"`
	Comment string `xml:"comment,attr" json:"comment,omitempty"`
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Object  struct {
		ObjectRef string `xml:"object_ref,attr" json:"object_ref,omitempty"`
	} `xml:"object" json:"object,omitzero"`
	State struct {
		StateRef string `xml:"state_ref,attr" json:"state_ref,omitempty"`
	} `xml:"state" json:"state,omitzero"`
}

type RpminfoObject struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Name    string `xml:"name" json:"Name,omitempty"`
}

type RpminfoState struct {
	ID      string `xml:"id,attr" json:"id,omitempty"`
	Version string `xml:"version,attr" json:"version,omitempty"`
	Evr     struct {
		Text      string `xml:",chardata" json:"text,omitempty"`
		Datatype  string `xml:"datatype,attr" json:"datatype,omitempty"`
		Operation string `xml:"operation,attr" json:"operation,omitempty"`
	} `xml:"evr" json:"evr,omitzero"`
}
