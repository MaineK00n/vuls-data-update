package reference

import (
	"encoding/json"
	"fmt"
)

type Reference struct {
	Name   string    `json:"name,omitempty"`
	Source string    `json:"source,omitempty"`
	Tags   []TagType `json:"tags,omitempty"`
	URL    string    `json:"url,omitempty"`
}

type TagType int

const (
	_ TagType = iota
	TagVendorAdvisory
	TagThirdPartyAdvisory
	TagCVE
	TagBugzilla
	TagExploit
	TagMISC
)

func (t TagType) String() string {
	switch t {
	case TagVendorAdvisory:
		return "vendor-advisory"
	case TagThirdPartyAdvisory:
		return "third-party-advisory"
	case TagCVE:
		return "cve"
	case TagBugzilla:
		return "bugzilla"
	case TagExploit:
		return "exploit"
	case TagMISC:
		return "misc"
	default:
		return ""
	}
}

func (t TagType) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.String())
}

func (t *TagType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var tt TagType
	switch s {
	case "vendor-advisory":
		tt = TagVendorAdvisory
	case "third-party-advisory":
		tt = TagThirdPartyAdvisory
	case "cve":
		tt = TagCVE
	case "bugzilla":
		tt = TagBugzilla
	case "exploit":
		tt = TagExploit
	case "misc":
		tt = TagMISC
	default:
		return fmt.Errorf("invalid TagType %s", s)
	}
	*t = tt
	return nil
}
