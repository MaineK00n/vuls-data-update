package source

import (
	"encoding/json"
	"fmt"
)

type SourceID int

const (
	_ SourceID = iota
	AlmaErrata
	AlmaOSV
	EPSS
)

func (id SourceID) String() string {
	switch id {
	case AlmaErrata:
		return "alma-errata"
	case AlmaOSV:
		return "alma-osv"
	case EPSS:
		return "epss"
	default:
		return ""
	}
}

func (id SourceID) MarshalJSON() ([]byte, error) {
	return json.Marshal(id.String())
}

func (id *SourceID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var sid SourceID
	switch s {
	case "alma-errata":
		sid = AlmaErrata
	case "alma-osv":
		sid = AlmaOSV
	case "epss":
		sid = EPSS
	default:
		return fmt.Errorf("invalid SourceID %s", s)
	}
	*id = sid
	return nil
}
