package ssvc

import (
	"cmp"
	"slices"
	"time"
)

type SSVC struct {
	Source    string     `json:"source,omitempty"`
	ID        string     `json:"id,omitempty"`
	Role      string     `json:"role,omitempty"`
	Version   string     `json:"version,omitempty"`
	Options   []Option   `json:"options,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
}

type Option struct {
	Key   string `json:"key,omitempty"`
	Value string `json:"value,omitempty"`
}

func (s *SSVC) Sort() {
	slices.SortFunc(s.Options, CompareOption)
}

func CompareOption(x, y Option) int {
	return cmp.Or(
		cmp.Compare(x.Key, y.Key),
		cmp.Compare(x.Value, y.Value),
	)
}

func Compare(x, y SSVC) int {
	return cmp.Or(
		cmp.Compare(x.Source, y.Source),
		cmp.Compare(x.ID, y.ID),
		cmp.Compare(x.Role, y.Role),
		cmp.Compare(x.Version, y.Version),
		slices.CompareFunc(x.Options, y.Options, CompareOption),
		func() int {
			switch {
			case x.Timestamp == nil && y.Timestamp == nil:
				return 0
			case x.Timestamp == nil && y.Timestamp != nil:
				return -1
			case x.Timestamp != nil && y.Timestamp == nil:
				return +1
			default:
				return x.Timestamp.Compare(*y.Timestamp)
			}
		}(),
	)
}
