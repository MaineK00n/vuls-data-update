package json

// Test-only exports so package json_test can exercise the PAN-OS changes[]
// interpretation (the most intricate, golden-test-opaque part of the
// extractor) directly.

// PanosStanza mirrors the unexported panosStanza for tests.
type PanosStanza struct {
	Status          string
	Version         string
	LessThan        string
	LessThanOrEqual string
	Changes         []PanosChange
}

// PanosChange mirrors the unexported panosChange for tests.
type PanosChange struct {
	At     string
	Status string
}

// PanosInterval mirrors the unexported panosInterval for tests.
type PanosInterval struct {
	GE, GT, LE, LT string
	Fixed          []string
}

// PanosStanzaIntervals runs panosStanzaIntervals over test-constructed input.
func PanosStanzaIntervals(s PanosStanza) ([]PanosInterval, error) {
	cs := make([]panosChange, 0, len(s.Changes))
	for _, c := range s.Changes {
		cs = append(cs, panosChange{at: c.At, status: c.Status})
	}
	is, err := panosStanzaIntervals(panosStanza{
		status:          s.Status,
		version:         s.Version,
		lessThan:        s.LessThan,
		lessThanOrEqual: s.LessThanOrEqual,
		changes:         cs,
	})
	if err != nil {
		return nil, err
	}
	if is == nil {
		return nil, nil
	}
	out := make([]PanosInterval, 0, len(is))
	for _, i := range is {
		out = append(out, PanosInterval{GE: i.ge, GT: i.gt, LE: i.le, LT: i.lt, Fixed: i.fixed})
	}
	return out, nil
}
