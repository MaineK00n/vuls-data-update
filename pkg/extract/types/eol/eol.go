package eol

import "time"

type EOL struct {
	Ended bool                 `json:"ended"`
	Date  map[string]time.Time `json:"date,omitempty"`
}

func (d *EOL) Sort() {}
