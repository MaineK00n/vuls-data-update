package time

import "time"

func Parse(layouts []string, value string) *time.Time {
	for _, layout := range layouts {
		t, err := time.Parse(layout, value)
		if err == nil {
			return &t
		}
	}
	return nil
}
