package build

import "time"

type Vulnerability struct {
	ID          string               `json:"id,omitempty"`
	Title       map[string]string    `json:"title,omitempty"`
	Description map[string]string    `json:"description,omitempty"`
	Published   map[string]time.Time `json:"published,omitempty"`
	Modified    map[string]time.Time `json:"modified,omitempty"`
	References  []Reference          `json:"references,omitempty"`
}

type Reference struct {
	Source string `json:"source,omitempty"`
	ID     string `json:"id,omitempty"`
	URL    string `json:"url,omitempty"`
}
