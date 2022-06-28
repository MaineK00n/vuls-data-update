package repository2cpe

import "time"

type RepositoryToCPE struct {
	Data map[string]struct {
		Cpes             []string `json:"cpes,omitempty"`
		RepoRelativeURLs []string `json:"repo_relative_urls,omitempty"`
	} `json:"data,omitempty"`
	LastUpdated time.Time `json:"last_updated,omitempty"`
}
