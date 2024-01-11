package cwe

type CWE struct {
	Source string   `json:"source,omitempty"`
	CWE    []string `json:"cwe,omitempty"`
}
