package api

import "time"

type response struct {
	Message string   `json:"message"`
	Count   int      `json:"count"`
	Total   int      `json:"total"`
	Results []Result `json:"results"`
}

type Result struct {
	URI            string   `json:"uri,omitempty"`
	ID             string   `json:"id,omitempty"`
	Name           string   `json:"name,omitempty"`
	Author         []string `json:"author,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Type           string   `json:"type,omitempty"`
	Dir            string   `json:"dir,omitempty"`
	Ref            string   `json:"ref,omitempty"`
	Vendor         string   `json:"vendor,omitempty"`
	Product        string   `json:"product,omitempty"`
	Classification struct {
		CVEID          []string `json:"cve-id,omitempty"`
		CWEID          []string `json:"cwe-id,omitempty"`
		CVSSMetrics    string   `json:"cvss-metrics,omitempty"`
		CVSSScore      float64  `json:"cvss-score,omitempty"`
		EPSSScore      float64  `json:"epss-score,omitempty"`
		EPSSPercentile float64  `json:"epss-percentile,omitempty"`
		CPE            string   `json:"cpe,omitempty"`
	} `json:"classification,omitzero"`
	Metadata    interface{} `json:"metadata,omitempty"`
	Digest      string      `json:"digest,omitempty"`
	CreatedAt   time.Time   `json:"created_at,omitzero"`
	UpdatedAt   time.Time   `json:"updated_at,omitzero"`
	ReleaseTag  string      `json:"release_tag,omitempty"`
	IsEarly     bool        `json:"is_early,omitempty"`
	Raw         string      `json:"raw,omitempty"`
	TemplateID  string      `json:"template_id,omitempty"`
	Description string      `json:"description,omitempty"`
	Filename    string      `json:"filename,omitempty"`
	Impact      string      `json:"impact,omitempty"`
	AIMeta      struct {
		ModelUsed         string `json:"model_used,omitempty"`
		IsPromptByHuman   bool   `json:"is_prompt_by_human,omitempty"`
		IsTemplateByHuman bool   `json:"is_template_by_human,omitempty"`
		Prompt            string `json:"prompt,omitempty"`
	} `json:"ai_meta,omitzero"`
	References   []string `json:"references,omitempty"`
	TemplateType string   `json:"template_type,omitempty"`
	IsDraft      bool     `json:"is_draft,omitempty"`
	IsGitHub     bool     `json:"is_github,omitempty"`
	IsNew        bool     `json:"is_new,omitempty"`
	IsPDResearch bool     `json:"is_pdresearch,omitempty"`
	IsPDTeam     bool     `json:"is_pdteam,omitempty"`
	IsPDTemplate bool     `json:"is_pdtemplate,omitempty"`
	Remediation  string   `json:"remediation,omitempty"`
}
