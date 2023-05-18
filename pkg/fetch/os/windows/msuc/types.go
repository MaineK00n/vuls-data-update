package msuc

type Update struct {
	UpdateID           string         `json:"update_id,omitempty"`
	Title              string         `json:"title,omitempty"`
	Description        string         `json:"description,omitempty"`
	Architecture       string         `json:"architecture,omitempty"`
	Classification     string         `json:"classification,omitempty"`
	SupportedProducts  string         `json:"supported_products,omitempty"`
	SupportedLanguages string         `json:"supported_languages,omitempty"`
	SecurityBulliten   string         `json:"security_bulliten,omitempty"`
	MSRCSeverity       string         `json:"msrc_severity,omitempty"`
	KBArticle          string         `json:"kb_article,omitempty"`
	MoreInfo           string         `json:"more_info,omitempty"`
	SupportURL         string         `json:"support_url,omitempty"`
	Supersededby       []Supersededby `json:"supersededby,omitempty"`
	Supersedes         []string       `json:"supersedes,omitempty"`
	RebootBehavior     string         `json:"reboot_behavior,omitempty"`
	UserInput          string         `json:"user_input,omitempty"`
	InstallationImpact string         `json:"installation_impact,omitempty"`
	Connectivity       string         `json:"connectivity,omitempty"`
	UninstallNotes     string         `json:"uninstall_notes,omitempty"`
	UninstallSteps     string         `json:"uninstall_steps,omitempty"`
	LastModified       string         `json:"last_modified,omitempty"`
}

type Supersededby struct {
	Title    string `json:"title,omitempty"`
	UpdateID string `json:"update_id,omitempty"`
}
