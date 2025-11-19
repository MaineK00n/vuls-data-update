package list

type Advisory struct {
	ID      string `json:"ID"`
	Title   string `json:"title"`
	Problem []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"problem"`
	Solution []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"solution,omitempty"`
	WorkAround []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"work_around,omitempty"`
	Severity         string   `json:"severity"`
	BaseSeverity     string   `json:"base_severity"`
	BaseScore        float64  `json:"base_score"`
	ThreatSeverity   string   `json:"threat_severity"`
	ThreatScore      *float64 `json:"threat_score,omitempty"`
	ShowCvssInHeader *bool    `json:"show_cvss_in_header,omitempty"`
	AV               string   `json:"AV"`
	AC               string   `json:"AC"`
	PR               string   `json:"PR"`
	UI               string   `json:"UI"`
	C                string   `json:"C"`
	I                string   `json:"I"`
	A                string   `json:"A"`
	Product          []string `json:"product"`
	Version          []string `json:"version,omitempty"`
	Affected         []string `json:"affected,omitempty"`
	AffectedList     []string `json:"affected_list,omitempty"`
	Fixed            []string `json:"fixed,omitempty"`
	Date             string   `json:"date"`
	Updated          string   `json:"updated"`
}
