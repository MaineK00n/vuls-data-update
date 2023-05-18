package bulletin

type Bulletin struct {
	DatePosted        string `xlsx:"0" json:"date_posted,omitempty"`
	BulletinID        string `xlsx:"1" json:"bulletin_id,omitempty"`
	BulletinKB        string `xlsx:"2" json:"bulletin_kb,omitempty"`
	BulletinSeverity  string `xlsx:"3" json:"bulletin_severity,omitempty"`
	BulletinImpact    string `xlsx:"4" json:"bulletin_impact,omitempty"`
	Title             string `xlsx:"5" json:"title,omitempty"`
	AffectedProduct   string `xlsx:"6" json:"affected_product,omitempty"`
	ComponentKB       string `xlsx:"7" json:"component_kb,omitempty"`
	AffectedComponent string `xlsx:"8" json:"affected_component,omitempty"`
	Impact            string `xlsx:"9" json:"impact,omitempty"`
	Severity          string `xlsx:"10" json:"severity,omitempty"`
	Reboot            string `xlsx:"12" json:"reboot,omitempty"`
	CVEs              string `xlsx:"13" json:"cv_es,omitempty"`
}
