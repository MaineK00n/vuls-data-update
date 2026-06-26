// Package missing lists Palo Alto Networks advisory IDs that are advertised by
// the list endpoint (https://security.paloaltonetworks.com/json/?page=) but
// whose per-advisory machine-readable endpoints (/json/<id>, /csaf/<id>) return
// HTTP 404 — a known upstream regression (the human-readable HTML pages still
// return 200, so the advisories themselves exist).
//
// The json/csaf fetchers tolerate a 404 only for these IDs; any other 404 is
// treated as an error so a new regression surfaces loudly instead of being
// silently skipped. Once upstream restores these endpoints this list should be
// emptied / removed — see MaineK00n/vuls-data-update#864 and vuls-data-db
// docs/paloalto-missing-json-csaf-ids.md.
package missing

var ids = map[string]struct{}{
	"CVE-2022-42889":   {},
	"PAN-SA-2014-0001": {},
	"PAN-SA-2014-0002": {},
	"PAN-SA-2014-0004": {},
	"PAN-SA-2014-0006": {},
	"PAN-SA-2015-0003": {},
	"PAN-SA-2015-0005": {},
	"PAN-SA-2015-0006": {},
	"PAN-SA-2016-0006": {},
	"PAN-SA-2016-0007": {},
	"PAN-SA-2016-0008": {},
	"PAN-SA-2016-0010": {},
	"PAN-SA-2016-0011": {},
	"PAN-SA-2016-0013": {},
	"PAN-SA-2016-0014": {},
	"PAN-SA-2016-0015": {},
	"PAN-SA-2016-0016": {},
	"PAN-SA-2016-0017": {},
	"PAN-SA-2016-0018": {},
	"PAN-SA-2016-0019": {},
	"PAN-SA-2016-0020": {},
	"PAN-SA-2016-0022": {},
	"PAN-SA-2016-0023": {},
	"PAN-SA-2016-0024": {},
	"PAN-SA-2016-0025": {},
	"PAN-SA-2016-0026": {},
	"PAN-SA-2016-0028": {},
	"PAN-SA-2016-0029": {},
	"PAN-SA-2016-0030": {},
	"PAN-SA-2016-0031": {},
	"PAN-SA-2016-0032": {},
	"PAN-SA-2016-0033": {},
	"PAN-SA-2018-0001": {},
	"PAN-SA-2018-0011": {},
	"PAN-SA-2018-0015": {},
	"PAN-SA-2019-0004": {},
	"PAN-SA-2019-0011": {},
	"PAN-SA-2019-0012": {},
	"PAN-SA-2019-0013": {},
	"PAN-SA-2022-0006": {},
	"PAN-SA-2022-0007": {},
}

// Is reports whether id is a known advisory whose per-advisory JSON/CSAF
// endpoint is expected to return HTTP 404 (a known upstream regression).
func Is(id string) bool {
	_, ok := ids[id]
	return ok
}
