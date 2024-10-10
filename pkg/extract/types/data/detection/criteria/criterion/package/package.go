package criterionpackage

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"

	"github.com/knqyf263/go-cpe/matching"
	"github.com/knqyf263/go-cpe/naming"
	"github.com/pkg/errors"
)

type Package struct {
	Name          string      `json:"name,omitempty"`
	CPE           string      `json:"cpe,omitempty"`
	Architectures []string    `json:"architectures,omitempty"`
	Repositories  []string    `json:"repositories,omitempty"`
	Functions     []string    `json:"functions,omitempty"`
	PatchStatus   PatchStatus `json:"patch_status,omitempty"`
}

type PatchStatus int

const (
	_ PatchStatus = iota
	PatchStatusNeedsTriage

	PatchStatusNotAffected
	PatchStatusNeeded
	PatchStatusDeferred
	PatchStatusPending
	PatchStatusIgnored
	PatchStatusReleased

	PatchStatusUnknown
)

func (s PatchStatus) String() string {
	switch s {
	case PatchStatusNeedsTriage:
		return "needs-triage"
	case PatchStatusNotAffected:
		return "not-affected"
	case PatchStatusNeeded:
		return "needed"
	case PatchStatusDeferred:
		return "deferred"
	case PatchStatusPending:
		return "pending"
	case PatchStatusIgnored:
		return "ignored"
	case PatchStatusReleased:
		return "released"

	case PatchStatusUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

func (p PatchStatus) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *PatchStatus) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("data should be a string, got %s", data)
	}

	var ps PatchStatus
	switch s {
	case "needs-triage":
		ps = PatchStatusNeedsTriage
	case "not-affected":
		ps = PatchStatusNotAffected
	case "needed":
		ps = PatchStatusNeeded
	case "deferred":
		ps = PatchStatusDeferred
	case "pending":
		ps = PatchStatusPending
	case "ignored":
		ps = PatchStatusIgnored
	case "released":
		ps = PatchStatusReleased
	case "unknown":
		ps = PatchStatusUnknown
	default:
		return fmt.Errorf("invalid PatchStatus %s", s)
	}
	*p = ps
	return nil
}

func (p *Package) Sort() {
	slices.Sort(p.Architectures)
	slices.Sort(p.Repositories)
	slices.Sort(p.Functions)
}

func Compare(x, y Package) int {
	return cmp.Or(
		cmp.Compare(x.Name, y.Name),
		cmp.Compare(x.CPE, y.CPE),
		slices.Compare(x.Architectures, y.Architectures),
		slices.Compare(x.Repositories, y.Repositories),
		slices.Compare(x.Functions, y.Functions),
		cmp.Compare(x.PatchStatus, y.PatchStatus),
	)
}

type Query struct {
	Package *QueryPackage
	CPE     *string
}

type QueryPackage struct {
	Name       string
	Arch       string
	Repository string
	Functions  []string
}

func (p Package) Accept(query Query) (bool, error) {
	switch {
	case query.Package != nil:
		if query.Package.Name != p.Name {
			return false, nil
		}

		if query.Package.Arch != "" && len(p.Architectures) > 0 && !slices.Contains(p.Architectures, query.Package.Arch) {
			return false, nil
		}

		if query.Package.Repository != "" && len(p.Repositories) > 0 && !slices.Contains(p.Repositories, query.Package.Repository) {
			return false, nil
		}

		if len(query.Package.Functions) > 0 && len(p.Functions) > 0 && !slices.ContainsFunc(p.Functions, func(e string) bool {
			return slices.Contains(query.Package.Functions, e)
		}) {
			return false, nil
		}

		return true, nil
	case query.CPE != nil:
		wfn1, err := naming.UnbindFS(*query.CPE)
		if err != nil {
			return false, errors.Wrapf(err, "unbind %q to WFN", *query.CPE)
		}

		wfn2, err := naming.UnbindFS(p.CPE)
		if err != nil {
			return false, nil
		}

		return matching.IsSubset(wfn1, wfn2), nil
	default:
		return false, errors.Errorf("query must be set to Package or CPE")
	}
}
