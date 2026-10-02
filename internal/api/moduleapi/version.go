package moduleapi

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"connectrpc.com/connect"
)

// ContractVersions lists the module contract versions the core supports. The
// protobuf package carries the version: whitetower.module.v1alpha1.
var ContractVersions = []string{"v1alpha1"}

// NegotiateVersion selects the contract version of an instance's session:
// the highest that both the instance, offering its versions in
// RegisterInstance, and the core support. With none in common it answers
// FAILED_PRECONDITION, naming the versions the core supports (CORE-3).
func NegotiateVersion(offered []string) (string, error) {
	best := ""
	for _, v := range offered {
		if slices.Contains(ContractVersions, v) && (best == "" || compareVersions(v, best) > 0) {
			best = v
		}
	}
	if best == "" {
		return "", connect.NewError(connect.CodeFailedPrecondition,
			fmt.Errorf("no contract version in common: the core supports %s", strings.Join(ContractVersions, ", ")))
	}
	return best, nil
}

var versionPattern = regexp.MustCompile(`^v([1-9][0-9]*)(?:(alpha|beta)([1-9][0-9]*))?$`)

// compareVersions orders contract versions as Kubernetes orders API versions:
// v1alpha1 < v1alpha2 < v1beta1 < v1 < v2alpha1 < v2. Versions that do not
// parse come first.
func compareVersions(a, b string) int {
	return slices.Compare(versionKey(a), versionKey(b))
}

func versionKey(v string) []int {
	m := versionPattern.FindStringSubmatch(v)
	if m == nil {
		return []int{-1}
	}
	major, _ := strconv.Atoi(m[1])
	stability := map[string]int{"alpha": 0, "beta": 1, "": 2}[m[2]]
	n, _ := strconv.Atoi(m[3])
	return []int{major, stability, n}
}

type versionKeyType struct{}

// ContractVersion returns the contract version of the call that ctx belongs
// to, from the protobuf package of its procedure. Plan P1-07 checks that an
// instance keeps to the version it negotiated (I-3).
func ContractVersion(ctx context.Context) string {
	v, _ := ctx.Value(versionKeyType{}).(string)
	return v
}

// procedureVersion returns the version in a procedure such as
// "/whitetower.module.v1alpha1.MetaService/GetServerInfo".
func procedureVersion(procedure string) string {
	service, _, _ := strings.Cut(strings.TrimPrefix(procedure, "/"), "/")
	parts := strings.Split(service, ".")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-2]
}
