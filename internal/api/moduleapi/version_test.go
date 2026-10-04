package moduleapi

import (
	"context"
	"slices"
	"testing"

	"connectrpc.com/connect"
)

func TestVersionsAreOrderedAsKubernetesOrdersThem(t *testing.T) {
	ordered := []string{"not-a-version", "v1alpha1", "v1alpha2", "v1alpha10", "v1beta1", "v1", "v2alpha1", "v2", "v10"}
	shuffled := []string{"v2", "v1alpha10", "v10", "v1", "not-a-version", "v2alpha1", "v1beta1", "v1alpha2", "v1alpha1"}
	if got := slices.SortedFunc(slices.Values(shuffled), compareVersions); !slices.Equal(got, ordered) {
		t.Fatalf("got %v, want %v", got, ordered)
	}
	for _, v := range []string{"", "v0", "v01", "v1alpha", "v1alpha0", "v1gamma1", "V1", "v1alpha1 "} {
		if compareVersions(v, "v1alpha1") >= 0 {
			t.Errorf("%q orders at or after v1alpha1; it should not parse", v)
		}
	}
}

// CORE-3: the highest version that both sides support, or
// FAILED_PRECONDITION naming the core's.
func TestNegotiateVersion(t *testing.T) {
	supported := ContractVersions
	t.Cleanup(func() { ContractVersions = supported })
	ContractVersions = []string{"v1alpha1", "v1beta1", "v1"}

	for _, tt := range []struct {
		offered []string
		want    string
	}{
		{[]string{"v1alpha1"}, "v1alpha1"},
		{[]string{"v1alpha1", "v1beta1"}, "v1beta1"},
		{[]string{"v1", "v1alpha1", "v2"}, "v1"},
		{[]string{"v2", "v1beta1", "v1alpha2"}, "v1beta1"},
	} {
		if got, err := NegotiateVersion(tt.offered); err != nil || got != tt.want {
			t.Errorf("offered %v: got %q, %v; want %q", tt.offered, got, err, tt.want)
		}
	}
	for _, offered := range [][]string{nil, {"v2"}, {"v1alpha2", "garbage"}} {
		_, err := NegotiateVersion(offered)
		if connect.CodeOf(err) != connect.CodeFailedPrecondition ||
			message(err) != "no contract version in common: the core supports v1alpha1, v1beta1, v1" {
			t.Errorf("offered %v: got %v, want FAILED_PRECONDITION naming the supported versions", offered, err)
		}
	}
}

func TestProcedureVersion(t *testing.T) {
	for procedure, want := range map[string]string{
		"/whitetower.module.v1alpha1.MetaService/GetServerInfo": "v1alpha1",
		"/whitetower.module.v1.RegistryService/Heartbeat":       "v1",
		"/Service/Method": "",
		"":                "",
	} {
		if got := procedureVersion(procedure); got != want {
			t.Errorf("%q: got %q, want %q", procedure, got, want)
		}
	}
	if v := ContractVersion(context.Background()); v != "" {
		t.Errorf("outside a call: %q", v)
	}
}
