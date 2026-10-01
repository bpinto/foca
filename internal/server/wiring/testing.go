//go:build foca_testing

package wiring

import (
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
)

// In test builds only, "fake" approves everything. Production builds can't
// select it, so no config line can turn approval off.
func init() {
	TestBuild = true
	authenticators["fake"] = func() (plugin.Authenticator, error) {
		a := fake.New()
		a.Default = fake.Approve
		return a, nil
	}
}
