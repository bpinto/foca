package fake

import (
	"testing"

	"github.com/bpinto/foca/internal/plugin/authntest"
)

// The fake stands in for real authenticators in the core's tests, so it
// must answer as they do.
func TestConformance(t *testing.T) {
	authntest.Run(t, func(t *testing.T) authntest.Harness {
		a := New()
		return authntest.Harness{
			Authenticator: a,
			Can:           []authntest.Answer{authntest.Approve, authntest.Deny, authntest.Ignore, authntest.Unavailable},
			Answer: func(ans authntest.Answer) {
				switch ans {
				case authntest.Approve:
					a.Default = Approve
				case authntest.Deny:
					a.Default = Deny
				case authntest.Ignore:
					a.Default = Hang
				case authntest.Unavailable:
					a.SetUnavailable(true)
				}
			},
			Shown: func() []string {
				var shown []string
				for _, r := range a.Requests() {
					shown = append(shown, r.Prompt)
				}
				return shown
			},
		}
	})
}
