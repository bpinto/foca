package helper

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bpinto/foca/internal/plugin/authntest"
)

// The authenticator conformance suite, through the adapter, against the
// fake helper. A real helper can't be scripted; its own suite covers it.
func TestAuthenticatorConformance(t *testing.T) {
	fakeOnly(t)
	authntest.Run(t, func(t *testing.T) authntest.Harness {
		h, home := open(t, "", KindAuthenticator)
		return authntest.Harness{
			Authenticator: NewAuthenticator(h, "touchid", false),
			Can:           []authntest.Answer{authntest.Approve, authntest.Deny, authntest.Ignore, authntest.Unavailable},
			Answer: func(a authntest.Answer) {
				script := map[authntest.Answer]string{
					authntest.Approve: "approve", authntest.Deny: "deny",
					authntest.Ignore: "hang", authntest.Unavailable: "unavailable",
				}[a]
				os.WriteFile(filepath.Join(home, "fake-helper.json"), []byte(`{"approve":"`+script+`"}`), 0o600)
			},
			Shown: func() []string { return shownReasons(home) },
			Grace: h.cfg.Grace,
		}
	})
}

// shownReasons reads the prompts the fake helper was asked to show.
func shownReasons(home string) []string {
	f, err := os.Open(filepath.Join(home, "calls.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var shown []string
	for sc := bufio.NewScanner(f); sc.Scan(); {
		var c struct {
			Op     string `json:"op"`
			Params struct {
				Reason string `json:"reason"`
			} `json:"params"`
		}
		if json.Unmarshal(sc.Bytes(), &c) == nil && c.Op == "approve" {
			shown = append(shown, c.Params.Reason)
		}
	}
	return shown
}
