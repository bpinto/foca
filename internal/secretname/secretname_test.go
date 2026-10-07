package secretname

import "testing"

func TestSplit(t *testing.T) {
	for name, want := range map[string][2]string{
		"common:github-pat": {"common", "github-pat"},
		"dev:A_b-1":         {"dev", "A_b-1"},
	} {
		v, id, ok := Split(name)
		if !ok || v != want[0] || id != want[1] || Join(v, id) != name {
			t.Errorf("%s: %q %q %v", name, v, id, ok)
		}
	}
	for _, bad := range []string{"github-pat", ":x", "common:", "Common:x", "a:b:c", "a:b c", "a b:c", "-a:b", "a:" + string(make([]byte, 129))} {
		if _, _, ok := Split(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}
