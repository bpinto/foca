//go:build !foca_testing

package wiring

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/bpinto/foca/internal/config"
	"github.com/bpinto/foca/internal/plugins/authn/polkit"
	"github.com/bpinto/foca/internal/plugins/authn/polkit/polkittest"
	"github.com/bpinto/foca/internal/plugins/events/logind"
)

// In a production build, no config can select the always-approving fake.
func TestFakeAuthenticatorRefusedInProductionBuild(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"fake\"\nsecret_store = \"memory\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_, err = Build(cfg, config.Paths{DataDir: filepath.Join(dir, "d"), RuntimeDir: filepath.Join(dir, "r")}, "test",
		slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err == nil || !strings.Contains(err.Error(), "only available in test builds") {
		t.Fatalf("got %v", err)
	}
	if TestBuild {
		t.Fatal("TestBuild set in a production build")
	}
}

func TestUnknownAuthenticatorsRefused(t *testing.T) {
	for _, name := range []string{"anything", "fido2", "pinentry"} {
		if _, err := authenticator(&env{}, name); err == nil || !strings.Contains(err.Error(), "unknown authenticator") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestPlannedKeyProtectorsSayTheyAreNotImplemented(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"x\"\nsecret_store = \"vault-file\"\nkey_protector = \"libsecret\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyProtector(&env{cfg: cfg}, config.Paths{}); err == nil || !strings.Contains(err.Error(), "not implemented yet") {
		t.Fatalf("got %v", err)
	}
}

// In a production build, no config can keep the vault key in a plain file.
func TestFileProtectorRefusedInProductionBuild(t *testing.T) {
	cfg, err := config.Parse([]byte("version = 1\n[plugins]\nauthenticator = \"x\"\nsecret_store = \"vault-file\"\nkey_protector = \"file\"\n[instances.dev]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyProtector(&env{cfg: cfg}, config.Paths{}); err == nil || !strings.Contains(err.Error(), "only available in test builds") {
		t.Fatalf("got %v", err)
	}
}

// In a production build, polkit and logind use the system bus at its fixed
// path, whatever the environment names: a bus someone else runs could hand
// polkit's or logind's name to anything.
func TestSystemBusIsNotTakenFromTheEnvironment(t *testing.T) {
	addr := polkittest.Bus(t)
	f := polkittest.StartFake(t, addr, polkit.Message, "unix-user:"+strconv.Itoa(os.Getuid()))
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", addr)
	t.Setenv("FOCA_SYSTEM_BUS", addr)
	a, err := authenticator(&env{}, "polkit")
	if err != nil {
		t.Fatal(err)
	}
	a.Available(context.Background())
	if len(f.Checks()) > 0 {
		t.Fatal("polkit asked the bus the environment names")
	}

	src, err := eventSources["logind"](&env{})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := src.(*logind.Source).Dial(); err == nil {
		defer conn.Close()
		var got, private string
		conn.BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&got)
		polkittest.Connect(t, addr).BusObject().Call("org.freedesktop.DBus.GetId", 0).Store(&private)
		if got == private {
			t.Fatal("logind dialled the bus the environment names")
		}
	}
}
