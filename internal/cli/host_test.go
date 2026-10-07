package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/identity"
	"github.com/bpinto/foca/internal/plugin"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/store/memory"
	"github.com/bpinto/foca/internal/protocol"
	"github.com/bpinto/foca/internal/server/core"
	"github.com/bpinto/foca/internal/server/wiring"
)

// Ctrl-C on a host command's prompt cancels it through the core, and the
// command keeps the prompt lock through the pause after it before it exits,
// as the service does. Otherwise the lock would drop with the process, and a
// realm's queued prompt could open at once under a finger reaching for the
// one that closed.
func TestHostCommandHoldsThePromptLockThroughThePause(t *testing.T) {
	lock := fsutil.PrivateLock(filepath.Join(t.TempDir(), "run"), "prompt.lock")
	auth := fake.New()
	auth.Default = fake.Hang
	auth.Started = make(chan plugin.ApprovalRequest, 1)
	sink := audit.NewMemory()
	const pause = 300 * time.Millisecond
	svc := core.New(core.Options{Authenticator: auth, Audit: sink, PromptTimeout: time.Minute, MaxQueue: 1,
		PromptPause: pause, PromptLock: lock}, nil, map[string]plugin.SecretStore{"common": memory.New()})
	op := &hostOp{host: &wiring.Host{Core: svc, Audit: sink}, vault: "common", unlock: func() error { return nil },
		call: core.HostCall("req-1", "common", identity.VerifiedPeer{PID: os.Getpid()})}
	env, _, _ := testEnv(t, nil)
	sigs := make(chan chan<- os.Signal, 1)
	env.Signals = func(ch chan<- os.Signal) { sigs <- ch }

	errc := make(chan error, 1)
	go func() {
		ctx, done := opContext(env)
		defer done()
		_, err := svc.AddSecret(ctx, op.call, core.NewSecret{ID: "x", Value: []byte("v")})
		errc <- err
	}()
	sig := <-sigs
	<-auth.Started
	sig <- syscall.SIGINT
	var err error
	select {
	case err = <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("the signal didn't cancel the prompt")
	}
	if pe := (*protocol.Error)(nil); !errors.As(err, &pe) || pe.Code != protocol.CodeTimeout {
		t.Fatalf("cancelled add: %v", err)
	}
	cancelled := time.Now()
	op.close()
	// The process exits once close returns, and its lock drops with it.
	if d := time.Since(cancelled); d < pause-50*time.Millisecond {
		t.Fatalf("closed %v after the cancel; the pause is %v", d, pause)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	release, err := lock(ctx)
	if err != nil {
		t.Fatalf("prompt lock still held after close: %v", err)
	}
	release()
}
