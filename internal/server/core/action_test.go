package core

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bpinto/foca/internal/action"
	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/plugins/authn/fake"
	"github.com/bpinto/foca/internal/plugins/provider/command"
	"github.com/bpinto/foca/internal/policy"
	"github.com/bpinto/foca/internal/protocol"
)

const awsJSON = `{"Version":1,"AccessKeyId":"AKIA","SecretAccessKey":"s"}`

// withActions offers the harness instance three actions: aws (a param,
// output checked), gh (uses github-pat) and fails (exits 3). Each run
// appends a line to the returned log file.
func withActions(t *testing.T, h *harness) (runs string) {
	t.Helper()
	dir := t.TempDir()
	runs = filepath.Join(dir, "runs")
	sh := func(name, body string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte("#!/bin/sh\necho \"$FOCA_ACTION $*\" >> "+runs+"\n"+body), 0o700)
		return p
	}
	env := map[string]string{"PATH": os.Getenv("PATH")}
	specs := []*action.Spec{
		{ID: "aws", Description: "AWS credentials", Command: sh("aws", "printf '%s' '"+awsJSON+"'"),
			Args: []string{"--profile", "{profile}"}, Format: action.FormatAWSCredProc, Env: env,
			Params: map[string]*action.Param{"profile": {Allowed: []string{"dev-admin", "prod-admin"}}}},
		{ID: "gh", Description: "List PRs", Command: sh("gh", `echo "token $GH_TOKEN"; echo "err $GH_TOKEN" >&2`),
			Env: env, EnvSecrets: map[string]string{"GH_TOKEN": "common:github-pat"}, Mask: true},
		{ID: "fails", Command: sh("fails", "echo out; exit 3"), Env: env},
		{ID: "uses-hidden", Command: sh("hidden", "true"), Env: env, EnvSecrets: map[string]string{"T": "common:prod-db"}},
	}
	for _, s := range specs {
		if err := s.Check(); err != nil {
			t.Fatal(err)
		}
	}
	h.inst.Actions = command.New(specs, h.inst.Secrets)
	return runs
}

func (h *harness) run(t *testing.T, c Call, name string, params map[string]string) (*ActionOutput, error) {
	t.Helper()
	return h.svc.RunAction(context.Background(), c, name, params)
}

func ranTimes(runs string) int {
	b, _ := os.ReadFile(runs)
	return strings.Count(string(b), "\n")
}

func TestRunActionIsApprovedRunAndAudited(t *testing.T) {
	h := newHarness(t, fake.Approve)
	runs := withActions(t, h)
	out, err := h.run(t, h.call(), "aws", map[string]string{"profile": "dev-admin"})
	if err != nil {
		t.Fatal(err)
	}
	if out.ExitCode != 0 || string(out.Stdout) != awsJSON {
		t.Fatalf("out %+v", out)
	}
	if b, _ := os.ReadFile(runs); string(b) != "aws --profile dev-admin\n" {
		t.Fatalf("ran %q", b)
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "approval.granted:ok", "action.run:ok")
	g, r := evs[0], evs[1]
	if g.Resources[0] != (audit.Resource{Kind: "action", ID: "aws"}) || g.Params["profile"] != "dev-admin" {
		t.Fatalf("approval %+v", g)
	}
	want := `run "AWS credentials" with profile=dev-admin in VM dev. VM claims: aws via claude.`
	if g.Approval.PromptText != want {
		t.Fatalf("prompt\n got %q\nwant %q", g.Approval.PromptText, want)
	}
	if req := h.auth.Requests()[0]; req.Operation != "action.run" || req.Params["profile"] != "dev-admin" {
		t.Fatalf("approval request %+v", req)
	}
	if r.Resource.ID != "aws" || r.Params["profile"] != "dev-admin" || r.Approval.ID != g.Approval.ID ||
		r.Run == nil || r.Run.ExitCode != 0 || r.Run.StdoutBytes != int64(len(awsJSON)) || !r.Run.StdoutReturned {
		t.Fatalf("run event %+v %+v", r, r.Run)
	}
}

func TestActionUsingASecretNamesItAndMasksIt(t *testing.T) {
	h := newHarness(t, fake.Approve)
	withActions(t, h)
	out, err := h.run(t, h.call(), "gh", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(out.Stdout) != "token [hidden:common:github-pat]\n" || string(out.StderrTail) != "err [hidden:common:github-pat]\n" {
		t.Fatalf("out %q %q", out.Stdout, out.StderrTail)
	}
	evs := h.sink.Events()
	g, r := evs[0], evs[1]
	if !strings.Contains(g.Approval.PromptText, `run "List PRs" (uses GitHub PAT) in VM dev.`) {
		t.Fatalf("prompt %q", g.Approval.PromptText)
	}
	for _, e := range []audit.Event{g, r} {
		if len(e.Uses) != 1 || e.Uses[0] != (audit.Resource{Kind: "secret", ID: "common:github-pat"}) {
			t.Fatalf("%s uses %+v", e.Type, e.Uses)
		}
	}
	if !r.Run.Masked || r.Run.StderrSHA256 != "" {
		t.Fatalf("run %+v", r.Run)
	}
}

func TestDeniedActionNeverRuns(t *testing.T) {
	h := newHarness(t, fake.Deny)
	runs := withActions(t, h)
	_, err := h.run(t, h.call(), "aws", map[string]string{"profile": "dev-admin"})
	if code(err) != protocol.CodeDenied || ranTimes(runs) != 0 {
		t.Fatalf("err %v, ran %d", err, ranTimes(runs))
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "approval.denied:denied", "action.run:denied")
	if evs[1].Params["profile"] != "dev-admin" {
		t.Fatalf("denied run %+v", evs[1])
	}
}

func TestUnknownActionsAndParamsAreRefusedAndAudited(t *testing.T) {
	h := newHarness(t, fake.Approve)
	runs := withActions(t, h)
	c := h.call()
	if _, err := h.run(t, c, "nope", nil); code(err) != protocol.CodeNotFound {
		t.Fatalf("unknown: %v", err)
	}
	if _, err := h.run(t, c, "uses-hidden", nil); code(err) != protocol.CodeNotFound {
		t.Fatalf("unexposed secret: %v", err)
	}
	if _, err := h.run(t, c, "aws", map[string]string{"profile": "dev-admin", "region": "x"}); code(err) != protocol.CodeParamRejected {
		t.Fatalf("unknown param: %v", err)
	}
	if _, err := h.run(t, c, "aws", map[string]string{"profile": "--debug"}); code(err) != protocol.CodeParamRejected {
		t.Fatalf("injection: %v", err)
	}
	if _, err := h.run(t, c, "../aws", nil); code(err) != protocol.CodeInvalidParams {
		t.Fatalf("bad name: %v", err)
	}
	if len(h.auth.Requests()) != 0 || ranTimes(runs) != 0 {
		t.Fatal("a refused request prompted or ran")
	}
	evs := h.sink.Events()
	wantTypes(t, evs, "action.run:not_found", "action.run:error", "action.run:rejected")
	if evs[0].Reason != "unknown" || evs[1].Reason != "uses_unexposed_secret" || evs[1].Uses[0].ID != "common:prod-db" ||
		evs[2].Reason != "param_rejected" || !strings.Contains(evs[2].Error.Message, `"region"`) || evs[2].Params != nil {
		t.Fatalf("events %+v", evs)
	}
	// Rejections are coalesced: the second param_rejected only counts.
	if err := h.svc.FlushRejections(context.Background()); err != nil {
		t.Fatal(err)
	}
	evs = h.sink.Events()
	if last := evs[len(evs)-1]; last.Reason != "param_rejected" || last.Coalesced == nil || last.Coalesced.Count != 1 {
		t.Fatalf("coalesced %+v", last)
	}
}

func TestNonZeroExitWithholdsStdout(t *testing.T) {
	h := newHarness(t, fake.Approve)
	withActions(t, h)
	out, err := h.run(t, h.call(), "fails", nil)
	if err != nil || out.ExitCode != 3 || out.Stdout != nil {
		t.Fatalf("%v %+v", err, out)
	}
	r := h.sink.Events()[1]
	if r.Outcome != audit.OutcomeError || r.Reason != "exit_status" || r.Run.ExitCode != 3 || r.Run.StdoutReturned {
		t.Fatalf("run event %+v %+v", r, r.Run)
	}
}

func TestUnrecordedRunReturnsNothing(t *testing.T) {
	h := newHarness(t, fake.Approve)
	withActions(t, h)
	h.sink.set(audit.TypeActionRun)
	out, err := h.run(t, h.call(), "aws", map[string]string{"profile": "dev-admin"})
	if code(err) != protocol.CodeAuditFailed || out != nil {
		t.Fatalf("%v %+v", err, out)
	}
}

func TestTooManyRunningIsBusy(t *testing.T) {
	h := newHarness(t, fake.Approve)
	runs := withActions(t, h)
	h.svc.running["dev"] = maxRunning
	if _, err := h.run(t, h.call(), "fails", nil); code(err) != protocol.CodeBusy || ranTimes(runs) != 0 {
		t.Fatalf("got %v", err)
	}
	if e := h.sink.Events()[0]; e.Type != audit.TypeRequestRejected || e.Reason != "too_many_running" {
		t.Fatalf("event %+v", e)
	}
	h.svc.running["dev"] = 0
	if _, err := h.run(t, h.call(), "fails", nil); err != nil {
		t.Fatal(err)
	}
	if h.svc.running["dev"] != 0 {
		t.Fatal("slot not released")
	}
}

// A grant for an action covers the params it was approved with, and only
// those.
func TestActionGrantCoversOnlyItsParams(t *testing.T) {
	r := newRig(t, every, fake.Approve, fake.Approve)
	runs := withActions(t, r.harness)
	r.inst.ActionPolicy = all(reuse(15*time.Minute, policy.ScopePeerSession))
	c := r.from("c1", "sid:10:100")
	dev := map[string]string{"profile": "dev-admin"}
	for i := 0; i < 2; i++ {
		if _, err := r.run(t, c, "aws", dev); err != nil {
			t.Fatal(err)
		}
	}
	if r.prompts() != 1 || ranTimes(runs) != 2 {
		t.Fatalf("prompts %d, runs %d", r.prompts(), ranTimes(runs))
	}
	reused := r.events(audit.TypeApprovalReused)
	if len(reused) != 1 || reused[0].Params["profile"] != "dev-admin" || reused[0].Resource.ID != "aws" {
		t.Fatalf("reused %+v", reused)
	}
	if !strings.Contains(r.auth.Requests()[0].Prompt, "Approving allows reuse for 15m by anything in VM dev.") {
		t.Fatalf("prompt %q", r.auth.Requests()[0].Prompt)
	}
	// Other values ask again.
	if _, err := r.run(t, c, "aws", map[string]string{"profile": "prod-admin"}); err != nil {
		t.Fatal(err)
	}
	if r.prompts() != 2 {
		t.Fatalf("prod-admin reused dev-admin's grant")
	}
	// A secret read is never covered by an action's grant.
	r.auth.Default = fake.Deny
	if err := r.read(t, c, "github-pat"); code(err) != protocol.CodeDenied {
		t.Fatalf("read: %v", err)
	}
	gs := r.grants(t, c)
	if len(gs) != 2 || gs[0].Resource.Kind != "action" || gs[0].Params["profile"] == "" {
		t.Fatalf("grants %+v", gs)
	}
	if n, _ := r.svc.DropGrants(context.Background(), c, []string{"aws"}); n != 2 {
		t.Fatalf("dropped %d", n)
	}
}

// Every param value must be on the prompt; values too long for it are
// refused before any prompt, never cut short.
func TestActionPromptTooLongIsRefused(t *testing.T) {
	h := newHarness(t, fake.Approve)
	runs := withActions(t, h)
	s := &action.Spec{ID: "echo", Command: "/bin/echo", Args: []string{"{text}"},
		Params: map[string]*action.Param{"text": {Pattern: "[a-z]+"}}}
	if err := s.Check(); err != nil {
		t.Fatal(err)
	}
	h.inst.Actions = command.New([]*action.Spec{s}, h.inst.Secrets)
	_, err := h.run(t, h.call(), "echo", map[string]string{"text": strings.Repeat("a", 250)})
	if code(err) != protocol.CodeParamRejected || len(h.auth.Requests()) != 0 || ranTimes(runs) != 0 {
		t.Fatalf("got %v", err)
	}
	if e := h.sink.Events()[0]; e.Type != audit.TypeRequestRejected || e.Reason != "prompt_too_long" {
		t.Fatalf("event %+v", e)
	}
}
