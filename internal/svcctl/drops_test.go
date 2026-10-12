package svcctl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The service takes only requests it can trust: private files of this user
// in a private directory, named as the CLI names them, that decode strictly
// and name well-formed grants. Every request is removed once looked at, so
// none is taken twice (design §8.6).
func TestDropRequestsTakeOnlyPrivateWellFormedFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "drop")
	if got, errs := TakeDropRequests(dir); got != nil || errs != nil {
		t.Fatalf("no directory: %v %v", got, errs)
	}
	const id = "01J9Z8K3J0000000000000000Z"
	good := []DropTarget{{ApprovalID: id}, {ApprovalID: id, Kind: "secret", Name: "common:github-pat"}}
	if err := WriteDropRequest(dir, good); err != nil {
		t.Fatal(err)
	}
	put := func(name, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		os.Chmod(filepath.Join(dir, name), mode)
	}
	ok := `{"v":1,"grants":[{"approval_id":"` + id + `"}]}`
	put("01J9Z8K3J0000000000000001Z.json", ok, 0o644) // others can read it
	put("01J9Z8K3J0000000000000002Z.json", `{"v":1,"grants":[{"approval_id":"`+id+`","extra":1}]}`, 0o600)
	put("01J9Z8K3J0000000000000003Z.json", `{"v":2,"grants":[{"approval_id":"`+id+`"}]}`, 0o600)
	put("01J9Z8K3J0000000000000004Z.json", `{"v":1,"grants":[{"approval_id":"nope"}]}`, 0o600)
	put("01J9Z8K3J0000000000000005Z.json", `{"v":1,"grants":[{"approval_id":"`+id+`","kind":"secret","name":"../x"}]}`, 0o600)
	put("01J9Z8K3J0000000000000006Z.json", ok+ok, 0o600)
	put("01J9Z8K3J0000000000000007Z.json", `{"v":1,"grants":[]}`, 0o600)
	put("not-a-request.json", ok, 0o600)
	put(".x.json.tmp-1", ok, 0o600)
	if err := os.Symlink(filepath.Join(dir, "not-a-request.json"), filepath.Join(dir, "01J9Z8K3J0000000000000008Z.json")); err != nil {
		t.Fatal(err)
	}

	got, errs := TakeDropRequests(dir)
	if len(got) != 2 || got[0] != good[0] || got[1] != good[1] {
		t.Fatalf("taken %+v", got)
	}
	if len(errs) != 8 {
		t.Fatalf("%d errors, want 8: %v", len(errs), errs)
	}
	left, _ := os.ReadDir(dir)
	var names []string
	for _, e := range left {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != ".x.json.tmp-1,not-a-request.json" {
		t.Fatalf("left in the directory: %v", names)
	}
	if got, errs := TakeDropRequests(dir); len(got) != 0 || len(errs) != 0 {
		t.Fatalf("taken twice: %v %v", got, errs)
	}

	// A directory others can write to isn't trusted at all.
	os.Chmod(dir, 0o777)
	put("01J9Z8K3J0000000000000009Z.json", ok, 0o600)
	if got, errs := TakeDropRequests(dir); len(got) != 0 || len(errs) != 1 {
		t.Fatalf("shared directory: %v %v", got, errs)
	}
	// The CLI refuses what the service would.
	if err := WriteDropRequest(t.TempDir(), []DropTarget{{ApprovalID: "nope"}}); err == nil {
		t.Fatal("wrote a malformed request")
	}
}
