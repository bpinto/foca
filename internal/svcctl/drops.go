package svcctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/bpinto/foca/internal/fsutil"
	"github.com/bpinto/foca/internal/ids"
	"github.com/bpinto/foca/internal/secretname"
)

// DropVersion is the drop request format version.
const DropVersion = 1

// maxDropFile bounds a request: far more than MaxDropTargets need.
const maxDropFile = 16 << 10

// MaxDropTargets is the most grants one request names.
const MaxDropTargets = 32

// DropRequest asks a service to drop single grants of one instance (design
// §8.6). The host CLI writes it into the instance's private drop directory and
// sends SIGUSR2; a signal carries no data. It can only remove grants.
type DropRequest struct {
	V      int          `json:"v"`
	Grants []DropTarget `json:"grants"`
}

// DropTarget names a grant by its approval, and, when one approval made
// several grants, by its resource as well.
type DropTarget struct {
	ApprovalID string `json:"approval_id"`
	Kind       string `json:"kind,omitempty"`
	Name       string `json:"name,omitempty"`
}

var approvalIDPattern = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)

// requestName is how WriteDropRequest names a request, so a temp file of
// WriteFileAtomic, or anything else in the directory, is never taken for one.
var requestName = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}\.json$`)

// Check reports what is wrong with t, if anything.
func (t DropTarget) Check() error {
	if !approvalIDPattern.MatchString(t.ApprovalID) {
		return fmt.Errorf("%q is not an approval id", t.ApprovalID)
	}
	switch t.Kind {
	case "":
		if t.Name != "" {
			return errors.New("a name needs a kind")
		}
	case "secret":
		if _, _, ok := secretname.Split(t.Name); !ok {
			return fmt.Errorf("%q is not a secret name", t.Name)
		}
	case "action":
		if !secretname.ValidID(t.Name) {
			return fmt.Errorf("%q is not an action name", t.Name)
		}
	default:
		return fmt.Errorf("unknown kind %q", t.Kind)
	}
	return nil
}

func (r DropRequest) check() error {
	if r.V != DropVersion {
		return fmt.Errorf("version %d; this foca reads version %d", r.V, DropVersion)
	}
	if len(r.Grants) == 0 || len(r.Grants) > MaxDropTargets {
		return fmt.Errorf("%d grants named, want 1 to %d", len(r.Grants), MaxDropTargets)
	}
	for _, t := range r.Grants {
		if err := t.Check(); err != nil {
			return err
		}
	}
	return nil
}

// WriteDropRequest leaves a request for the service in dir, the instance's
// private drop directory, creating it if need be.
func WriteDropRequest(dir string, targets []DropTarget) error {
	r := DropRequest{V: DropVersion, Grants: targets}
	if err := r.check(); err != nil {
		return err
	}
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(filepath.Join(dir, ids.New()+".json"), b, 0o600); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		return err
	}
	return nil
}

// TakeDropRequests reads and removes every request in dir. Only a private
// file of the current user, in a private directory, that decodes strictly
// and names only well-formed grants is taken; the rest are removed and
// reported. A missing directory holds no requests.
func TakeDropRequests(dir string) ([]DropTarget, []error) {
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err := fsutil.EnsurePrivateDir(dir); err != nil {
		return nil, []error{err}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, []error{err}
	}
	var out []DropTarget
	var errs []error
	for _, e := range entries {
		if !requestName.MatchString(e.Name()) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		r, err := readDropRequest(path)
		if rerr := os.Remove(path); rerr != nil && err == nil {
			// Not removed means it could be taken again; harmless, as a drop
			// is idempotent, but worth saying.
			errs = append(errs, rerr)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w; ignored", path, err))
			continue
		}
		out = append(out, r.Grants...)
	}
	return out, errs
}

func readDropRequest(path string) (DropRequest, error) {
	var r DropRequest
	f, err := openPrivate(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxDropFile+1))
	if err != nil {
		return r, err
	}
	if len(b) > maxDropFile {
		return r, fmt.Errorf("larger than %d bytes", maxDropFile)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return DropRequest{}, err
	}
	if d.More() {
		return DropRequest{}, errors.New("more than one request in the file")
	}
	if err := r.check(); err != nil {
		return DropRequest{}, err
	}
	return r, nil
}
