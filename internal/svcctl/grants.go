package svcctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bpinto/foca/internal/audit"
	"github.com/bpinto/foca/internal/fsutil"
)

// GrantsVersion is the snapshot format version.
const GrantsVersion = 1

// maxGrantsFile bounds what ReadGrants takes in: far more than the grants
// one instance can hold.
const maxGrantsFile = 4 << 20

// GrantsSnapshot is what a service records about one instance's live grants,
// so the host can see them all (design §8.6). It holds names, never values.
type GrantsSnapshot struct {
	V         int       `json:"v"`
	Instance  string    `json:"instance"`
	WrittenAt time.Time `json:"written_at"`
	// Reuse is false while no grant can be made or reused (design D13).
	Reuse  bool    `json:"reuse"`
	Grants []Grant `json:"grants"`
}

type Grant struct {
	Kind       string            `json:"kind"`
	Name       string            `json:"name"`
	Params     map[string]string `json:"params,omitempty"`
	Scope      string            `json:"scope"`
	ScopeKey   *audit.ScopeKey   `json:"scope_key"`
	ApprovalID string            `json:"approval_id"`
	GrantedAt  time.Time         `json:"granted_at"`
	ExpiresAt  time.Time         `json:"expires_at"`
	// Quiet grants are reused without notifying the host (notify = false).
	Quiet bool `json:"quiet,omitempty"`
}

// WriteGrants replaces the snapshot at path. Like the pid file it only has to
// outlive the process, so one in place but not yet durable will do.
func WriteGrants(path string, s GrantsSnapshot) error {
	s.V = GrantsVersion
	if s.Grants == nil {
		s.Grants = []Grant{}
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if err := fsutil.WriteFileAtomic(path, append(b, '\n'), 0o600); err != nil && !errors.Is(err, fsutil.ErrNotDurable) {
		return err
	}
	return nil
}

// RemoveGrants removes the snapshot at path, if there is one.
func RemoveGrants(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ReadGrants returns the snapshot at grantsPath, but only while the verified
// service behind pidPath runs: a snapshot a crashed service left behind
// names grants that no longer exist. Grants expired by now, which the
// service hasn't swept yet, are left out.
func ReadGrants(pidPath, grantsPath string, now time.Time) (GrantsSnapshot, error) {
	var s GrantsSnapshot
	if _, err := PID(pidPath); err != nil {
		return s, err
	}
	f, err := openPrivate(grantsPath)
	if errors.Is(err, os.ErrNotExist) {
		return s, fmt.Errorf("the service keeps no grants snapshot at %s (an older foca, or it couldn't write one; see its log)", grantsPath)
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxGrantsFile+1))
	if err != nil {
		return s, err
	}
	if len(b) > maxGrantsFile {
		return s, fmt.Errorf("%s is larger than %d bytes; not reading it", grantsPath, maxGrantsFile)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return GrantsSnapshot{}, fmt.Errorf("%s is malformed: %w", grantsPath, err)
	}
	if s.V != GrantsVersion {
		return GrantsSnapshot{}, fmt.Errorf("%s has version %d; this foca reads version %d", grantsPath, s.V, GrantsVersion)
	}
	live := s.Grants[:0]
	for _, g := range s.Grants {
		if now.Before(g.ExpiresAt) {
			live = append(live, g)
		}
	}
	s.Grants = live
	return s, nil
}
