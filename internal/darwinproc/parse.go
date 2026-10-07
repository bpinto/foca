// Package darwinproc reads process information from the macOS kernel
// without cgo: the peer's audit token, the pid version that pins a process,
// its executable path and its kinfo_proc. The syscalls are behind the darwin
// build tag; parsing is plain Go so it is tested on Linux too.
package darwinproc

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// pathInfoMaxSize is PROC_PIDPATHINFO_MAXSIZE, the buffer proc_pidpath uses.
const pathInfoMaxSize = 4 * 1024

// ParsePathInfo returns the path a PROC_PIDPATHINFO buffer holds: an
// absolute path, NUL-terminated.
func ParsePathInfo(b []byte) (string, error) {
	end := bytes.IndexByte(b, 0)
	if end < 0 {
		return "", errors.New("path info: not terminated")
	}
	if end == 0 || b[0] != '/' {
		return "", errors.New("path info: no absolute path")
	}
	return string(b[:end]), nil
}

// AuditToken is the peer's audit_token_t: eight 32-bit words.
type AuditToken [8]uint32

// PID and PIDVersion are words 5 and 7. The version changes whenever the
// pid is reused and when the process execs, so (pid, version) names exactly
// one process image.
func (t AuditToken) PID() int          { return int(t[5]) }
func (t AuditToken) PIDVersion() int32 { return int32(t[7]) }

// ParseAuditToken decodes the 32 bytes getsockopt(LOCAL_PEERTOKEN) fills.
func ParseAuditToken(b []byte) (AuditToken, error) {
	var t AuditToken
	if len(b) != 32 {
		return t, errors.New("audit token: want 32 bytes")
	}
	for i := range t {
		t[i] = binary.NativeEndian.Uint32(b[i*4:])
	}
	return t, nil
}

// uniqIdentifierInfo is struct proc_uniqidentifierinfo from
// <sys/proc_info.h>: the pid version is at byte 32.
const (
	uniqIdentifierInfoSize = 56
	idVersionOffset        = 32
)

// ParseIDVersion reads p_idversion from a proc_uniqidentifierinfo buffer.
func ParseIDVersion(b []byte) (int32, error) {
	if len(b) < uniqIdentifierInfoSize {
		return 0, errors.New("proc_uniqidentifierinfo: short buffer")
	}
	return int32(binary.NativeEndian.Uint32(b[idVersionOffset:])), nil
}
