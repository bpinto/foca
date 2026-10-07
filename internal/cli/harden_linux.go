//go:build linux

package cli

import "golang.org/x/sys/unix"

// harden makes the process not dumpable. Other processes of the same user can
// then no longer attach to it, read its memory or environment through /proc,
// or see its executable, and it leaves no core dump. Root still can (design
// §12.4).
func harden() error { return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
