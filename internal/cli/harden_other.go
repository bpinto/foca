//go:build !linux

package cli

// harden does nothing here yet; on macOS foca doesn't hide its memory from
// other processes of the same user (design §12.4).
func harden() error { return nil }
