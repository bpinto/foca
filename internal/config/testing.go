//go:build foca_testing

package config

// Test builds may use the macOS plugins on any OS, so the Go fake helper can
// stand in for foca-darwin in tests on Linux. Production builds can't.
func init() { darwinPluginsAnywhere = true }
