//go:build foca_testing

package sysbus

import "os"

// In test builds only, FOCA_SYSTEM_BUS points foca at a private bus.
func init() {
	testBus = func() string { return os.Getenv("FOCA_SYSTEM_BUS") }
}
