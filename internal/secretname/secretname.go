// Package secretname is a secret's full name, "<vault>:<id>". Realms ask for
// secrets by it, and prompts, grants, policy and audit name them by it, so
// two vaults can hold the same id without either ever standing in for the
// other. Inside a vault, ids are bare.
package secretname

import (
	"regexp"
	"strings"
)

var (
	vaultPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	idPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
)

// ValidVault reports whether s is a valid vault (or instance) name.
func ValidVault(s string) bool { return vaultPattern.MatchString(s) }

// ValidID reports whether s is a valid secret id within a vault.
func ValidID(s string) bool { return idPattern.MatchString(s) }

// Join makes a full name.
func Join(vault, id string) string { return vault + ":" + id }

// Split splits a full name; ok is false unless both parts are valid.
func Split(name string) (vault, id string, ok bool) {
	vault, id, found := strings.Cut(name, ":")
	if !found || !ValidVault(vault) || !ValidID(id) {
		return "", "", false
	}
	return vault, id, true
}
