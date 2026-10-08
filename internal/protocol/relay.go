package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// The guest relay proves itself on each upstream connection (design §14):
// it asks relay.challenge for a fresh nonce and the connection's id, then
// sends relay.hello with its Ed25519 signature over RelayMessage. Until that
// passes, an instance with a guest relay answers nothing else.
const (
	MethodRelayChallenge = "relay.challenge"
	MethodRelayHello     = "relay.hello"
)

// NonceSize is the length of a relay.challenge nonce.
const NonceSize = 32

type RelayChallengeParams struct {
	Common
}

type RelayChallengeResult struct {
	Instance   string `json:"instance"`
	Connection string `json:"connection"`
	Nonce      string `json:"nonce"` // base64
}

type RelayHelloParams struct {
	Common
	Signature string `json:"signature"` // base64
}

type RelayHelloResult struct {
	Instance string `json:"instance"`
}

// RelayMessage is what the relay signs: a fixed label, the instance and the
// connection the host named, and its nonce. NUL can't occur in the names, so
// no two inputs give the same bytes.
func RelayMessage(instance, connection string, nonce []byte) []byte {
	m := []byte("foca relay.hello v1\x00" + instance + "\x00" + connection + "\x00")
	return append(m, nonce...)
}

const relayKeyPrefix = "ed25519:"

// FormatRelayKey writes a relay's public key as host config takes it.
func FormatRelayKey(pub ed25519.PublicKey) string {
	return relayKeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// ParseRelayKey reads "ed25519:<base64>", the form FormatRelayKey writes.
func ParseRelayKey(s string) (ed25519.PublicKey, error) {
	b64, ok := strings.CutPrefix(s, relayKeyPrefix)
	if !ok {
		return nil, errors.New(`public_key must be "ed25519:<base64>", as foca relay keygen prints it`)
	}
	b, err := base64.StdEncoding.Strict().DecodeString(b64)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("public_key is not a base64 Ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(b), nil
}
