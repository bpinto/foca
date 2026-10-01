// Package ids generates sortable unique identifiers (ULID layout: 48-bit
// millisecond timestamp followed by 80 random bits, Crockford base32).
package ids

import (
	"crypto/rand"
	"time"
)

const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a 26-character identifier that sorts by creation time.
func New() string {
	return newAt(time.Now())
}

func newAt(t time.Time) string {
	var b [16]byte
	ms := uint64(t.UnixMilli())
	for i := 5; i >= 0; i-- {
		b[i] = byte(ms)
		ms >>= 8
	}
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ids: crypto/rand failed: " + err.Error())
	}
	return encode(b)
}

// encode writes 128 bits as 26 base32 characters, most significant first.
// The first character carries only the top 3 bits.
func encode(b [16]byte) string {
	var out [26]byte
	var acc uint64
	var bits uint
	pos := 25
	for i := 15; i >= 0; i-- {
		acc |= uint64(b[i]) << bits
		bits += 8
		for bits >= 5 && pos >= 0 {
			out[pos] = alphabet[acc&31]
			acc >>= 5
			bits -= 5
			pos--
		}
	}
	if pos == 0 {
		out[0] = alphabet[acc&31]
	}
	return string(out[:])
}
