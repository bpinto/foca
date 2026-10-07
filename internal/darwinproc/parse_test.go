package darwinproc

import (
	"encoding/binary"
	"testing"
)

func TestParsePathInfo(t *testing.T) {
	b := make([]byte, pathInfoMaxSize)
	copy(b, "/usr/bin/nc")
	if got, err := ParsePathInfo(b); err != nil || got != "/usr/bin/nc" {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range [][]byte{nil, {0}, []byte("nc\x00"), []byte("/usr/bin/nc")} {
		if _, err := ParsePathInfo(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestParseAuditToken(t *testing.T) {
	b := make([]byte, 32)
	for i := range 8 {
		binary.NativeEndian.PutUint32(b[i*4:], uint32(100+i))
	}
	tok, err := ParseAuditToken(b)
	if err != nil || tok.PID() != 105 || tok.PIDVersion() != 107 {
		t.Fatalf("got %v pid=%d version=%d", err, tok.PID(), tok.PIDVersion())
	}
	if _, err := ParseAuditToken(b[:31]); err == nil {
		t.Fatal("short token accepted")
	}
}

// The buffer is laid out as XNU's struct proc_uniqidentifierinfo: a 16-byte
// uuid, the 64-bit unique id and parent unique id, then the 32-bit pid
// version at byte 32. The offsets are written out here, not taken from the
// code under test.
func TestParseIDVersion(t *testing.T) {
	b := make([]byte, 56)
	binary.NativeEndian.PutUint64(b[16:], 0x1111111111111111)
	binary.NativeEndian.PutUint64(b[24:], 0x2222222222222222)
	binary.NativeEndian.PutUint32(b[32:], 42)
	binary.NativeEndian.PutUint32(b[36:], 0x33333333)
	if v, err := ParseIDVersion(b); err != nil || v != 42 {
		t.Fatalf("got %d %v", v, err)
	}
	if _, err := ParseIDVersion(b[:40]); err == nil {
		t.Fatal("short buffer accepted")
	}
}
